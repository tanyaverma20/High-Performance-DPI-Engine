#include "parser_pool.h"
#include "profiler.h"
#include <iostream>

namespace DPI {

// ============================================================================
// ParserWorker Implementation
// ============================================================================

ParserWorker::ParserWorker(int parser_id,
                           ThreadSafeQueue<RawPacketJob>& input_queue,
                           LBSelector lb_selector)
    : parser_id_(parser_id),
      input_queue_(input_queue),
      lb_selector_(std::move(lb_selector)) {
}

ParserWorker::~ParserWorker() {
    stop();
}

void ParserWorker::start() {
    if (running_) return;
    running_ = true;
    thread_ = std::thread(&ParserWorker::run, this);
    std::cout << "[Parser" << parser_id_ << "] Started\n";
}

void ParserWorker::stop() {
    if (!running_) return;
    running_ = false;
    if (thread_.joinable()) {
        thread_.join();
    }
    std::cout << "[Parser" << parser_id_ << "] Stopped\n";
}

ParserWorker::ParserStats ParserWorker::getStats() const {
    return stats_;
}

void ParserWorker::run() {
    while (true) {
        auto raw_opt = input_queue_.popWithTimeout(
            std::chrono::milliseconds(50),
            &Profiler::instance().lb_pop_lock_ns,
            &Profiler::instance().lb_idle_ns
        );

        if (!raw_opt) {
            if (!running_ && input_queue_.empty()) {
                // Input queue drained and shutdown signaled
                break;
            }
            continue;
        }

        PacketAnalyzer::RawPacket raw;
        raw.header.ts_sec  = raw_opt->ts_sec;
        raw.header.ts_usec = raw_opt->ts_usec;
        raw.header.incl_len = raw_opt->data.size();
        raw.header.orig_len = raw_opt->data.size();
        raw.data = std::move(raw_opt->data);

        PacketAnalyzer::ParsedPacket parsed;
        bool parse_success = false;
        {
            ScopedNsTimer t(Profiler::instance().reader_parse_ns);
            parse_success = PacketAnalyzer::PacketParser::parse(raw, parsed);
        }

        if (parse_success) {
            PacketJob job;
            {
                ScopedNsTimer t(Profiler::instance().reader_job_create_ns);
                job = createPacketJob(raw, parsed, raw_opt->packet_id);
            }

            LoadBalancer& lb = lb_selector_(job.tuple);
            lb.getInputQueue().push(
                std::move(job),
                nullptr,
                &Profiler::instance().reader_push_wait_ns
            );

            stats_.total_parsed++;
            Profiler::instance().reader_packets++;
        } else {
            stats_.total_errors++;
        }
    }
}

PacketJob ParserWorker::createPacketJob(const PacketAnalyzer::RawPacket& raw,
                                         const PacketAnalyzer::ParsedPacket& parsed,
                                         uint32_t packet_id) {
    PacketJob job;
    job.packet_id = packet_id;
    job.ts_sec    = raw.header.ts_sec;
    job.ts_usec   = raw.header.ts_usec;

    job.tuple.src_ip   = parsed.src_ip_raw;
    job.tuple.dst_ip   = parsed.dst_ip_raw;
    job.tuple.src_port = parsed.src_port;
    job.tuple.dst_port = parsed.dest_port;
    job.tuple.protocol = parsed.protocol;

    if (parsed.has_ipv6) {
        job.flow_key = FlowKey::fromIPv6(parsed.src_ipv6, parsed.dst_ipv6, parsed.src_port, parsed.dest_port, parsed.protocol);
        job.has_flow_key = true;
    } else if (parsed.has_ip) {
        job.flow_key = FlowKey::fromFiveTuple(job.tuple);
        job.has_flow_key = true;
    }

    job.tcp_flags = parsed.tcp_flags;
    job.tcp_seq_number = parsed.seq_number;

    job.data = raw.data;

    job.eth_offset = 0;
    job.ip_offset  = 14;

    if (job.data.size() > 14) {
        uint8_t ip_ihl       = job.data[14] & 0x0F;
        size_t ip_header_len = ip_ihl * 4;
        job.transport_offset = 14 + ip_header_len;

        if (parsed.has_tcp && job.data.size() > job.transport_offset) {
            uint8_t tcp_data_offset = (job.data[job.transport_offset + 12] >> 4) & 0x0F;
            size_t tcp_header_len   = tcp_data_offset * 4;
            job.payload_offset      = job.transport_offset + tcp_header_len;
        } else if (parsed.has_udp) {
            job.payload_offset = job.transport_offset + 8;
        }

        if (job.payload_offset < job.data.size()) {
            job.payload_length = job.data.size() - job.payload_offset;
        }
    }

    return job;
}

// ============================================================================
// ParserManager Implementation
// ============================================================================

ParserManager::ParserManager(int num_workers,
                             ThreadSafeQueue<RawPacketJob>& input_queue,
                             LBSelector lb_selector) {
    if (num_workers < 1) num_workers = 1;
    for (int i = 0; i < num_workers; i++) {
        workers_.push_back(std::make_unique<ParserWorker>(i, input_queue, lb_selector));
    }
}

ParserManager::~ParserManager() {
    stopAll();
}

void ParserManager::startAll() {
    for (auto& w : workers_) {
        w->start();
    }
    std::cout << "[ParserManager] Created " << workers_.size() << " Parser threads\n";
}

void ParserManager::stopAll() {
    for (auto& w : workers_) {
        w->stop();
    }
}

ParserManager::AggregatedStats ParserManager::getAggregatedStats() const {
    AggregatedStats total;
    for (const auto& w : workers_) {
        auto st = w->getStats();
        total.total_parsed += st.total_parsed;
        total.total_errors += st.total_errors;
    }
    return total;
}

} // namespace DPI
