#include "fast_path.h"
#include "sni_extractor.h"
#include "packet_parser.h"
#include "profiler.h"
#include <iostream>
#include <chrono>

namespace DPI {

// ============================================================================
// FastPathProcessor Implementation
// ============================================================================

FastPathProcessor::FastPathProcessor(int fp_id, RuleManager* rule_manager, OutputCallback output_cb)
    : fp_id_(fp_id),
      rule_manager_(rule_manager),
      output_cb_(std::move(output_cb)),
      input_queue_(10000),
      connection_tracker_(fp_id, 100000) {
}

FastPathProcessor::~FastPathProcessor() {
    stop();
}

void FastPathProcessor::start() {
    if (running_) return;
    running_ = true;
    thread_ = std::thread(&FastPathProcessor::run, this);
    std::cout << "[FP" << fp_id_ << "] Started\n";
}

void FastPathProcessor::stop() {
    if (!running_) return;
    running_ = false;
    input_queue_.shutdown();
    if (thread_.joinable()) {
        thread_.join();
    }
    std::cout << "[FP" << fp_id_ << "] Stopped\n";
}

void FastPathProcessor::run() {
    auto last_cleanup = std::chrono::steady_clock::now();
    
    while (true) {
        auto job_opt = input_queue_.popWithTimeout(
            std::chrono::milliseconds(50),
            &Profiler::instance().fp_pop_lock_ns,
            &Profiler::instance().fp_idle_ns
        );
        
        if (job_opt) {
            processPacket(*job_opt);
        } else if (!running_ && input_queue_.empty()) {
            // Shutting down and queue is fully drained
            break;
        }
        
        auto now = std::chrono::steady_clock::now();
        if (now - last_cleanup > std::chrono::seconds(10)) {
            connection_tracker_.cleanupStale();
            last_cleanup = now;
        }
    }
}

void FastPathProcessor::processPacket(const PacketJob& job) {
    stats_.total_processed++;
    Profiler::instance().fp_packets++;
    
    Connection* conn = nullptr;
    bool is_client = false;
    
    {
        ScopedNsTimer t(Profiler::instance().fp_conn_lookup_ns);
        const FlowKey* key_ptr = nullptr;
        if (job.has_flow_key) {
            key_ptr = &job.flow_key;
        } else {
            FlowKey fk = FlowKey::fromFiveTuple(job.tuple);
            key_ptr = &fk;
        }
        
        conn = connection_tracker_.getOrCreateConnection(*key_ptr);
        
        is_client = (conn->original_is_canonical) ?
                         (key_ptr->canonical() == *key_ptr) :
                         (key_ptr->canonical() != *key_ptr);
        
        connection_tracker_.updateConnection(conn, job.data.size(), is_client);
        
        if (job.tuple.protocol == 6) { // TCP
            updateTCPState(conn, job.tcp_flags, is_client);
        }
    }
    
    if (conn->state == ConnectionState::BLOCKED) {
        ScopedNsTimer t(Profiler::instance().fp_handle_action_ns);
        handleAction(job, PacketAction::DROP);
        return;
    }
    
    {
        ScopedNsTimer t(Profiler::instance().fp_rule_check_ns);
        if (rule_manager_->isIPBlocked(std::get<IPv4Addr>(conn->flow_key.src_addr)) ||
            rule_manager_->isIPBlocked(std::get<IPv4Addr>(conn->flow_key.dst_addr))) {
            connection_tracker_.blockConnection(conn);
            handleAction(job, PacketAction::DROP);
            return;
        }
    }
    
    if (conn->state == ConnectionState::NEW || conn->state == ConnectionState::ESTABLISHED) {
        ScopedNsTimer t(Profiler::instance().fp_inspect_ns);
        inspectPayload(conn, job, is_client);
    }
    
    if (conn->state == ConnectionState::CLASSIFIED) {
        ScopedNsTimer t(Profiler::instance().fp_rule_check_ns);
        if (rule_manager_->isAppBlocked(conn->app_type)) {
            connection_tracker_.blockConnection(conn);
            handleAction(job, PacketAction::DROP);
            return;
        }
        
        const std::string& domain = conn->bestDomain();
        if (!domain.empty() && rule_manager_->isDomainBlocked(domain)) {
            connection_tracker_.blockConnection(conn);
            handleAction(job, PacketAction::DROP);
            return;
        }
    }
    
    {
        ScopedNsTimer t(Profiler::instance().fp_handle_action_ns);
        handleAction(job, PacketAction::FORWARD);
    }
}

void FastPathProcessor::updateTCPState(Connection* conn, uint8_t flags, bool is_client) {
    if (flags & PacketAnalyzer::TCPFlags::SYN) {
        if (flags & PacketAnalyzer::TCPFlags::ACK) {
            conn->syn_ack_seen = true;
            if (conn->syn_seen) conn->state = ConnectionState::ESTABLISHED;
        } else {
            conn->syn_seen = true;
        }
    } else if (flags & PacketAnalyzer::TCPFlags::FIN) {
        conn->fin_seen = true;
    } else if (flags & PacketAnalyzer::TCPFlags::RST) {
        connection_tracker_.closeConnection(conn->flow_key);
    }
}

void FastPathProcessor::inspectPayload(Connection* conn, const PacketJob& job, bool is_client) {
    const uint8_t* payload = job.getPayload();
    if (!payload) return;
    
    bool classification_updated = false;
    std::string sni, http_host, dns_query;

    if (conn->flow_key.protocol == 17) { // UDP
        if (conn->flow_key.src_port == 53 || conn->flow_key.dst_port == 53) {
            auto result = DNSExtractor::extractQuery(payload, job.payload_length);
            if (result) {
                dns_query = result->query_domain;
                connection_tracker_.classifyConnection(conn, AppType::DNS, "", "", dns_query);
                classification_updated = true;
            }
        } else if (QUICSNIExtractor::isQUICInitial(payload, job.payload_length)) {
            auto result = QUICSNIExtractor::extract(payload, job.payload_length);
            if (result) {
                sni = *result;
                connection_tracker_.classifyConnection(conn, sniToAppType(sni), sni);
                classification_updated = true;
            } else {
                connection_tracker_.classifyConnection(conn, AppType::QUIC, "");
                classification_updated = true;
            }
        }
    } else if (conn->flow_key.protocol == 6 && is_client) { // TCP, client to server
        if (conn->flow_key.src_port == 80 || conn->flow_key.dst_port == 80 || HTTPHostExtractor::isHTTPRequest(payload, job.payload_length)) {
            auto host = HTTPHostExtractor::extract(payload, job.payload_length);
            if (host) {
                http_host = *host;
                connection_tracker_.classifyConnection(conn, sniToAppType(http_host), "", http_host, "");
                classification_updated = true;
            } else {
                connection_tracker_.classifyConnection(conn, AppType::HTTP, "");
                classification_updated = true;
            }
        } else {
            // TCP Reassembly for TLS (Client to Server)
            auto result = conn->tcp_reassembler_client.tryExtractSNI(job.tcp_seq_number, payload, job.payload_length);
            if (result) {
                sni = *result;
                connection_tracker_.classifyConnection(conn, sniToAppType(sni), sni);
                classification_updated = true;
                conn->tcp_reassembler_client.clear();
            }
        }
    } else if (conn->flow_key.protocol == 6 && !is_client) {
        // (Optional) Server to Client reassembly can be implemented here if needed for Server Hello
        // auto result = conn->tcp_reassembler_server.tryExtractSNI(job.tcp_seq_number, payload, job.payload_length);
    }

    if (!classification_updated && (conn->packets_in + conn->packets_out > 10)) {
        // If we still don't know what it is after 10 packets, just classify as unknown
        connection_tracker_.classifyConnection(conn, AppType::UNKNOWN, "");
    }
}

void FastPathProcessor::handleAction(const PacketJob& job, PacketAction action) {
    if (action == PacketAction::DROP) {
        stats_.total_dropped++;
    } else {
        stats_.total_forwarded++;
    }
    
    if (output_cb_) {
        output_cb_(job, action);
    }
}

FastPathProcessor::FPStats FastPathProcessor::getStats() const {
    FPStats current = stats_;
    current.total_connections = connection_tracker_.getActiveCount();
    return current;
}

std::string FastPathProcessor::generateClassificationReport() const {
    auto stats = connection_tracker_.getStats();
    std::ostringstream ss;
    ss << "FP" << fp_id_ << " Report:\n"
       << "  Active: " << stats.active_connections << "\n"
       << "  Total:  " << stats.total_connections_seen << "\n"
       << "  Classified: " << stats.classified_connections << "\n"
       << "  Blocked: " << stats.blocked_connections << "\n";
    return ss.str();
}

// ============================================================================
// FPManager Implementation
// ============================================================================

FPManager::FPManager(int num_fps, RuleManager* rule_manager, OutputCallback output_cb)
    : rule_manager_(rule_manager), output_cb_(std::move(output_cb)) {
    
    for (int i = 0; i < num_fps; i++) {
        fps_.push_back(std::make_unique<FastPathProcessor>(i, rule_manager_, output_cb_));
    }
    
    std::cout << "[FPManager] Created " << num_fps << " FP threads\n";
}

FPManager::~FPManager() {
    stopAll();
}

void FPManager::startAll() {
    for (auto& fp : fps_) {
        fp->start();
    }
}

void FPManager::stopAll() {
    for (auto& fp : fps_) {
        fp->stop();
    }
}

FastPathProcessor& FPManager::getFP(int id) {
    return *fps_[id];
}

std::vector<ThreadSafeQueue<PacketJob>*> FPManager::getQueuePtrs() {
    std::vector<ThreadSafeQueue<PacketJob>*> ptrs;
    ptrs.reserve(fps_.size());
    for (auto& fp : fps_) {
        ptrs.push_back(&fp->getInputQueue());
    }
    return ptrs;
}

FPManager::AggregatedStats FPManager::getAggregatedStats() const {
    AggregatedStats stats = {0, 0, 0, 0};
    
    for (const auto& fp : fps_) {
        auto fp_stats = fp->getStats();
        stats.total_processed += fp_stats.total_processed;
        stats.total_forwarded += fp_stats.total_forwarded;
        stats.total_dropped += fp_stats.total_dropped;
        stats.total_connections += fp_stats.total_connections;
    }
    
    return stats;
}

std::string FPManager::generateClassificationReport() const {
    std::ostringstream ss;
    for (const auto& fp : fps_) {
        ss << fp->generateClassificationReport();
    }
    return ss.str();
}

} // namespace DPI
