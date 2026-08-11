#ifndef PARSER_POOL_H
#define PARSER_POOL_H

#include "types.h"
#include "thread_safe_queue.h"
#include "packet_parser.h"
#include "load_balancer.h"
#include <vector>
#include <thread>
#include <atomic>
#include <memory>
#include <functional>

namespace DPI {

// ============================================================================
// RawPacketJob - Represents an unparsed packet passed from Reader to Parser pool
// ============================================================================
struct RawPacketJob {
    uint32_t packet_id = 0;
    uint32_t ts_sec    = 0;
    uint32_t ts_usec   = 0;
    std::vector<uint8_t> data;
};

// Callback to resolve the downstream LoadBalancer for a given 5-tuple
using LBSelector = std::function<LoadBalancer&(const FiveTuple&)>;

// ============================================================================
// ParserWorker - Worker thread that parses raw packets in parallel
// ============================================================================
class ParserWorker {
public:
    ParserWorker(int parser_id,
                 ThreadSafeQueue<RawPacketJob>& input_queue,
                 LBSelector lb_selector);
    ~ParserWorker();

    void start();
    void stop();

    struct ParserStats {
        uint64_t total_parsed = 0;
        uint64_t total_errors = 0;
    };

    ParserStats getStats() const;

private:
    int parser_id_;
    ThreadSafeQueue<RawPacketJob>& input_queue_;
    LBSelector lb_selector_;

    std::atomic<bool> running_{false};
    std::thread thread_;
    ParserStats stats_;

    void run();
    PacketJob createPacketJob(const PacketAnalyzer::RawPacket& raw,
                               const PacketAnalyzer::ParsedPacket& parsed,
                               uint32_t packet_id);
};

// ============================================================================
// ParserManager - Manages a pool of ParserWorker threads
// ============================================================================
class ParserManager {
public:
    ParserManager(int num_workers,
                  ThreadSafeQueue<RawPacketJob>& input_queue,
                  LBSelector lb_selector);
    ~ParserManager();

    void startAll();
    void stopAll();

    struct AggregatedStats {
        uint64_t total_parsed = 0;
        uint64_t total_errors = 0;
    };

    AggregatedStats getAggregatedStats() const;
    int getNumWorkers() const { return static_cast<int>(workers_.size()); }

private:
    std::vector<std::unique_ptr<ParserWorker>> workers_;
};

} // namespace DPI

#endif // PARSER_POOL_H
