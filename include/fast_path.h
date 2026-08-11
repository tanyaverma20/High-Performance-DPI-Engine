#ifndef FAST_PATH_H
#define FAST_PATH_H

#include "types.h"
#include "thread_safe_queue.h"
#include "connection_tracker.h"
#include "rule_manager.h"
#include "sni_extractor.h"
#include <thread>
#include <atomic>
#include <memory>
#include <functional>

namespace DPI {

using OutputCallback = std::function<void(const PacketJob&, PacketAction)>;

class FastPathProcessor {
public:
    FastPathProcessor(int fp_id, RuleManager* rule_manager, OutputCallback output_cb);
    ~FastPathProcessor();
    
    void start();
    void stop();
    
    ThreadSafeQueue<PacketJob>& getInputQueue() { return input_queue_; }
    ConnectionTracker& getConnectionTracker() { return connection_tracker_; }
    
    struct FPStats {
        uint64_t total_processed = 0;
        uint64_t total_forwarded = 0;
        uint64_t total_dropped = 0;
        uint64_t total_connections = 0;
    };
    
    FPStats getStats() const;
    std::string generateClassificationReport() const;

private:
    int fp_id_;
    RuleManager* rule_manager_;
    OutputCallback output_cb_;
    ThreadSafeQueue<PacketJob> input_queue_;
    ConnectionTracker connection_tracker_;
    
    std::atomic<bool> running_{false};
    std::thread thread_;
    FPStats stats_;
    
    void run();
    void processPacket(const PacketJob& job);
    void updateTCPState(Connection* conn, uint8_t flags, bool is_client);
    void inspectPayload(Connection* conn, const PacketJob& job, bool is_client);
    void handleAction(const PacketJob& job, PacketAction action);
};

class FPManager {
public:
    FPManager(int num_fps, RuleManager* rule_manager, OutputCallback output_cb);
    ~FPManager();
    
    void startAll();
    void stopAll();
    
    FastPathProcessor& getFP(int id);
    std::vector<ThreadSafeQueue<PacketJob>*> getQueuePtrs();
    
    struct AggregatedStats {
        uint64_t total_processed;
        uint64_t total_forwarded;
        uint64_t total_dropped;
        uint64_t total_connections;
    };
    
    AggregatedStats getAggregatedStats() const;
    std::string generateClassificationReport() const;

private:
    std::vector<std::unique_ptr<FastPathProcessor>> fps_;
    RuleManager* rule_manager_;
    OutputCallback output_cb_;
};

} // namespace DPI

#endif // FAST_PATH_H
