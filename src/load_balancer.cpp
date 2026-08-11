#include "load_balancer.h"
#include "profiler.h"
#include <iostream>
#include <chrono>

namespace DPI {

// ============================================================================
// LoadBalancer Implementation
// ============================================================================

LoadBalancer::LoadBalancer(int lb_id,
                           std::vector<ThreadSafeQueue<PacketJob>*> fp_queues,
                           int fp_start_id)
    : lb_id_(lb_id),
      fp_start_id_(fp_start_id),
      num_fps_(fp_queues.size()),
      input_queue_(10000),
      fp_queues_(std::move(fp_queues)),
      per_fp_counts_(num_fps_) {
}

LoadBalancer::~LoadBalancer() {
    stop();
}

void LoadBalancer::start() {
    if (running_) return;
    
    running_ = true;
    thread_ = std::thread(&LoadBalancer::run, this);
    
    std::cout << "[LB" << lb_id_ << "] Started (serving FP" 
              << fp_start_id_ << "-FP" << (fp_start_id_ + num_fps_ - 1) << ")\n";
}

void LoadBalancer::stop() {
    if (!running_) return;
    
    running_ = false;
    input_queue_.shutdown();
    
    if (thread_.joinable()) {
        thread_.join();
    }
    
    std::cout << "[LB" << lb_id_ << "] Stopped\n";
}

void LoadBalancer::run() {
    while (true) {
        // Get packet from input queue (with timeout to check running flag)
        auto job_opt = input_queue_.popWithTimeout(
            std::chrono::milliseconds(100),
            &Profiler::instance().lb_pop_lock_ns,
            &Profiler::instance().lb_idle_ns
        );
        
        if (!job_opt) {
            if (!running_ && input_queue_.empty()) break;
            continue;  // Timeout
        }
        
        packets_received_++;
        Profiler::instance().lb_packets++;
        
        int fp_index = 0;
        {
            ScopedNsTimer t(Profiler::instance().lb_select_fp_ns);
            fp_index = selectFP(job_opt->tuple);
        }
        
        fp_queues_[fp_index]->push(
            std::move(*job_opt),
            nullptr,
            &Profiler::instance().lb_push_wait_ns
        );
        
        packets_dispatched_++;
        per_fp_counts_[fp_index]++;
    }
}

int LoadBalancer::selectFP(const FiveTuple& tuple) {
    // FiveTupleHash hashes the canonical form of the tuple (fix E1).
    // Both A->B and B->A therefore produce the same hash and select the same FP,
    // ensuring bidirectional flow packets always reach the same worker thread.
    FiveTupleHash hasher;
    size_t hash = hasher(tuple);  // hasher internally calls tuple.canonical()
    return static_cast<int>(hash % static_cast<size_t>(num_fps_));
}

LoadBalancer::LBStats LoadBalancer::getStats() const {
    LBStats stats;
    stats.packets_received = packets_received_.load();
    stats.packets_dispatched = packets_dispatched_.load();
    
    stats.per_fp_packets = per_fp_counts_;
    
    return stats;
}

// ============================================================================
// LBManager Implementation
// ============================================================================

LBManager::LBManager(int num_lbs, int fps_per_lb,
                     std::vector<ThreadSafeQueue<PacketJob>*> fp_queues)
    : fps_per_lb_(fps_per_lb) {
    
    // Create load balancers, each handling a subset of FPs
    for (int lb_id = 0; lb_id < num_lbs; lb_id++) {
        std::vector<ThreadSafeQueue<PacketJob>*> lb_fp_queues;
        int fp_start = lb_id * fps_per_lb;
        
        for (int i = 0; i < fps_per_lb; i++) {
            lb_fp_queues.push_back(fp_queues[fp_start + i]);
        }
        
        lbs_.push_back(std::make_unique<LoadBalancer>(lb_id, lb_fp_queues, fp_start));
    }
    
    std::cout << "[LBManager] Created " << num_lbs << " load balancers, "
              << fps_per_lb << " FPs each\n";
}

LBManager::~LBManager() {
    stopAll();
}

void LBManager::startAll() {
    for (auto& lb : lbs_) {
        lb->start();
    }
}

void LBManager::stopAll() {
    for (auto& lb : lbs_) {
        lb->stop();
    }
}

LoadBalancer& LBManager::getLBForPacket(const FiveTuple& tuple) {
    // First level of load balancing: select LB based on hash
    FiveTupleHash hasher;
    size_t hash = hasher(tuple);
    int lb_index = hash % lbs_.size();
    return *lbs_[lb_index];
}

LBManager::AggregatedStats LBManager::getAggregatedStats() const {
    AggregatedStats stats = {0, 0};
    
    for (const auto& lb : lbs_) {
        auto lb_stats = lb->getStats();
        stats.total_received += lb_stats.packets_received;
        stats.total_dispatched += lb_stats.packets_dispatched;
    }
    
    return stats;
}

} // namespace DPI
