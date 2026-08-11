#ifndef PROFILER_H
#define PROFILER_H

#include <atomic>
#include <cstdint>
#include <string>
#include <chrono>
#include <iostream>
#include <iomanip>

namespace DPI {

class Profiler {
public:
    static Profiler& instance() {
        static Profiler p;
        return p;
    }

    void reset() {
        reader_gen_raw_ns.store(0);
        reader_parse_ns.store(0);
        reader_job_create_ns.store(0);
        reader_lb_lookup_ns.store(0);
        reader_push_wait_ns.store(0);

        lb_pop_lock_ns.store(0);
        lb_idle_ns.store(0);
        lb_select_fp_ns.store(0);
        lb_push_wait_ns.store(0);

        fp_pop_lock_ns.store(0);
        fp_idle_ns.store(0);
        fp_conn_lookup_ns.store(0);
        fp_rule_check_ns.store(0);
        fp_inspect_ns.store(0);
        fp_handle_action_ns.store(0);

        output_pop_lock_ns.store(0);
        output_idle_ns.store(0);
        output_write_ns.store(0);

        reader_packets.store(0);
        lb_packets.store(0);
        fp_packets.store(0);
        output_packets.store(0);

        total_wall_time_ns.store(0);
    }

    // Reader stats
    std::atomic<uint64_t> reader_gen_raw_ns{0};
    std::atomic<uint64_t> reader_parse_ns{0};
    std::atomic<uint64_t> reader_job_create_ns{0};
    std::atomic<uint64_t> reader_lb_lookup_ns{0};
    std::atomic<uint64_t> reader_push_wait_ns{0};

    // Load Balancer stats
    std::atomic<uint64_t> lb_pop_lock_ns{0};
    std::atomic<uint64_t> lb_idle_ns{0};
    std::atomic<uint64_t> lb_select_fp_ns{0};
    std::atomic<uint64_t> lb_push_wait_ns{0};

    // FastPath stats
    std::atomic<uint64_t> fp_pop_lock_ns{0};
    std::atomic<uint64_t> fp_idle_ns{0};
    std::atomic<uint64_t> fp_conn_lookup_ns{0};
    std::atomic<uint64_t> fp_rule_check_ns{0};
    std::atomic<uint64_t> fp_inspect_ns{0};
    std::atomic<uint64_t> fp_handle_action_ns{0};

    // Output stats
    std::atomic<uint64_t> output_pop_lock_ns{0};
    std::atomic<uint64_t> output_idle_ns{0};
    std::atomic<uint64_t> output_write_ns{0};

    // Packet counts
    std::atomic<uint64_t> reader_packets{0};
    std::atomic<uint64_t> lb_packets{0};
    std::atomic<uint64_t> fp_packets{0};
    std::atomic<uint64_t> output_packets{0};

    // Overall wall time
    std::atomic<uint64_t> total_wall_time_ns{0};

    void printReport(int workers) const;
};

struct ScopedNsTimer {
    std::atomic<uint64_t>& acc;
    std::chrono::high_resolution_clock::time_point t0;
    ScopedNsTimer(std::atomic<uint64_t>& accumulator)
        : acc(accumulator), t0(std::chrono::high_resolution_clock::now()) {}
    ~ScopedNsTimer() {
        auto t1 = std::chrono::high_resolution_clock::now();
        uint64_t ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
        acc.fetch_add(ns, std::memory_order_relaxed);
    }
};

} // namespace DPI

#endif // PROFILER_H
