#include "profiler.h"
#include <iostream>
#include <iomanip>

namespace DPI {

void Profiler::printReport(int workers) const {
    double wall_sec = total_wall_time_ns.load() / 1e9;
    uint64_t pkts = reader_packets.load();

    std::cout << "\n===================================================\n";
    std::cout << "     PHASE 3.1 PIPELINE PROFILING REPORT (" << workers << " FP Workers)\n";
    std::cout << "===================================================\n";
    std::cout << "Total Packets Processed: " << pkts << "\n";
    std::cout << "Total Wall-Clock Time:   " << std::fixed << std::setprecision(4) << wall_sec << " s\n";
    if (wall_sec > 0) {
        std::cout << "Throughput:              " << std::fixed << std::setprecision(0) << (pkts / wall_sec) << " pkts/sec\n";
    }

    uint64_t r_gen = reader_gen_raw_ns.load();
    uint64_t r_parse = reader_parse_ns.load();
    uint64_t r_job = reader_job_create_ns.load();
    uint64_t r_lookup = reader_lb_lookup_ns.load();
    uint64_t r_push_wait = reader_push_wait_ns.load();

    uint64_t reader_active_total = r_gen + r_parse + r_job + r_lookup + r_push_wait;

    uint64_t lb_lock = lb_pop_lock_ns.load();
    uint64_t lb_idle = lb_idle_ns.load();
    uint64_t lb_select = lb_select_fp_ns.load();
    uint64_t lb_push_wait = lb_push_wait_ns.load();
    uint64_t lb_active_total = lb_lock + lb_select + lb_push_wait;

    uint64_t fp_lock = fp_pop_lock_ns.load();
    uint64_t fp_idle = fp_idle_ns.load();
    uint64_t fp_conn = fp_conn_lookup_ns.load();
    uint64_t fp_rule = fp_rule_check_ns.load();
    uint64_t fp_inspect = fp_inspect_ns.load();
    uint64_t fp_action = fp_handle_action_ns.load();
    uint64_t fp_active_total = fp_lock + fp_conn + fp_rule + fp_inspect + fp_action;

    uint64_t out_lock = output_pop_lock_ns.load();
    uint64_t out_idle = output_idle_ns.load();
    uint64_t out_write = output_write_ns.load();
    uint64_t out_active_total = out_lock + out_write;

    auto print_line = [](const std::string& name, uint64_t ns, double ref_ns) {
        double ms = ns / 1e6;
        double pct = (ref_ns > 0) ? (ns * 100.0 / ref_ns) : 0.0;
        std::cout << "  - " << std::left << std::setw(32) << name 
                  << std::right << std::setw(10) << std::fixed << std::setprecision(2) << ms << " ms ("
                  << std::setw(6) << std::fixed << std::setprecision(2) << pct << "%)\n";
    };

    std::cout << "\n--- 1. READER THREAD BREAKDOWN (Sequential Upstream) ---\n";
    std::cout << "Total Reader Thread Active Time: " << (reader_active_total / 1e6) << " ms\n";
    print_line("Raw Packet Input / Generation", r_gen, reader_active_total);
    print_line("PacketParser::parse()", r_parse, reader_active_total);
    print_line("createPacketJob()", r_job, reader_active_total);
    print_line("getLBForPacket()", r_lookup, reader_active_total);
    print_line("Queue Push Wait (LB queue full)", r_push_wait, reader_active_total);

    std::cout << "\n--- 2. LOAD BALANCER THREAD BREAKDOWN ---\n";
    std::cout << "Total LB Thread Active CPU Time: " << (lb_active_total / 1e6) << " ms\n";
    print_line("Queue Lock Acquisition", lb_lock, lb_active_total);
    print_line("selectFP() & Dispatch", lb_select, lb_active_total);
    print_line("FP Queue Push Wait", lb_push_wait, lb_active_total);
    std::cout << "  - Idle / Waiting for Reader:     " << (lb_idle / 1e6) << " ms\n";

    std::cout << "\n--- 3. FASTPATH WORKER THREADS BREAKDOWN (Aggregated across " << workers << " workers) ---\n";
    std::cout << "Total FP Workers Active CPU Time: " << (fp_active_total / 1e6) << " ms\n";
    print_line("Queue Lock Acquisition", fp_lock, fp_active_total);
    print_line("Connection Tracker Lookup/Update", fp_conn, fp_active_total);
    print_line("Rule Manager Checks", fp_rule, fp_active_total);
    print_line("Payload Inspection / Reassembly", fp_inspect, fp_active_total);
    print_line("Action Handling & Output Push", fp_action, fp_active_total);
    std::cout << "  - Total FP Idle Time (Waiting):  " << (fp_idle / 1e6) << " ms\n";

    std::cout << "\n--- 4. OUTPUT WRITER THREAD BREAKDOWN ---\n";
    std::cout << "Total Output Thread Active Time:  " << (out_active_total / 1e6) << " ms\n";
    print_line("Queue Lock Acquisition", out_lock, out_active_total);
    print_line("writeOutputPacket() / I/O", out_write, out_active_total);
    std::cout << "  - Total Output Idle Time:        " << (out_idle / 1e6) << " ms\n";

    uint64_t total_locking = lb_lock + fp_lock + out_lock;
    std::cout << "\n--- 5. SYNCHRONIZATION & QUEUE SUMMARY ---\n";
    std::cout << "Total Mutex Lock Acquisition Time: " << (total_locking / 1e6) << " ms\n";
    std::cout << "Total Queue Backpressure Wait Time: " << ((r_push_wait + lb_push_wait) / 1e6) << " ms\n";

    std::cout << "===================================================\n\n";
}

} // namespace DPI
