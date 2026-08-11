#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <string>
#include <algorithm>
#include "dpi_engine.h"
#include "profiler.h"

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif

using namespace DPI;

static size_t getPeakMemoryMB() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.PeakWorkingSetSize / (1024 * 1024);
    }
#endif
    return 0;
}

static double getProcessCPUTimeSec() {
#ifdef _WIN32
    FILETIME ftCreate, ftExit, ftKernel, ftUser;
    if (GetProcessTimes(GetCurrentProcess(), &ftCreate, &ftExit, &ftKernel, &ftUser)) {
        ULARGE_INTEGER k, u;
        k.LowPart  = ftKernel.dwLowDateTime;
        k.HighPart = ftKernel.dwHighDateTime;
        u.LowPart  = ftUser.dwLowDateTime;
        u.HighPart = ftUser.dwHighDateTime;
        return static_cast<double>(k.QuadPart + u.QuadPart) / 10000000.0;
    }
#endif
    return 0.0;
}

static std::vector<RawPacketJob> generateDataset(int num_packets) {
    std::vector<uint8_t> base_data = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
        0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    std::vector<RawPacketJob> dataset;
    dataset.reserve(num_packets);
    for (int i = 0; i < num_packets; i++) {
        RawPacketJob raw_job;
        raw_job.packet_id = i;
        raw_job.ts_sec = 0;
        raw_job.ts_usec = i;
        raw_job.data = base_data;
        raw_job.data[34 + 7] = static_cast<uint8_t>(i % 256);
        raw_job.data[29] = (i % 100) + 1;
        dataset.push_back(std::move(raw_job));
    }
    return dataset;
}

static void runWorkloadExperiment(int num_packets, const std::vector<int>& parser_counts, int fps_per_lb) {
    std::cout << "\n===================================================\n";
    std::cout << " WORKLOAD: " << num_packets << " PACKETS (Generating Dataset...)\n";
    std::cout << "===================================================\n";

    auto dataset = generateDataset(num_packets);
    std::cout << "[Workload] Pre-allocated " << dataset.size() << " raw packet jobs in memory.\n\n";

    double baseline_pps = 0.0;

    for (int parsers : parser_counts) {
        DPIEngine::Config config;
        config.num_parser_workers = parsers;
        config.num_load_balancers = 1;
        config.fps_per_lb = fps_per_lb;
        config.verbose = false;
        
        DPIEngine engine(config);
        
        std::cout << ">>> Run: Packets = " << num_packets 
                  << " | Parser Workers = " << parsers 
                  << " | FP Workers = " << fps_per_lb << "..." << std::endl;
        
        double cpu_start = getProcessCPUTimeSec();
        auto start_time = std::chrono::high_resolution_clock::now();
        engine.processSynthetic(dataset);
        auto end_time = std::chrono::high_resolution_clock::now();
        double cpu_end = getProcessCPUTimeSec();
        
        std::chrono::duration<double> elapsed = end_time - start_time;
        double pps = num_packets / elapsed.count();
        double mbps = (num_packets * 54.0) / (1024 * 1024 * elapsed.count());
        double cpu_time = cpu_end - cpu_start;

        if (parsers == parser_counts[0]) {
            baseline_pps = pps;
        }

        double speedup = (baseline_pps > 0.0) ? (pps / baseline_pps) : 1.0;
        double pct_gain = (baseline_pps > 0.0) ? ((pps - baseline_pps) / baseline_pps * 100.0) : 0.0;
        
        const auto& stats = engine.getStats();
        size_t peak_mem_mb = getPeakMemoryMB();

        std::cout << "  [Result] Packets: " << num_packets << " | Parsers: " << parsers << " | FPs: " << fps_per_lb << std::endl;
        std::cout << "  [Result] Elapsed Time:   " << std::fixed << std::setprecision(3) << elapsed.count() << " s" << std::endl;
        std::cout << "  [Result] Throughput:     " << std::fixed << std::setprecision(0) << pps << " pkts/sec" << std::endl;
        std::cout << "  [Result] Bandwidth:      " << std::fixed << std::setprecision(2) << mbps << " MB/sec" << std::endl;
        std::cout << "  [Result] Speedup:        " << std::fixed << std::setprecision(2) << speedup << "x vs Baseline" << std::endl;
        std::cout << "  [Result] Improvement:    " << std::showpos << std::setprecision(1) << pct_gain << "%" << std::noshowpos << std::endl;
        std::cout << "  [Result] Process CPU:    " << std::fixed << std::setprecision(2) << cpu_time << " s active CPU" << std::endl;
        std::cout << "  [Result] Peak Memory:    " << peak_mem_mb << " MB" << std::endl;
        std::cout << "  [Result] Packet Drops:   " << stats.dropped_packets.load() << std::endl;

        Profiler::instance().printReport(fps_per_lb);
    }
}

int main(int argc, char* argv[]) {
    std::cout << "===================================================\n";
    std::cout << "  DPI ENGINE PHASE 3.3 PERFORMANCE VALIDATION SUITE\n";
    std::cout << "===================================================\n";

    std::vector<int> target_workloads;
    std::vector<int> parser_counts = {1, 2, 4, 8};
    int fps = 4;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if ((arg == "--packets" || arg == "-n") && i + 1 < argc) {
            target_workloads.push_back(std::stoi(argv[++i]));
        } else if ((arg == "--parsers" || arg == "--parser-workers" || arg == "-p") && i + 1 < argc) {
            parser_counts = { std::stoi(argv[++i]) };
        } else if (arg == "--fps" && i + 1 < argc) {
            fps = std::stoi(argv[++i]);
        } else if (arg == "--all") {
            target_workloads = {100000, 1000000};
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: dpi_benchmark.exe [options]\n"
                      << "  --packets N, -n N        Specify workload packet count (e.g. 100000, 1000000)\n"
                      << "  --parsers N, -p N        Run specific parser worker count (default: 1 2 4 8)\n"
                      << "  --fps N                  Specify FastPath worker count (default: 4)\n"
                      << "  --all                    Run both 100,000 and 1,000,000 packet workloads\n"
                      << "  --help, -h               Show this help message\n";
            return 0;
        }
    }

    if (target_workloads.empty()) {
        target_workloads = {10000};
        std::cout << "[Note] No --packets argument specified. Defaulting to lightweight workload (" 
                  << target_workloads[0] << " packets).\n";
        std::cout << "[Note] To run large-scale validation: use --packets 100000, --packets 1000000, or --all.\n";
    }

    // Warm-up run
    {
        DPIEngine::Config warmup_cfg;
        warmup_cfg.num_parser_workers = 1;
        warmup_cfg.num_load_balancers = 1;
        warmup_cfg.fps_per_lb = 1;
        warmup_cfg.verbose = false;
        DPIEngine warmup_engine(warmup_cfg);
        warmup_engine.processSynthetic(1000);
    }

    for (int num_pkts : target_workloads) {
        runWorkloadExperiment(num_pkts, parser_counts, fps);
    }

    std::cout << "\n===================================================\n";
    std::cout << "  Phase 3.3 Benchmarking & Validation Complete\n";
    std::cout << "===================================================\n";
    return 0;
}
