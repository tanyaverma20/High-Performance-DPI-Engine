#ifndef TCP_REASSEMBLER_H
#define TCP_REASSEMBLER_H

#include <vector>
#include <string>
#include <optional>
#include <chrono>
#include <cstdint>
#include <algorithm>

namespace DPI {

// ============================================================================
// TCP Reassembler - Bounded buffer for out-of-order reassembly
// ============================================================================
struct ReassemblerConfig {
    size_t max_buffer_bytes = 16 * 1024; // 16 KB strict aggregate max per direction
    std::chrono::seconds timeout_seconds{30};
};

class TCPReassembler {
public:
    explicit TCPReassembler(const ReassemblerConfig& config = ReassemblerConfig{})
        : config_(config) {}
    
    // Attempt to extract SNI from buffered payload
    // seq: the TCP sequence number of the payload
    std::optional<std::string> tryExtractSNI(uint32_t seq, const uint8_t* payload, size_t length);
    
    bool isFailed() const { return failed_; }
    void clear();

    // Utility for wraparound-safe sequence number comparison
    // Returns > 0 if s1 > s2, < 0 if s1 < s2, 0 if s1 == s2
    static int32_t seqDiff(uint32_t s1, uint32_t s2) {
        return static_cast<int32_t>(s1 - s2);
    }
    
    // Check if timeout has expired
    bool isTimedOut(std::chrono::steady_clock::time_point now) const {
        return !failed_ && (now - last_update_ > config_.timeout_seconds);
    }

private:
    struct Segment {
        uint32_t seq;
        std::vector<uint8_t> data;
        
        bool operator<(const Segment& o) const {
            return seqDiff(seq, o.seq) < 0;
        }
    };
    
    ReassemblerConfig config_;
    
    std::vector<uint8_t> buffer_; // In-order contiguous bytes
    uint32_t expected_seq_ = 0;   // The next sequence number we expect
    bool has_syn_ = false;
    bool expected_seq_initialized_ = false;
    
    std::vector<Segment> out_of_order_; // Out-of-order buffered segments
    size_t current_memory_usage_ = 0;   // Strict aggregate limit counter
    
    bool failed_ = false;
    std::chrono::steady_clock::time_point last_update_ = std::chrono::steady_clock::now();
    
    void mergeOutOfOrder();
};

} // namespace DPI

#endif // TCP_REASSEMBLER_H
