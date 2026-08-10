#ifndef DPI_TYPES_H
#define DPI_TYPES_H

#include <cstdint>
#include <string>
#include <functional>
#include <chrono>
#include <vector>
#include <atomic>
#include <optional>
#include <cstring>   // memcpy

namespace DPI {

// ============================================================================
// Five-Tuple: Uniquely identifies a connection/flow
// ============================================================================
struct FiveTuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;  // TCP=6, UDP=17

    bool operator==(const FiveTuple& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }

    // Create reverse tuple (server→client direction)
    FiveTuple reverse() const {
        return {dst_ip, src_ip, dst_port, src_port, protocol};
    }

    // ---------------------------------------------------------------------------
    // canonical() — direction-independent representation
    //
    // Both A→B and B→A return the same canonical FiveTuple so that hashing and
    // flow-table lookup are direction-agnostic.  We define "canonical" as the
    // ordering where (src_ip, src_port) <= (dst_ip, dst_port) lexicographically.
    //
    // Invariant: canonical(A→B) == canonical(B→A)
    // ---------------------------------------------------------------------------
    FiveTuple canonical() const {
        bool already_canonical =
            (src_ip < dst_ip) ||
            (src_ip == dst_ip && src_port <= dst_port);
        return already_canonical ? *this : reverse();
    }

    std::string toString() const;
};

// ============================================================================
// Hash function for FiveTuple — hashes the CANONICAL form so that both
// directions of the same flow produce the same hash value and select the same
// worker thread.
//
// Fix (D9/E1): previously hashed the raw tuple, causing A→B and B→A to hash
// to different values and be dispatched to different FP workers.
// ============================================================================
struct FiveTupleHash {
    size_t operator()(const FiveTuple& tuple) const {
        // Always hash the canonical form — direction-independent
        FiveTuple c = tuple.canonical();

        size_t h = 0;
        auto mix = [&](size_t v) {
            h ^= v + 0x9e3779b9 + (h << 6) + (h >> 2);
        };
        mix(std::hash<uint32_t>{}(c.src_ip));
        mix(std::hash<uint32_t>{}(c.dst_ip));
        mix(std::hash<uint16_t>{}(c.src_port));
        mix(std::hash<uint16_t>{}(c.dst_port));
        mix(std::hash<uint8_t>{}(c.protocol));
        return h;
    }
};

// ============================================================================
// Application Classification
// ============================================================================
enum class AppType {
    UNKNOWN = 0,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    // Specific applications (detected via SNI)
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE,
    // Add more as needed
    APP_COUNT  // Keep this last for counting
};

std::string appTypeToString(AppType type);
AppType sniToAppType(const std::string& sni);

// ============================================================================
// Connection State
// ============================================================================
enum class ConnectionState {
    NEW,
    ESTABLISHED,
    CLASSIFIED,
    BLOCKED,
    CLOSED
};

// ============================================================================
// Packet Action (what to do with the packet)
// ============================================================================
enum class PacketAction {
    FORWARD,    // Send to internet
    DROP,       // Block/drop the packet
    INSPECT,    // Needs further inspection
    LOG_ONLY    // Forward but log
};

// ============================================================================
// Connection Entry (tracked per flow)
//
// The flow is keyed by the CANONICAL five-tuple (direction-independent).
// The original_direction_is_canonical flag records whether the packet that
// created this connection was already in canonical form (i.e. was the
// initiating/client direction).  This is needed to correctly attribute
// directional byte counters and TCP handshake flags.
// ============================================================================
struct Connection {
    FiveTuple tuple;                   // Canonical (direction-independent) key
    bool original_is_canonical = true; // true = creator packet was client→server

    ConnectionState state = ConnectionState::NEW;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;  // Server Name Indication (if detected)

    uint64_t packets_in  = 0;  // client→server
    uint64_t packets_out = 0;  // server→client
    uint64_t bytes_in    = 0;
    uint64_t bytes_out   = 0;

    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;

    PacketAction action = PacketAction::FORWARD;

    // For TCP state tracking
    bool syn_seen     = false;
    bool syn_ack_seen = false;
    bool fin_seen     = false;
};

// ============================================================================
// Packet wrapper for queue passing
//
// Fix (D9): payload_data raw pointer has been removed.  It was set to
// data.data() + payload_offset at job-creation time, but after a std::move the
// vector is emptied and the pointer becomes dangling.
//
// Instead, call getPayload() which computes data.data() + payload_offset each
// time, always from the live vector.  Returns nullptr if out of bounds.
// ============================================================================
struct PacketJob {
    uint32_t packet_id = 0;
    FiveTuple tuple;
    std::vector<uint8_t> data;
    size_t eth_offset       = 0;
    size_t ip_offset        = 0;
    size_t transport_offset = 0;
    size_t payload_offset   = 0;
    size_t payload_length   = 0;
    uint8_t tcp_flags       = 0;

    // Timestamps
    uint32_t ts_sec  = 0;
    uint32_t ts_usec = 0;

    // Safe payload accessor — never returns a dangling pointer.
    // Returns nullptr if there is no payload or offset is out of bounds.
    const uint8_t* getPayload() const {
        if (payload_length == 0 || payload_offset >= data.size()) {
            return nullptr;
        }
        return data.data() + payload_offset;
    }
};

// ============================================================================
// Statistics - uses atomic uint64_t, protected by atomics
// ============================================================================
struct DPIStats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded_packets{0};
    std::atomic<uint64_t> dropped_packets{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    std::atomic<uint64_t> other_packets{0};
    std::atomic<uint64_t> active_connections{0};

    // Non-copyable due to atomics
    DPIStats() = default;
    DPIStats(const DPIStats&) = delete;
    DPIStats& operator=(const DPIStats&) = delete;
};

} // namespace DPI

#endif // DPI_TYPES_H
