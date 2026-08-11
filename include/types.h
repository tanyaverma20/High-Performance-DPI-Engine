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
#include <variant>
#include "ipv6_utils.h"
#include "tcp_reassembler.h"

namespace DPI {

// ============================================================================
// Five-Tuple: Uniquely identifies a connection/flow (IPv4 only)
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

    FiveTuple reverse() const {
        return {dst_ip, src_ip, dst_port, src_port, protocol};
    }

    FiveTuple canonical() const {
        bool already_canonical =
            (src_ip < dst_ip) ||
            (src_ip == dst_ip && src_port <= dst_port);
        return already_canonical ? *this : reverse();
    }

    std::string toString() const;
};

struct FiveTupleHash {
    size_t operator()(const FiveTuple& tuple) const {
        FiveTuple c = tuple.canonical();
        size_t h = 0;
        auto mix = [&](size_t v) { h ^= v + 0x9e3779b9 + (h << 6) + (h >> 2); };
        mix(std::hash<uint32_t>{}(c.src_ip));
        mix(std::hash<uint32_t>{}(c.dst_ip));
        mix(std::hash<uint16_t>{}(c.src_port));
        mix(std::hash<uint16_t>{}(c.dst_port));
        mix(std::hash<uint8_t>{}(c.protocol));
        return h;
    }
};

using IPv4Addr = uint32_t;
using IPAddress = std::variant<IPv4Addr, IPv6Address>;

struct FlowKey {
    IPAddress src_addr;
    IPAddress dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;

    bool isIPv6() const { return src_addr.index() == 1; }

    static FlowKey fromFiveTuple(const FiveTuple& t) {
        return { t.src_ip, t.dst_ip, t.src_port, t.dst_port, t.protocol };
    }

    static FlowKey fromIPv6(const IPv6Address& src, const IPv6Address& dst, uint16_t sport, uint16_t dport, uint8_t proto) {
        return { src, dst, sport, dport, proto };
    }

    bool operator==(const FlowKey& o) const {
        return src_addr == o.src_addr &&
               dst_addr == o.dst_addr &&
               src_port == o.src_port &&
               dst_port == o.dst_port &&
               protocol == o.protocol;
    }
    
    bool operator!=(const FlowKey& o) const {
        return !(*this == o);
    }

    FlowKey reverse() const {
        return { dst_addr, src_addr, dst_port, src_port, protocol };
    }

    FlowKey canonical() const;
    std::string toString() const;
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& key) const;
};

enum class AppType {
    UNKNOWN = 0,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
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
    APP_COUNT
};

std::string appTypeToString(AppType type);
AppType sniToAppType(const std::string& sni);

enum class ConnectionState {
    NEW,
    ESTABLISHED,
    CLASSIFIED,
    BLOCKED,
    CLOSED
};

enum class PacketAction {
    FORWARD,
    DROP,
    INSPECT,
    LOG_ONLY
};

struct Connection {
    FlowKey flow_key;
    bool has_flow_key = false;
    FiveTuple tuple;
    bool original_is_canonical = true;

    ConnectionState state = ConnectionState::NEW;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;
    std::string http_host;
    std::string dns_query;

    uint64_t packets_in  = 0;
    uint64_t packets_out = 0;
    uint64_t bytes_in    = 0;
    uint64_t bytes_out   = 0;

    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;

    PacketAction action = PacketAction::FORWARD;

    bool syn_seen     = false;
    bool syn_ack_seen = false;
    bool fin_seen     = false;

    // Per-flow direction-specific TCP reassembly (max 16KB each)
    TCPReassembler tcp_reassembler_client;
    TCPReassembler tcp_reassembler_server;

    std::string bestDomain() const {
        if (!sni.empty()) return sni;
        if (!http_host.empty()) return http_host;
        if (!dns_query.empty()) return dns_query;
        return "";
    }
};

struct PacketJob {
    uint32_t packet_id = 0;
    FiveTuple tuple;
    FlowKey flow_key;
    bool has_flow_key = false;
    uint32_t tcp_seq_number = 0;

    std::vector<uint8_t> data;
    size_t eth_offset       = 0;
    size_t ip_offset        = 0;
    size_t transport_offset = 0;
    size_t payload_offset   = 0;
    size_t payload_length   = 0;
    uint8_t tcp_flags       = 0;

    uint32_t ts_sec  = 0;
    uint32_t ts_usec = 0;

    const uint8_t* getPayload() const {
        if (payload_length == 0 || payload_offset >= data.size()) {
            return nullptr;
        }
        return data.data() + payload_offset;
    }
};

struct DPIStats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded_packets{0};
    std::atomic<uint64_t> dropped_packets{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    std::atomic<uint64_t> other_packets{0};
    std::atomic<uint64_t> active_connections{0};

    DPIStats() = default;
    DPIStats(const DPIStats&) = delete;
    DPIStats& operator=(const DPIStats&) = delete;
};

} // namespace DPI

#endif // DPI_TYPES_H
