#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <cstdint>
#include <string>
#include <array>
#include "pcap_reader.h"
#include "ipv6_utils.h"

namespace PacketAnalyzer {

// Ethernet Header (14 bytes)
struct EthernetHeader {
    std::array<uint8_t, 6> dest_mac;
    std::array<uint8_t, 6> src_mac;
    uint16_t ether_type;
};

// IPv4 Header (20-60 bytes)
struct IPv4Header {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
};

// TCP Header (20-60 bytes)
struct TCPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t  data_offset;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

// UDP Header (8 bytes)
struct UDPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

// ============================================================================
// ParsedPacket — Phase 2: extended with IPv6, ICMP/ICMPv6, extension header flags
// ============================================================================
struct ParsedPacket {
    // Timestamps
    uint32_t timestamp_sec  = 0;
    uint32_t timestamp_usec = 0;

    // Ethernet layer
    std::string src_mac;
    std::string dest_mac;
    uint16_t ether_type = 0;

    // IP layer
    bool    has_ip      = false;
    uint8_t ip_version  = 0;   // 4 or 6

    // IPv4 fields
    std::string src_ip;        // human-readable (display only)
    std::string dest_ip;
    uint32_t    src_ip_raw = 0;  // network byte order as read by memcpy
    uint32_t    dst_ip_raw = 0;

    // IPv6 fields
    bool has_ipv6 = false;
    DPI::IPv6Address src_ipv6{};   // zeroed by default
    DPI::IPv6Address dst_ipv6{};
    uint8_t  ip_hop_limit      = 0;
    uint32_t ip_flow_label     = 0;
    uint8_t  ip_traffic_class  = 0;

    // Set when an IPv6 extension header could not be fully parsed
    bool ipv6_ext_unsupported = false;

    uint8_t protocol     = 0;  // final resolved protocol (after ext headers)
    uint8_t ttl          = 0;  // IPv4 TTL or IPv6 hop limit (shared)

    // Transport layer
    bool     has_tcp = false;
    bool     has_udp = false;
    uint16_t src_port  = 0;
    uint16_t dest_port = 0;

    // TCP-specific
    uint8_t  tcp_flags  = 0;
    uint32_t seq_number = 0;
    uint32_t ack_number = 0;

    // ICMP / ICMPv6
    bool    has_icmp   = false;
    bool    has_icmpv6 = false;
    uint8_t icmp_type  = 0;
    uint8_t icmp_code  = 0;

    // IPv6 Extension flags
    bool has_ipv6_hop_by_hop = false;
    bool has_ipv6_routing = false;
    bool has_ipv6_fragment = false;
    bool has_ipv6_dest_opts = false;
    bool has_ipv6_auth = false;

    // Payload
    size_t         payload_length = 0;
    const uint8_t* payload_data   = nullptr;  // Points into original packet
};

// ============================================================================
// PacketParser
// ============================================================================
class PacketParser {
public:
    static bool parse(const RawPacket& raw, ParsedPacket& parsed);

    static std::string macToString(const uint8_t* mac);
    static std::string ipToString(uint32_t ip);
    static std::string protocolToString(uint8_t protocol);
    static std::string tcpFlagsToString(uint8_t flags);

    // Walk IPv6 extension headers; updates offset to transport payload.
    // Returns the final next-header value (TCP/UDP/ICMPv6/etc.).
    // Sets parsed.ipv6_ext_unsupported on truncation or unrecognised headers.
    static uint8_t walkIPv6ExtHeaders(const uint8_t* data, size_t len,
                                       size_t& offset, uint8_t first_next_hdr,
                                       ParsedPacket& parsed);

private:
    static bool parseEthernet(const uint8_t* data, size_t len,
                               ParsedPacket& parsed, size_t& offset);
    static bool parseIPv4(const uint8_t* data, size_t len,
                           ParsedPacket& parsed, size_t& offset);
    static bool parseIPv6(const uint8_t* data, size_t len,
                           ParsedPacket& parsed, size_t& offset);

    static bool parseTCP(const uint8_t* data, size_t len,
                          ParsedPacket& parsed, size_t& offset);
    static bool parseUDP(const uint8_t* data, size_t len,
                          ParsedPacket& parsed, size_t& offset);
    static bool parseICMP(const uint8_t* data, size_t len,
                           ParsedPacket& parsed, size_t& offset);
    static bool parseICMPv6(const uint8_t* data, size_t len,
                              ParsedPacket& parsed, size_t& offset);
};

// TCP Flag constants
namespace TCPFlags {
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t RST = 0x04;
    constexpr uint8_t PSH = 0x08;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t URG = 0x20;
}

// Protocol numbers
namespace Protocol {
    constexpr uint8_t ICMP   = 1;
    constexpr uint8_t TCP    = 6;
    constexpr uint8_t UDP    = 17;
    constexpr uint8_t ICMPv6 = 58;

    // IPv6 extension header next-header values
    constexpr uint8_t IPV6_HOP_BY_HOP = 0;
    constexpr uint8_t IPV6_ROUTING     = 43;
    constexpr uint8_t IPV6_FRAGMENT    = 44;
    constexpr uint8_t IPV6_DEST_OPTS   = 60;
    constexpr uint8_t IPV6_NO_NEXT_HDR = 59;
}

// EtherType values
namespace EtherType {
    constexpr uint16_t IPv4 = 0x0800;
    constexpr uint16_t IPv6 = 0x86DD;
    constexpr uint16_t ARP  = 0x0806;
}

} // namespace PacketAnalyzer

#endif // PACKET_PARSER_H
