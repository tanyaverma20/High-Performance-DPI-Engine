#include "packet_parser.h"
#include "platform.h"
#include <sstream>
#include <iomanip>
#include <cstring>

using PortableNet::netToHost16;
using PortableNet::netToHost32;

#define ntohs(x) netToHost16(x)
#define ntohl(x) netToHost32(x)

namespace PacketAnalyzer {

// ============================================================================
// Top-level parse dispatcher
// ============================================================================
bool PacketParser::parse(const RawPacket& raw, ParsedPacket& parsed) {
    parsed = ParsedPacket{};
    parsed.timestamp_sec  = raw.header.ts_sec;
    parsed.timestamp_usec = raw.header.ts_usec;

    const uint8_t* data = raw.data.data();
    size_t len = raw.data.size();
    size_t offset = 0;

    if (!parseEthernet(data, len, parsed, offset)) return false;

    if (parsed.ether_type == EtherType::IPv4) {
        if (!parseIPv4(data, len, parsed, offset)) return false;

        if (parsed.protocol == Protocol::TCP) {
            if (!parseTCP(data, len, parsed, offset)) return false;
        } else if (parsed.protocol == Protocol::UDP) {
            if (!parseUDP(data, len, parsed, offset)) return false;
        } else if (parsed.protocol == Protocol::ICMP) {
            if (!parseICMP(data, len, parsed, offset)) return false;
        }

    } else if (parsed.ether_type == EtherType::IPv6) {
        if (!parseIPv6(data, len, parsed, offset)) return false;

        if (parsed.protocol == Protocol::TCP) {
            if (!parseTCP(data, len, parsed, offset)) return false;
        } else if (parsed.protocol == Protocol::UDP) {
            if (!parseUDP(data, len, parsed, offset)) return false;
        } else if (parsed.protocol == Protocol::ICMPv6) {
            if (!parseICMPv6(data, len, parsed, offset)) return false;
        }
    }
    // Other EtherTypes (ARP, etc.) — return true, has_ip remains false

    if (offset < len) {
        parsed.payload_length = len - offset;
        parsed.payload_data   = data + offset;
    }

    return true;
}

// ============================================================================
// Ethernet (14 bytes)
// ============================================================================
bool PacketParser::parseEthernet(const uint8_t* data, size_t len,
                                  ParsedPacket& parsed, size_t& offset) {
    constexpr size_t ETH_LEN = 14;
    if (len < ETH_LEN) return false;

    parsed.dest_mac = macToString(data);
    parsed.src_mac  = macToString(data + 6);

    uint16_t et_raw;
    std::memcpy(&et_raw, data + 12, 2);
    parsed.ether_type = ntohs(et_raw);

    offset = ETH_LEN;
    return true;
}

// ============================================================================
// IPv4 (minimum 20 bytes)
// ============================================================================
bool PacketParser::parseIPv4(const uint8_t* data, size_t len,
                              ParsedPacket& parsed, size_t& offset) {
    constexpr size_t MIN_IP4_LEN = 20;
    if (len < offset + MIN_IP4_LEN) return false;

    const uint8_t* ip = data + offset;
    uint8_t version = (ip[0] >> 4) & 0x0F;
    if (version != 4) return false;

    uint8_t ihl = ip[0] & 0x0F;
    size_t  ip_hdr_len = static_cast<size_t>(ihl) * 4;
    if (ip_hdr_len < MIN_IP4_LEN || len < offset + ip_hdr_len) return false;

    parsed.ip_version = 4;
    parsed.ttl        = ip[8];
    parsed.protocol   = ip[9];

    std::memcpy(&parsed.src_ip_raw, ip + 12, 4);
    std::memcpy(&parsed.dst_ip_raw, ip + 16, 4);
    parsed.src_ip  = ipToString(parsed.src_ip_raw);
    parsed.dest_ip = ipToString(parsed.dst_ip_raw);

    parsed.has_ip = true;
    offset += ip_hdr_len;
    return true;
}

// ============================================================================
// IPv6 (fixed 40-byte base header)
// ============================================================================
bool PacketParser::parseIPv6(const uint8_t* data, size_t len,
                              ParsedPacket& parsed, size_t& offset) {
    constexpr size_t IPV6_HEADER_LEN = 40;
    if (len < offset + IPV6_HEADER_LEN) return false;

    const uint8_t* ip6 = data + offset;

    uint8_t version = (ip6[0] >> 4) & 0x0F;
    if (version != 6) return false;

    // Traffic class (bits 4-11) and flow label (bits 12-31)
    parsed.ip_traffic_class = ((ip6[0] & 0x0F) << 4) | ((ip6[1] >> 4) & 0x0F);
    parsed.ip_flow_label    = (static_cast<uint32_t>(ip6[1] & 0x0F) << 16)
                            | (static_cast<uint32_t>(ip6[2]) << 8)
                            |  static_cast<uint32_t>(ip6[3]);

    // Payload length (bytes 4-5): length of everything after the 40-byte header
    uint16_t payload_len_raw;
    std::memcpy(&payload_len_raw, ip6 + 4, 2);
    uint16_t payload_len = ntohs(payload_len_raw);
    (void)payload_len; // used for validation; we rely on actual buffer length

    uint8_t next_hdr  = ip6[6];
    parsed.ip_hop_limit = ip6[7];
    parsed.ttl          = ip6[7];

    // Source address (bytes 8-23)
    std::memcpy(parsed.src_ipv6.data(), ip6 + 8,  16);
    // Destination address (bytes 24-39)
    std::memcpy(parsed.dst_ipv6.data(), ip6 + 24, 16);

    parsed.ip_version = 6;
    parsed.has_ip     = true;
    parsed.has_ipv6   = true;
    offset += IPV6_HEADER_LEN;

    // Walk extension headers to find the transport protocol
    parsed.protocol = walkIPv6ExtHeaders(data, len, offset, next_hdr, parsed);
    return true;
}

// ============================================================================
// walkIPv6ExtHeaders — safe bounded walk over IPv6 extension headers
//
// Recognised extension headers (next-header values):
//   0  Hop-by-Hop Options
//   43 Routing
//   44 Fragment
//   60 Destination Options
//
// All others are treated as the transport protocol and parsing stops.
//
// Safety guarantees:
//  - Never reads beyond [data, data+len)
//  - Never loops more than MAX_EXT_HEADERS times
//  - On truncation: sets parsed.ipv6_ext_unsupported, returns 0 (No Next Header)
// ============================================================================
uint8_t PacketParser::walkIPv6ExtHeaders(const uint8_t* data, size_t len,
                                          size_t& offset, uint8_t next_hdr,
                                          ParsedPacket& parsed) {
    constexpr int MAX_EXT_HEADERS = 10;

    auto isExtHeader = [](uint8_t nh) {
        return nh == Protocol::IPV6_HOP_BY_HOP ||
               nh == Protocol::IPV6_ROUTING     ||
               nh == Protocol::IPV6_FRAGMENT    ||
               nh == Protocol::IPV6_DEST_OPTS   ||
               nh == 51; // Protocol::IPV6_AUTH
    };

    for (int count = 0; count < MAX_EXT_HEADERS && isExtHeader(next_hdr); ++count) {
        // Set flags based on the header we are about to process
        if (next_hdr == Protocol::IPV6_HOP_BY_HOP) parsed.has_ipv6_hop_by_hop = true;
        else if (next_hdr == Protocol::IPV6_ROUTING) parsed.has_ipv6_routing = true;
        else if (next_hdr == Protocol::IPV6_FRAGMENT) parsed.has_ipv6_fragment = true;
        else if (next_hdr == Protocol::IPV6_DEST_OPTS) parsed.has_ipv6_dest_opts = true;
        else if (next_hdr == 51) parsed.has_ipv6_auth = true;

        // Fragment header is exactly 8 bytes with a fixed layout
        if (next_hdr == Protocol::IPV6_FRAGMENT) {
            if (offset + 8 > len) {
                parsed.ipv6_ext_unsupported = true;
                return Protocol::IPV6_NO_NEXT_HDR;
            }
            uint8_t next_nh = data[offset];
            
            // Fragment offset is in bytes 2 and 3 (13 bits). M flag is the lowest bit.
            uint16_t frag_data;
            std::memcpy(&frag_data, data + offset + 2, 2);
            frag_data = ntohs(frag_data);
            uint16_t frag_offset = (frag_data & 0xFFF8) >> 3;
            
            if (frag_offset > 0) {
                // This is a non-initial fragment. We MUST NOT parse the transport layer.
                // We return a special Protocol value to signify "Stop Parsing L4".
                // We could use IPV6_NO_NEXT_HDR, but keeping the actual protocol might be useful for logging.
                // To prevent parseTCP/UDP from running, we'll return Protocol::IPV6_NO_NEXT_HDR for non-initial fragments.
                parsed.protocol = next_nh; 
                parsed.ipv6_ext_unsupported = true; // Mark unsupported as we do not do full IP reassembly here
                offset += 8;
                return Protocol::IPV6_NO_NEXT_HDR;
            }
            
            next_hdr = next_nh;
            offset  += 8;
            continue;
        }

        // Variable-length extension headers: need at least 2 bytes (NH + Len)
        if (offset + 2 > len) {
            parsed.ipv6_ext_unsupported = true;
            return Protocol::IPV6_NO_NEXT_HDR;
        }

        uint8_t nh_field  = data[offset];
        uint8_t hdr_ext_len = data[offset + 1];

        size_t hdr_total = 0;
        if (next_hdr == 51) { // Authentication Header
            // AH length is specified in 4-byte units, minus 2
            hdr_total = (static_cast<size_t>(hdr_ext_len) + 2) * 4;
        } else {
            // Other extension headers: length in 8-byte units, not including first 8 bytes
            hdr_total = (static_cast<size_t>(hdr_ext_len) + 1) * 8;
        }

        if (offset + hdr_total > len || hdr_total < 8) {
            parsed.ipv6_ext_unsupported = true;
            return Protocol::IPV6_NO_NEXT_HDR;
        }

        next_hdr  = nh_field;
        offset   += hdr_total;
    }

    return next_hdr;
}

// ============================================================================
// TCP — hardened: validates data_offset range (5..15), header fits in buffer
// ============================================================================
bool PacketParser::parseTCP(const uint8_t* data, size_t len,
                             ParsedPacket& parsed, size_t& offset) {
    constexpr size_t MIN_TCP_LEN = 20;
    if (len < offset + MIN_TCP_LEN) return false;

    const uint8_t* tcp = data + offset;

    uint16_t tmp16;
    std::memcpy(&tmp16, tcp + 0, 2);
    parsed.src_port = ntohs(tmp16);

    std::memcpy(&tmp16, tcp + 2, 2);
    parsed.dest_port = ntohs(tmp16);

    uint32_t tmp32;
    std::memcpy(&tmp32, tcp + 4, 4);
    parsed.seq_number = ntohl(tmp32);

    std::memcpy(&tmp32, tcp + 8, 4);
    parsed.ack_number = ntohl(tmp32);

    uint8_t data_offset = (tcp[12] >> 4) & 0x0F;
    // Data offset must be 5..15 (20..60 bytes)
    if (data_offset < 5 || data_offset > 15) return false;

    size_t tcp_hdr_len = static_cast<size_t>(data_offset) * 4;
    // Header must fit within available buffer
    if (len < offset + tcp_hdr_len) return false;

    parsed.tcp_flags = tcp[13];

    parsed.has_tcp = true;
    offset += tcp_hdr_len;
    return true;
}

// ============================================================================
// UDP — hardened: validates length field
// ============================================================================
bool PacketParser::parseUDP(const uint8_t* data, size_t len,
                             ParsedPacket& parsed, size_t& offset) {
    constexpr size_t UDP_HDR_LEN = 8;
    if (len < offset + UDP_HDR_LEN) return false;

    const uint8_t* udp = data + offset;

    uint16_t tmp16;
    std::memcpy(&tmp16, udp + 0, 2);
    parsed.src_port = ntohs(tmp16);

    std::memcpy(&tmp16, udp + 2, 2);
    parsed.dest_port = ntohs(tmp16);

    // UDP length field includes the 8-byte header
    uint16_t udp_len_raw;
    std::memcpy(&udp_len_raw, udp + 4, 2);
    uint16_t udp_len = ntohs(udp_len_raw);

    // Minimum valid UDP length is 8 (header only, no payload)
    if (udp_len < UDP_HDR_LEN) return false;

    // UDP length must not claim more data than available in the buffer
    if (offset + udp_len > len) return false;

    parsed.has_udp = true;
    offset += UDP_HDR_LEN;
    return true;
}

// ============================================================================
// ICMP — safe recognition (type, code, minimum 8 bytes)
// ============================================================================
bool PacketParser::parseICMP(const uint8_t* data, size_t len,
                              ParsedPacket& parsed, size_t& offset) {
    constexpr size_t ICMP_MIN_LEN = 8;
    if (len < offset + ICMP_MIN_LEN) return false;

    parsed.icmp_type = data[offset];
    parsed.icmp_code = data[offset + 1];
    parsed.has_icmp  = true;
    offset += ICMP_MIN_LEN;
    return true;
}

// ============================================================================
// ICMPv6 — safe recognition (type, code, minimum 8 bytes)
// ============================================================================
bool PacketParser::parseICMPv6(const uint8_t* data, size_t len,
                                ParsedPacket& parsed, size_t& offset) {
    constexpr size_t ICMPV6_MIN_LEN = 8;
    if (len < offset + ICMPV6_MIN_LEN) return false;

    parsed.icmp_type   = data[offset];
    parsed.icmp_code   = data[offset + 1];
    parsed.has_icmpv6  = true;
    offset += ICMPV6_MIN_LEN;
    return true;
}

// ============================================================================
// Formatting helpers
// ============================================================================
std::string PacketParser::macToString(const uint8_t* mac) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; i++) {
        if (i > 0) ss << ":";
        ss << std::setw(2) << static_cast<int>(mac[i]);
    }
    return ss.str();
}

std::string PacketParser::ipToString(uint32_t ip) {
    // ip is stored in network byte order (as read by memcpy from wire)
    std::ostringstream ss;
    ss << ((ip >>  0) & 0xFF) << "."
       << ((ip >>  8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

std::string PacketParser::protocolToString(uint8_t protocol) {
    switch (protocol) {
        case Protocol::ICMP:   return "ICMP";
        case Protocol::TCP:    return "TCP";
        case Protocol::UDP:    return "UDP";
        case Protocol::ICMPv6: return "ICMPv6";
        default: return "Unknown(" + std::to_string(protocol) + ")";
    }
}

std::string PacketParser::tcpFlagsToString(uint8_t flags) {
    std::string result;
    if (flags & TCPFlags::SYN) result += "SYN ";
    if (flags & TCPFlags::ACK) result += "ACK ";
    if (flags & TCPFlags::FIN) result += "FIN ";
    if (flags & TCPFlags::RST) result += "RST ";
    if (flags & TCPFlags::PSH) result += "PSH ";
    if (flags & TCPFlags::URG) result += "URG ";
    if (!result.empty()) result.pop_back();
    return result.empty() ? "none" : result;
}

} // namespace PacketAnalyzer
