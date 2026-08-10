#include "packet_parser.h"
#include "platform.h"
#include <sstream>
#include <iomanip>
#include <cstring>

// Use portable byte order functions
using PortableNet::netToHost16;
using PortableNet::netToHost32;

// Wrapper macros for compatibility — applied to values already read via memcpy
#define ntohs(x) netToHost16(x)
#define ntohl(x) netToHost32(x)

namespace PacketAnalyzer {

bool PacketParser::parse(const RawPacket& raw, ParsedPacket& parsed) {
    // Initialize parsed packet
    parsed = ParsedPacket();
    parsed.timestamp_sec  = raw.header.ts_sec;
    parsed.timestamp_usec = raw.header.ts_usec;

    const uint8_t* data = raw.data.data();
    size_t len = raw.data.size();
    size_t offset = 0;

    // Parse Ethernet header first
    if (!parseEthernet(data, len, parsed, offset)) {
        return false;
    }

    // Parse IP layer if it's an IPv4 packet
    if (parsed.ether_type == EtherType::IPv4) {
        if (!parseIPv4(data, len, parsed, offset)) {
            return false;
        }

        // Parse transport layer based on protocol
        if (parsed.protocol == Protocol::TCP) {
            if (!parseTCP(data, len, parsed, offset)) {
                return false;
            }
        } else if (parsed.protocol == Protocol::UDP) {
            if (!parseUDP(data, len, parsed, offset)) {
                return false;
            }
        }
    }

    // Set payload information
    if (offset < len) {
        parsed.payload_length = len - offset;
        parsed.payload_data   = data + offset;
    } else {
        parsed.payload_length = 0;
        parsed.payload_data   = nullptr;
    }

    return true;
}

bool PacketParser::parseEthernet(const uint8_t* data, size_t len,
                                  ParsedPacket& parsed, size_t& offset) {
    // Ethernet header is 14 bytes
    constexpr size_t ETH_HEADER_LEN = 14;

    if (len < ETH_HEADER_LEN) {
        return false;  // Packet too short
    }

    // Parse destination MAC (bytes 0-5)
    parsed.dest_mac = macToString(data);

    // Parse source MAC (bytes 6-11)
    parsed.src_mac = macToString(data + 6);

    // Parse EtherType (bytes 12-13, big-endian)
    // Fix (D4): use memcpy instead of reinterpret_cast to avoid UB on
    // architectures that require aligned 16-bit access.
    uint16_t ether_type_raw;
    std::memcpy(&ether_type_raw, data + 12, 2);
    parsed.ether_type = ntohs(ether_type_raw);

    offset = ETH_HEADER_LEN;
    return true;
}

bool PacketParser::parseIPv4(const uint8_t* data, size_t len,
                              ParsedPacket& parsed, size_t& offset) {
    // Minimum IPv4 header is 20 bytes
    constexpr size_t MIN_IP_HEADER_LEN = 20;

    if (len < offset + MIN_IP_HEADER_LEN) {
        return false;  // Packet too short
    }

    const uint8_t* ip_data = data + offset;

    // First byte: version (4 bits) + IHL (4 bits)
    uint8_t version_ihl    = ip_data[0];
    parsed.ip_version      = (version_ihl >> 4) & 0x0F;
    uint8_t ihl            = version_ihl & 0x0F;  // Header length in 32-bit words

    if (parsed.ip_version != 4) {
        return false;  // Not IPv4
    }

    size_t ip_header_len = ihl * 4;  // Convert to bytes
    if (ip_header_len < MIN_IP_HEADER_LEN || len < offset + ip_header_len) {
        return false;
    }

    // Parse fields
    parsed.ttl      = ip_data[8];
    parsed.protocol = ip_data[9];

    // Source IP (bytes 12-15) — memcpy preserves the wire byte order
    std::memcpy(&parsed.src_ip_raw, ip_data + 12, 4);
    parsed.src_ip = ipToString(parsed.src_ip_raw);

    // Destination IP (bytes 16-19)
    std::memcpy(&parsed.dst_ip_raw, ip_data + 16, 4);
    parsed.dest_ip = ipToString(parsed.dst_ip_raw);

    parsed.has_ip = true;
    offset += ip_header_len;

    return true;
}

bool PacketParser::parseTCP(const uint8_t* data, size_t len,
                             ParsedPacket& parsed, size_t& offset) {
    // Minimum TCP header is 20 bytes
    constexpr size_t MIN_TCP_HEADER_LEN = 20;

    if (len < offset + MIN_TCP_HEADER_LEN) {
        return false;
    }

    const uint8_t* tcp_data = data + offset;

    // Fix (D4): all multi-byte reads use memcpy — no reinterpret_cast on
    // potentially unaligned byte-buffer pointers.

    // Source port (bytes 0-1)
    uint16_t tmp16;
    std::memcpy(&tmp16, tcp_data + 0, 2);
    parsed.src_port = ntohs(tmp16);

    // Destination port (bytes 2-3)
    std::memcpy(&tmp16, tcp_data + 2, 2);
    parsed.dest_port = ntohs(tmp16);

    // Sequence number (bytes 4-7)
    uint32_t tmp32;
    std::memcpy(&tmp32, tcp_data + 4, 4);
    parsed.seq_number = ntohl(tmp32);

    // Acknowledgment number (bytes 8-11)
    std::memcpy(&tmp32, tcp_data + 8, 4);
    parsed.ack_number = ntohl(tmp32);

    // Data offset (upper 4 bits of byte 12) — header length in 32-bit words
    uint8_t data_offset  = (tcp_data[12] >> 4) & 0x0F;
    size_t tcp_header_len = data_offset * 4;

    // Flags (byte 13)
    parsed.tcp_flags = tcp_data[13];

    if (tcp_header_len < MIN_TCP_HEADER_LEN || len < offset + tcp_header_len) {
        return false;
    }

    parsed.has_tcp = true;
    offset += tcp_header_len;

    return true;
}

bool PacketParser::parseUDP(const uint8_t* data, size_t len,
                             ParsedPacket& parsed, size_t& offset) {
    // UDP header is always 8 bytes
    constexpr size_t UDP_HEADER_LEN = 8;

    if (len < offset + UDP_HEADER_LEN) {
        return false;
    }

    const uint8_t* udp_data = data + offset;

    // Fix (D4): memcpy instead of reinterpret_cast

    // Source port (bytes 0-1)
    uint16_t tmp16;
    std::memcpy(&tmp16, udp_data + 0, 2);
    parsed.src_port = ntohs(tmp16);

    // Destination port (bytes 2-3)
    std::memcpy(&tmp16, udp_data + 2, 2);
    parsed.dest_port = ntohs(tmp16);

    parsed.has_udp = true;
    offset += UDP_HEADER_LEN;

    return true;
}

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
    // IP is stored in network byte order (big-endian, as read by memcpy).
    // Extract each octet directly.
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

std::string PacketParser::protocolToString(uint8_t protocol) {
    switch (protocol) {
        case Protocol::ICMP: return "ICMP";
        case Protocol::TCP:  return "TCP";
        case Protocol::UDP:  return "UDP";
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
    if (!result.empty()) result.pop_back();  // Remove trailing space
    return result.empty() ? "none" : result;
}

} // namespace PacketAnalyzer
