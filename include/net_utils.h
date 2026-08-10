#ifndef DPI_NET_UTILS_H
#define DPI_NET_UTILS_H

// ============================================================================
// net_utils.h — Shared network utility functions
// ============================================================================
//
// Provides a single canonical implementation of common network helpers that
// were previously duplicated (as lambdas or inline code) across multiple
// translation units: dpi_engine.cpp, rule_manager.cpp, main_working.cpp, etc.
//
// Phase 1 scope: IPv4 address parsing from dotted-decimal string → uint32_t.
// Full IPv6 support is deferred to Phase 2.
// ============================================================================

#include <cstdint>
#include <string>

namespace DPI {

// ---------------------------------------------------------------------------
// parseIPv4Address
//
// Converts a dotted-decimal IPv4 string (e.g. "192.168.1.1") to a uint32_t
// in the same byte order used by PacketParser (matching the memcpy from the
// network packet — i.e. network/big-endian byte order stored as little-endian
// uint32 on x86, which is what the rest of the code expects after the existing
// memcpy in parseIPv4()).
//
// Returns 0 for empty or malformed input (same behaviour as the previous
// duplicated lambda implementations).
// ---------------------------------------------------------------------------
inline uint32_t parseIPv4Address(const std::string& ip) {
    uint32_t result = 0;
    int octet = 0;
    int shift = 0;

    for (char c : ip) {
        if (c == '.') {
            result |= (static_cast<uint32_t>(octet) << shift);
            shift += 8;
            octet = 0;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
        }
    }
    // Final octet
    result |= (static_cast<uint32_t>(octet) << shift);
    return result;
}

// ---------------------------------------------------------------------------
// ipv4ToString
//
// Converts a uint32_t IPv4 address (same byte order as parseIPv4Address
// above) back to a dotted-decimal string. Provided here so callers do not
// need to depend on PacketParser for this conversion.
// ---------------------------------------------------------------------------
inline std::string ipv4ToString(uint32_t ip) {
    // Each byte is a decimal octet
    return std::to_string((ip >> 0) & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 24) & 0xFF);
}

} // namespace DPI

#endif // DPI_NET_UTILS_H
