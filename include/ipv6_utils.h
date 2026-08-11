#ifndef DPI_IPV6_UTILS_H
#define DPI_IPV6_UTILS_H

// ============================================================================
// ipv6_utils.h  —  IPv6 address type, hashing, and string conversion
//
// Phase 2: IPv6 is represented as a fixed-size std::array<uint8_t,16>.
// This gives value semantics, cheap copy, and direct comparability with
// std::array's lexicographic operator<.
//
// String output uses RFC 5952 canonical form (:: compression of longest
// consecutive run of all-zero 16-bit groups, minimum run length 2).
// ============================================================================

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <sstream>
#include <string>

namespace DPI {

// ============================================================================
// IPv6Address — 16-byte fixed-size representation
// ============================================================================
using IPv6Address = std::array<uint8_t, 16>;

// ============================================================================
// ipv6ToString — RFC 5952 canonical IPv6 string
// ============================================================================
inline std::string ipv6ToString(const IPv6Address& addr) {
    // Parse into 8 big-endian 16-bit groups
    uint16_t g[8];
    for (int i = 0; i < 8; ++i) {
        g[i] = (static_cast<uint16_t>(addr[2 * i]) << 8) | addr[2 * i + 1];
    }

    // Find longest run of consecutive zero groups (>= 2) for :: compression
    int best_start = -1, best_len = 0;
    {
        int cs = -1, cl = 0;
        for (int i = 0; i <= 8; ++i) {
            if (i < 8 && g[i] == 0) {
                if (cs < 0) { cs = i; cl = 1; } else ++cl;
            } else {
                if (cl >= 2 && cl > best_len) { best_start = cs; best_len = cl; }
                cs = -1; cl = 0;
            }
        }
    }

    std::ostringstream out;
    out << std::hex;
    bool prev_collapsed = false;

    for (int i = 0; i < 8; ) {
        if (i == best_start) {
            out << "::";
            prev_collapsed = true;
            i += best_len;
        } else {
            if (i > 0 && !prev_collapsed) out << ':';
            prev_collapsed = false;
            out << g[i];
            ++i;
        }
    }

    return out.str();
}

// ============================================================================
// IPv6AddressHash — for use in unordered containers
// ============================================================================
struct IPv6AddressHash {
    size_t operator()(const IPv6Address& addr) const noexcept {
        size_t h = 0;
        auto mix = [&](size_t v) {
            h ^= v + 0x9e3779b9ULL + (h << 6) + (h >> 2);
        };
        // Hash as four 32-bit chunks
        for (int i = 0; i < 4; ++i) {
            uint32_t chunk = 0;
            std::memcpy(&chunk, addr.data() + i * 4, 4);
            mix(std::hash<uint32_t>{}(chunk));
        }
        return h;
    }
};

} // namespace DPI

#endif // DPI_IPV6_UTILS_H
