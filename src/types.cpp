#include "types.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace DPI {

// ============================================================================
// FiveTuple::toString
// ============================================================================
std::string FiveTuple::toString() const {
    auto formatIP = [](uint32_t ip) {
        std::ostringstream s;
        s << ((ip >> 0) & 0xFF) << "."
          << ((ip >> 8) & 0xFF) << "."
          << ((ip >> 16) & 0xFF) << "."
          << ((ip >> 24) & 0xFF);
        return s.str();
    };
    std::ostringstream ss;
    ss << formatIP(src_ip) << ":" << src_port
       << " -> "
       << formatIP(dst_ip) << ":" << dst_port
       << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") << ")";
    return ss.str();
}

// ============================================================================
// FlowKey helpers — private to this translation unit
// ============================================================================

// Lexicographic comparison of two IPAddress values.
// Precondition: both are the same variant type (enforced by flow construction).
// Returns true if a < b.
static bool ipAddrLess(const IPAddress& a, const IPAddress& b) {
    if (a.index() != b.index()) {
        // Different families — sort IPv4 before IPv6 arbitrarily
        return a.index() < b.index();
    }
    if (const auto* pa = std::get_if<IPv4Addr>(&a)) {
        return *pa < std::get<IPv4Addr>(b);
    }
    return std::get<IPv6Address>(a) < std::get<IPv6Address>(b);
}

static bool ipAddrEqual(const IPAddress& a, const IPAddress& b) {
    return a == b;
}

// ============================================================================
// FlowKey::canonical — direction-independent (same algorithm for IPv4/IPv6)
// ============================================================================
FlowKey FlowKey::canonical() const {
    bool already =
        ipAddrLess(src_addr, dst_addr) ||
        (ipAddrEqual(src_addr, dst_addr) && src_port <= dst_port);
    return already ? *this : reverse();
}

// ============================================================================
// FlowKey::toString — for logging/reporting only
// ============================================================================
std::string FlowKey::toString() const {
    std::ostringstream ss;
    if (const auto* pv4 = std::get_if<IPv4Addr>(&src_addr)) {
        uint32_t s = *pv4;
        ss << ((s>>0)&0xFF) << "." << ((s>>8)&0xFF) << "."
           << ((s>>16)&0xFF) << "." << ((s>>24)&0xFF);
    } else {
        ss << ipv6ToString(std::get<IPv6Address>(src_addr));
    }
    ss << ":" << src_port << " -> ";
    if (const auto* pv4 = std::get_if<IPv4Addr>(&dst_addr)) {
        uint32_t d = *pv4;
        ss << ((d>>0)&0xFF) << "." << ((d>>8)&0xFF) << "."
           << ((d>>16)&0xFF) << "." << ((d>>24)&0xFF);
    } else {
        ss << ipv6ToString(std::get<IPv6Address>(dst_addr));
    }
    ss << ":" << dst_port;
    ss << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP"
                 : protocol == 1 ? "ICMP" : protocol == 58 ? "ICMPv6" : "?") << ")";
    return ss.str();
}

// ============================================================================
// FlowKeyHash — hashes canonical form (direction-independent)
// ============================================================================
size_t FlowKeyHash::operator()(const FlowKey& key) const {
    FlowKey c = key.canonical();
    size_t h = 0;
    auto mix = [&](size_t v) {
        h ^= v + 0x9e3779b9ULL + (h << 6) + (h >> 2);
    };

    // Mix in ip_version so IPv4 and IPv6 flows can't collide
    mix(c.src_addr.index());

    // Hash source address
    if (const auto* pv4 = std::get_if<IPv4Addr>(&c.src_addr)) {
        mix(std::hash<uint32_t>{}(*pv4));
    } else {
        const auto& a = std::get<IPv6Address>(c.src_addr);
        for (int i = 0; i < 4; ++i) {
            uint32_t chunk = 0;
            std::memcpy(&chunk, a.data() + i * 4, 4);
            mix(std::hash<uint32_t>{}(chunk));
        }
    }

    // Hash destination address
    if (const auto* pv4 = std::get_if<IPv4Addr>(&c.dst_addr)) {
        mix(std::hash<uint32_t>{}(*pv4));
    } else {
        const auto& a = std::get<IPv6Address>(c.dst_addr);
        for (int i = 0; i < 4; ++i) {
            uint32_t chunk = 0;
            std::memcpy(&chunk, a.data() + i * 4, 4);
            mix(std::hash<uint32_t>{}(chunk));
        }
    }

    mix(std::hash<uint16_t>{}(c.src_port));
    mix(std::hash<uint16_t>{}(c.dst_port));
    mix(std::hash<uint8_t>{}(c.protocol));
    return h;
}

// ============================================================================
// Domain matching helpers (unchanged from Phase 1)
// ============================================================================
static std::string normalizeDomain(const std::string& s) {
    if (s.empty()) return {};
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        out.push_back(static_cast<char>(std::tolower(c)));
    }
    if (!out.empty() && out.back() == '.') out.pop_back();
    return out;
}

static bool isDomainOrSubdomain(const std::string& host, const std::string& apex) {
    if (host.empty() || apex.empty()) return false;
    if (host == apex) return true;
    if (host.size() <= apex.size()) return false;
    size_t dot_pos = host.size() - apex.size() - 1;
    return host[dot_pos] == '.' &&
           host.compare(dot_pos + 1, apex.size(), apex) == 0;
}

// ============================================================================
// appTypeToString
// ============================================================================
std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::UNKNOWN:    return "Unknown";
        case AppType::HTTP:       return "HTTP";
        case AppType::HTTPS:      return "HTTPS";
        case AppType::DNS:        return "DNS";
        case AppType::TLS:        return "TLS";
        case AppType::QUIC:       return "QUIC";
        case AppType::GOOGLE:     return "Google";
        case AppType::FACEBOOK:   return "Facebook";
        case AppType::YOUTUBE:    return "YouTube";
        case AppType::TWITTER:    return "Twitter/X";
        case AppType::INSTAGRAM:  return "Instagram";
        case AppType::NETFLIX:    return "Netflix";
        case AppType::AMAZON:     return "Amazon";
        case AppType::MICROSOFT:  return "Microsoft";
        case AppType::APPLE:      return "Apple";
        case AppType::WHATSAPP:   return "WhatsApp";
        case AppType::TELEGRAM:   return "Telegram";
        case AppType::TIKTOK:     return "TikTok";
        case AppType::SPOTIFY:    return "Spotify";
        case AppType::ZOOM:       return "Zoom";
        case AppType::DISCORD:    return "Discord";
        case AppType::GITHUB:     return "GitHub";
        case AppType::CLOUDFLARE: return "Cloudflare";
        default:                  return "Unknown";
    }
}

// ============================================================================
// sniToAppType (unchanged from Phase 1 — domain-boundary safe)
// ============================================================================
AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;
    const std::string h = normalizeDomain(sni);
    if (h.empty()) return AppType::UNKNOWN;

    if (isDomainOrSubdomain(h, "youtube.com") ||
        isDomainOrSubdomain(h, "ytimg.com")   ||
        isDomainOrSubdomain(h, "youtu.be")    ||
        isDomainOrSubdomain(h, "yt3.ggpht.com")) return AppType::YOUTUBE;

    if (isDomainOrSubdomain(h, "instagram.com") ||
        isDomainOrSubdomain(h, "cdninstagram.com")) return AppType::INSTAGRAM;

    if (isDomainOrSubdomain(h, "whatsapp.com") ||
        isDomainOrSubdomain(h, "whatsapp.net") ||
        isDomainOrSubdomain(h, "wa.me")) return AppType::WHATSAPP;

    if (isDomainOrSubdomain(h, "facebook.com") ||
        isDomainOrSubdomain(h, "fbcdn.net")    ||
        isDomainOrSubdomain(h, "fb.com")       ||
        isDomainOrSubdomain(h, "fbsbx.com")    ||
        isDomainOrSubdomain(h, "meta.com")) return AppType::FACEBOOK;

    if (isDomainOrSubdomain(h, "google.com")     ||
        isDomainOrSubdomain(h, "googleapis.com") ||
        isDomainOrSubdomain(h, "gstatic.com")    ||
        isDomainOrSubdomain(h, "ggpht.com")      ||
        isDomainOrSubdomain(h, "gvt1.com")       ||
        isDomainOrSubdomain(h, "googleusercontent.com")) return AppType::GOOGLE;

    if (isDomainOrSubdomain(h, "twitter.com") ||
        isDomainOrSubdomain(h, "twimg.com")   ||
        isDomainOrSubdomain(h, "x.com")       ||
        isDomainOrSubdomain(h, "t.co")) return AppType::TWITTER;

    if (isDomainOrSubdomain(h, "netflix.com")  ||
        isDomainOrSubdomain(h, "nflxvideo.net") ||
        isDomainOrSubdomain(h, "nflximg.net")) return AppType::NETFLIX;

    if (isDomainOrSubdomain(h, "amazon.com")    ||
        isDomainOrSubdomain(h, "amazon.co.uk")  ||
        isDomainOrSubdomain(h, "amazon.de")     ||
        isDomainOrSubdomain(h, "amazonaws.com") ||
        isDomainOrSubdomain(h, "cloudfront.net")||
        isDomainOrSubdomain(h, "aws.amazon.com")) return AppType::AMAZON;

    if (isDomainOrSubdomain(h, "microsoft.com")     ||
        isDomainOrSubdomain(h, "msn.com")           ||
        isDomainOrSubdomain(h, "live.com")           ||
        isDomainOrSubdomain(h, "outlook.com")        ||
        isDomainOrSubdomain(h, "office.com")         ||
        isDomainOrSubdomain(h, "office365.com")      ||
        isDomainOrSubdomain(h, "azure.com")          ||
        isDomainOrSubdomain(h, "bing.com")           ||
        isDomainOrSubdomain(h, "windows.com")        ||
        isDomainOrSubdomain(h, "microsoftonline.com")) return AppType::MICROSOFT;

    if (isDomainOrSubdomain(h, "apple.com")    ||
        isDomainOrSubdomain(h, "icloud.com")   ||
        isDomainOrSubdomain(h, "mzstatic.com") ||
        isDomainOrSubdomain(h, "itunes.apple.com")) return AppType::APPLE;

    if (isDomainOrSubdomain(h, "telegram.org") ||
        isDomainOrSubdomain(h, "telegram.me")  ||
        isDomainOrSubdomain(h, "t.me")) return AppType::TELEGRAM;

    if (isDomainOrSubdomain(h, "tiktok.com")     ||
        isDomainOrSubdomain(h, "tiktokcdn.com")  ||
        isDomainOrSubdomain(h, "musical.ly")     ||
        isDomainOrSubdomain(h, "bytedance.com")) return AppType::TIKTOK;

    if (isDomainOrSubdomain(h, "spotify.com") ||
        isDomainOrSubdomain(h, "scdn.co")) return AppType::SPOTIFY;

    if (isDomainOrSubdomain(h, "zoom.us")  ||
        isDomainOrSubdomain(h, "zoom.com") ||
        isDomainOrSubdomain(h, "zoomgov.com")) return AppType::ZOOM;

    if (isDomainOrSubdomain(h, "discord.com") ||
        isDomainOrSubdomain(h, "discord.gg")  ||
        isDomainOrSubdomain(h, "discordapp.com")) return AppType::DISCORD;

    if (isDomainOrSubdomain(h, "github.com")           ||
        isDomainOrSubdomain(h, "githubusercontent.com") ||
        isDomainOrSubdomain(h, "github.io")) return AppType::GITHUB;

    if (isDomainOrSubdomain(h, "cloudflare.com") ||
        isDomainOrSubdomain(h, "cloudflare.net") ||
        isDomainOrSubdomain(h, "1.1.1.1")        ||
        isDomainOrSubdomain(h, "workers.dev")    ||
        isDomainOrSubdomain(h, "pages.dev")) return AppType::CLOUDFLARE;

    return AppType::HTTPS;
}

} // namespace DPI
