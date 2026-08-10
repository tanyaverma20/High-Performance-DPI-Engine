#include "types.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace DPI {

std::string FiveTuple::toString() const {
    std::ostringstream ss;

    // Format IP addresses (same byte order as stored)
    auto formatIP = [](uint32_t ip) {
        std::ostringstream s;
        s << ((ip >> 0) & 0xFF) << "."
          << ((ip >> 8) & 0xFF) << "."
          << ((ip >> 16) & 0xFF) << "."
          << ((ip >> 24) & 0xFF);
        return s.str();
    };

    ss << formatIP(src_ip) << ":" << src_port
       << " -> "
       << formatIP(dst_ip) << ":" << dst_port
       << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") << ")";

    return ss.str();
}

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
// Domain matching helpers
// ============================================================================

// Lowercase a string once, removing a trailing dot if present (FQDN form).
// Empty input returns empty string — no UB.
static std::string normalizeDomain(const std::string& s) {
    if (s.empty()) return {};

    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        out.push_back(static_cast<char>(std::tolower(c)));
    }

    // Strip trailing dot (FQDN notation: "example.com." → "example.com")
    if (!out.empty() && out.back() == '.') {
        out.pop_back();
    }
    return out;
}

// ---------------------------------------------------------------------------
// isDomainOrSubdomain(host, apex)
//
// Returns true iff `host` is exactly `apex` OR is a valid subdomain of `apex`.
//
// A valid subdomain must have a dot boundary directly before the apex suffix:
//   host == "example.com"          apex == "example.com"  → true  (exact)
//   host == "www.example.com"      apex == "example.com"  → true  (subdomain)
//   host == "api.v2.example.com"   apex == "example.com"  → true  (deep subdomain)
//   host == "notexample.com"       apex == "example.com"  → false (different TLD)
//   host == "prefixexample.com"    apex == "example.com"  → false (no dot boundary)
//
// Both `host` and `apex` must already be lowercase and without trailing dots.
// ---------------------------------------------------------------------------
static bool isDomainOrSubdomain(const std::string& host, const std::string& apex) {
    if (host.empty() || apex.empty()) return false;

    // Exact match
    if (host == apex) return true;

    // Subdomain: host must end with "." + apex
    if (host.size() <= apex.size()) return false;  // host too short to be subdomain

    size_t dot_pos = host.size() - apex.size() - 1;
    return host[dot_pos] == '.' &&
           host.compare(dot_pos + 1, apex.size(), apex) == 0;
}

// ============================================================================
// sniToAppType — Map SNI/domain to application type
//
// Fix (D1): The original implementation used std::string::find() for all
// checks, which performs unanchored substring matching.  This caused e.g.
// "netflix.com" to be classified as Twitter/X (because it contains the
// substring "x.com") and allowed spoofed hostnames like
// "amazonsupport.evil.com" to be classified as Amazon.
//
// This implementation uses isDomainOrSubdomain() which requires a dot-label
// boundary, preventing all such false positives.
// ============================================================================
AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;

    // Normalize once — lowercase + strip trailing dot
    const std::string h = normalizeDomain(sni);
    if (h.empty()) return AppType::UNKNOWN;

    // -----------------------------------------------------------------------
    // Order matters: more specific checks first to avoid shadow effects.
    // (e.g. YouTube before Google, Instagram/WhatsApp before Facebook)
    // -----------------------------------------------------------------------

    // YouTube (check before Google — youtube.com is not google.com)
    if (isDomainOrSubdomain(h, "youtube.com") ||
        isDomainOrSubdomain(h, "ytimg.com")   ||
        isDomainOrSubdomain(h, "youtu.be")    ||
        isDomainOrSubdomain(h, "yt3.ggpht.com")) {
        return AppType::YOUTUBE;
    }

    // Instagram (check before Facebook)
    if (isDomainOrSubdomain(h, "instagram.com") ||
        isDomainOrSubdomain(h, "cdninstagram.com")) {
        return AppType::INSTAGRAM;
    }

    // WhatsApp (check before Facebook)
    if (isDomainOrSubdomain(h, "whatsapp.com") ||
        isDomainOrSubdomain(h, "whatsapp.net") ||
        isDomainOrSubdomain(h, "wa.me")) {
        return AppType::WHATSAPP;
    }

    // Facebook / Meta
    if (isDomainOrSubdomain(h, "facebook.com") ||
        isDomainOrSubdomain(h, "fbcdn.net")    ||
        isDomainOrSubdomain(h, "fb.com")       ||
        isDomainOrSubdomain(h, "fbsbx.com")    ||
        isDomainOrSubdomain(h, "meta.com")) {
        return AppType::FACEBOOK;
    }

    // Google (broad — after YouTube, Instagram, WhatsApp, Facebook)
    if (isDomainOrSubdomain(h, "google.com")      ||
        isDomainOrSubdomain(h, "googleapis.com")  ||
        isDomainOrSubdomain(h, "gstatic.com")     ||
        isDomainOrSubdomain(h, "ggpht.com")       ||
        isDomainOrSubdomain(h, "gvt1.com")        ||
        isDomainOrSubdomain(h, "googleusercontent.com")) {
        return AppType::GOOGLE;
    }

    // Twitter / X
    // NOTE: "x.com" must be matched as a full domain apex, not substring.
    // Previously `find("x.com")` matched "netflix.com" — this is now fixed.
    if (isDomainOrSubdomain(h, "twitter.com") ||
        isDomainOrSubdomain(h, "twimg.com")   ||
        isDomainOrSubdomain(h, "x.com")       ||
        isDomainOrSubdomain(h, "t.co")) {
        return AppType::TWITTER;
    }

    // Netflix
    if (isDomainOrSubdomain(h, "netflix.com")  ||
        isDomainOrSubdomain(h, "nflxvideo.net") ||
        isDomainOrSubdomain(h, "nflximg.net")) {
        return AppType::NETFLIX;
    }

    // Amazon / AWS
    // NOTE: "amazon" as substring would match "amazonsupport.evil.com".
    // We only match known Amazon apex domains.
    if (isDomainOrSubdomain(h, "amazon.com")    ||
        isDomainOrSubdomain(h, "amazon.co.uk")  ||
        isDomainOrSubdomain(h, "amazon.de")     ||
        isDomainOrSubdomain(h, "amazonaws.com") ||
        isDomainOrSubdomain(h, "cloudfront.net")||
        isDomainOrSubdomain(h, "aws.amazon.com")) {
        return AppType::AMAZON;
    }

    // Microsoft
    if (isDomainOrSubdomain(h, "microsoft.com") ||
        isDomainOrSubdomain(h, "msn.com")       ||
        isDomainOrSubdomain(h, "live.com")       ||
        isDomainOrSubdomain(h, "outlook.com")    ||
        isDomainOrSubdomain(h, "office.com")     ||
        isDomainOrSubdomain(h, "office365.com")  ||
        isDomainOrSubdomain(h, "azure.com")      ||
        isDomainOrSubdomain(h, "bing.com")       ||
        isDomainOrSubdomain(h, "windows.com")    ||
        isDomainOrSubdomain(h, "microsoftonline.com")) {
        return AppType::MICROSOFT;
    }

    // Apple
    if (isDomainOrSubdomain(h, "apple.com")    ||
        isDomainOrSubdomain(h, "icloud.com")   ||
        isDomainOrSubdomain(h, "mzstatic.com") ||
        isDomainOrSubdomain(h, "itunes.apple.com")) {
        return AppType::APPLE;
    }

    // Telegram
    if (isDomainOrSubdomain(h, "telegram.org") ||
        isDomainOrSubdomain(h, "telegram.me")  ||
        isDomainOrSubdomain(h, "t.me")) {
        return AppType::TELEGRAM;
    }

    // TikTok / ByteDance
    if (isDomainOrSubdomain(h, "tiktok.com")     ||
        isDomainOrSubdomain(h, "tiktokcdn.com")  ||
        isDomainOrSubdomain(h, "musical.ly")     ||
        isDomainOrSubdomain(h, "bytedance.com")) {
        return AppType::TIKTOK;
    }

    // Spotify
    if (isDomainOrSubdomain(h, "spotify.com") ||
        isDomainOrSubdomain(h, "scdn.co")) {
        return AppType::SPOTIFY;
    }

    // Zoom
    // NOTE: "zoom" as substring would match "zoom-phishing.com".
    // Only match the known Zoom apex domains.
    if (isDomainOrSubdomain(h, "zoom.us")  ||
        isDomainOrSubdomain(h, "zoom.com") ||
        isDomainOrSubdomain(h, "zoomgov.com")) {
        return AppType::ZOOM;
    }

    // Discord
    if (isDomainOrSubdomain(h, "discord.com") ||
        isDomainOrSubdomain(h, "discord.gg")  ||
        isDomainOrSubdomain(h, "discordapp.com")) {
        return AppType::DISCORD;
    }

    // GitHub
    if (isDomainOrSubdomain(h, "github.com")          ||
        isDomainOrSubdomain(h, "githubusercontent.com") ||
        isDomainOrSubdomain(h, "github.io")) {
        return AppType::GITHUB;
    }

    // Cloudflare
    // NOTE: "cf-" as substring was wildly over-broad. Match only known Cloudflare domains.
    if (isDomainOrSubdomain(h, "cloudflare.com") ||
        isDomainOrSubdomain(h, "cloudflare.net") ||
        isDomainOrSubdomain(h, "1.1.1.1") ||        // CF DNS (rare as SNI)
        isDomainOrSubdomain(h, "workers.dev")    ||
        isDomainOrSubdomain(h, "pages.dev")) {
        return AppType::CLOUDFLARE;
    }

    // SNI present but not recognized → classify as generic HTTPS
    return AppType::HTTPS;
}

} // namespace DPI
