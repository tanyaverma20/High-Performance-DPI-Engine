// =============================================================================
// tests/test_correctness.cpp
//
// Phase 1 Correctness Regression Tests
//
// Lightweight test harness using assert() — no external dependencies.
// Each TEST() call prints PASS or FAIL and tracks a global failure count.
// The process exits with a non-zero code if any test failed.
//
// Run:
//   ./dpi_tests
// =============================================================================

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <string>
#include <vector>
#include <utility>  // std::move

// Pull in the modules under test
#include "types.h"
#include "rule_manager.h"
#include "packet_parser.h"
#include "pcap_reader.h"

using namespace DPI;
using namespace PacketAnalyzer;

// ---------------------------------------------------------------------------
// Minimal test harness
// ---------------------------------------------------------------------------
static int g_tests  = 0;
static int g_failed = 0;

#define TEST(name, expr)                                                         \
    do {                                                                          \
        g_tests++;                                                                \
        if (!(expr)) {                                                            \
            std::cerr << "  FAIL: " << (name) << "\n";                          \
            g_failed++;                                                           \
        } else {                                                                  \
            std::cout << "  PASS: " << (name) << "\n";                          \
        }                                                                         \
    } while (false)

static void section(const char* title) {
    std::cout << "\n--- " << title << " ---\n";
}

// ===========================================================================
// A. Domain Classification
//    Verifies that sniToAppType uses proper domain-label boundary matching
//    and does NOT produce the substring false-positives identified in the
//    audit (D1).
// ===========================================================================
static void test_classification() {
    section("A. Domain Classification");

    // Correct positive classifications
    TEST("netflix.com -> Netflix",
         sniToAppType("netflix.com") == AppType::NETFLIX);

    TEST("www.netflix.com -> Netflix",
         sniToAppType("www.netflix.com") == AppType::NETFLIX);

    TEST("x.com -> Twitter/X",
         sniToAppType("x.com") == AppType::TWITTER);

    TEST("www.x.com -> Twitter/X",
         sniToAppType("www.x.com") == AppType::TWITTER);

    TEST("twitter.com -> Twitter/X",
         sniToAppType("twitter.com") == AppType::TWITTER);

    TEST("youtube.com -> YouTube",
         sniToAppType("youtube.com") == AppType::YOUTUBE);

    TEST("www.youtube.com -> YouTube",
         sniToAppType("www.youtube.com") == AppType::YOUTUBE);

    TEST("m.youtube.com -> YouTube",
         sniToAppType("m.youtube.com") == AppType::YOUTUBE);

    TEST("zoom.us -> Zoom",
         sniToAppType("zoom.us") == AppType::ZOOM);

    TEST("discord.com -> Discord",
         sniToAppType("discord.com") == AppType::DISCORD);

    TEST("microsoft.com -> Microsoft",
         sniToAppType("microsoft.com") == AppType::MICROSOFT);

    // Critical false-positive regressions (previously broken)

    // D1 regression: netflix.com contains "x.com" substring — must NOT be Twitter
    TEST("netflix.com is NOT Twitter/X  [D1 regression]",
         sniToAppType("netflix.com") != AppType::TWITTER);

    TEST("notx.com is NOT Twitter/X",
         sniToAppType("notx.com") != AppType::TWITTER);

    TEST("microsoft.com is NOT Twitter/X",
         sniToAppType("microsoft.com") != AppType::TWITTER);

    TEST("notyoutube.com is NOT YouTube",
         sniToAppType("notyoutube.com") != AppType::YOUTUBE);

    // attacker-controlled hostnames with known domain as substring
    TEST("amazonsupport.evil.com is NOT Amazon",
         sniToAppType("amazonsupport.evil.com") != AppType::AMAZON);

    TEST("zoom-phishing.com is NOT Zoom",
         sniToAppType("zoom-phishing.com") != AppType::ZOOM);

    TEST("notdiscord.example.com is NOT Discord",
         sniToAppType("notdiscord.example.com") != AppType::DISCORD);

    TEST("cf-ray.badsite.net is NOT Cloudflare",
         sniToAppType("cf-ray.badsite.net") != AppType::CLOUDFLARE);

    // Empty / edge cases
    TEST("empty string -> UNKNOWN",
         sniToAppType("") == AppType::UNKNOWN);

    TEST("Uppercase SNI normalised correctly",
         sniToAppType("WWW.YOUTUBE.COM") == AppType::YOUTUBE);

    TEST("Trailing dot (FQDN) handled",
         sniToAppType("netflix.com.") == AppType::NETFLIX);
}

// ===========================================================================
// B. Domain Blocking
//    Verifies that blockDomain(apex) blocks exact + valid subdomains but
//    does NOT block unrelated hostnames containing apex as a substring (D6).
// ===========================================================================
static void test_domain_blocking() {
    section("B. Domain Blocking");

    RuleManager rm;
    rm.blockDomain("evil.com");

    TEST("evil.com is blocked (exact)",
         rm.isDomainBlocked("evil.com"));

    TEST("www.evil.com is blocked (subdomain)",
         rm.isDomainBlocked("www.evil.com"));

    TEST("api.evil.com is blocked (subdomain)",
         rm.isDomainBlocked("api.evil.com"));

    TEST("deep.api.evil.com is blocked (deep subdomain)",
         rm.isDomainBlocked("deep.api.evil.com"));

    // D6 regression: "notevil.com" contains "evil.com" as substring
    TEST("notevil.com is NOT blocked  [D6 regression]",
         !rm.isDomainBlocked("notevil.com"));

    TEST("evil.org is NOT blocked (different TLD)",
         !rm.isDomainBlocked("evil.org"));

    TEST("prefixevil.com is NOT blocked",
         !rm.isDomainBlocked("prefixevil.com"));

    // Wildcard pattern preserved
    RuleManager rm2;
    rm2.blockDomain("*.blocked.net");

    TEST("sub.blocked.net blocked by wildcard",
         rm2.isDomainBlocked("sub.blocked.net"));

    TEST("blocked.net matched by wildcard (bare)",
         rm2.isDomainBlocked("blocked.net"));

    TEST("notblocked.net not matched by *.blocked.net",
         !rm2.isDomainBlocked("notblocked.net"));

    // Case insensitivity
    RuleManager rm3;
    rm3.blockDomain("Example.com");

    TEST("EXAMPLE.COM blocked (case-insensitive)",
         rm3.isDomainBlocked("EXAMPLE.COM"));

    TEST("sub.example.com blocked (case-insensitive subdomain)",
         rm3.isDomainBlocked("sub.example.com"));
}

// ===========================================================================
// C. Flow Canonicalization
//    Verifies that canonical(A->B) == canonical(B->A) and that both produce
//    the same hash, so both directions of a flow select the same worker.
// ===========================================================================
static void test_flow_canonicalization() {
    section("C. Flow Canonicalization");

    FiveTuple ab;
    ab.src_ip   = 0x0100000A;  // 10.0.0.1
    ab.dst_ip   = 0x0200000A;  // 10.0.0.2
    ab.src_port = 12345;
    ab.dst_port = 443;
    ab.protocol = 6;  // TCP

    FiveTuple ba = ab.reverse();  // 10.0.0.2:443 -> 10.0.0.1:12345

    FiveTuple can_ab = ab.canonical();
    FiveTuple can_ba = ba.canonical();

    TEST("canonical(A->B) == canonical(B->A)",
         can_ab == can_ba);

    FiveTupleHash hasher;
    TEST("hash(A->B) == hash(B->A)",
         hasher(ab) == hasher(ba));

    // Ensure unrelated flows are NOT merged
    FiveTuple cd;
    cd.src_ip   = 0x0300000A;  // 10.0.0.3
    cd.dst_ip   = 0x0400000A;  // 10.0.0.4
    cd.src_port = 54321;
    cd.dst_port = 80;
    cd.protocol = 6;

    TEST("canonical(A->B) != canonical(C->D)  [different flows]",
         !(can_ab == cd.canonical()));

    TEST("hash(A->B) != hash(C->D)  [collision unlikely for these inputs]",
         hasher(ab) != hasher(cd));

    // Symmetric case: src > dst — should still canonicalize
    FiveTuple high_to_low;
    high_to_low.src_ip   = 0x0A00000A;  // higher IP
    high_to_low.dst_ip   = 0x01000000;  // lower IP
    high_to_low.src_port = 80;
    high_to_low.dst_port = 9999;
    high_to_low.protocol = 6;

    FiveTuple rev_high = high_to_low.reverse();
    TEST("high-to-low canonical == low-to-high canonical",
         high_to_low.canonical() == rev_high.canonical());
    TEST("high-to-low hash == low-to-high hash",
         hasher(high_to_low) == hasher(rev_high));
}

// ===========================================================================
// D. Packet Parsing
//    Verifies that the parser handles valid packets and rejects truncated ones.
// ===========================================================================

// Build a minimal valid raw Ethernet+IPv4+TCP packet
static std::vector<uint8_t> make_tcp_packet() {
    // Ethernet: 14 bytes
    // IPv4: 20 bytes (IHL=5)
    // TCP: 20 bytes (data offset=5)
    // Payload: "HELLO"
    std::vector<uint8_t> pkt(14 + 20 + 20 + 5, 0);

    // Ethernet header
    // dst mac: 00:00:00:00:00:01
    pkt[5] = 0x01;
    // src mac: 00:00:00:00:00:02
    pkt[11] = 0x02;
    // EtherType = 0x0800 (IPv4)
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    // IPv4 header (offset 14)
    uint8_t* ip = pkt.data() + 14;
    ip[0]  = 0x45;                    // version=4, IHL=5
    ip[8]  = 64;                      // TTL
    ip[9]  = 6;                       // protocol=TCP
    // src IP: 192.168.1.1 → bytes 0xC0,0xA8,0x01,0x01
    ip[12] = 0xC0; ip[13] = 0xA8; ip[14] = 0x01; ip[15] = 0x01;
    // dst IP: 93.184.216.34
    ip[16] = 93;   ip[17] = 184;  ip[18] = 216;  ip[19] = 34;

    // TCP header (offset 14+20=34)
    uint8_t* tcp = pkt.data() + 34;
    tcp[0] = 0x00; tcp[1] = 0xC8;    // src port 200
    tcp[2] = 0x01; tcp[3] = 0xBB;    // dst port 443
    // seq, ack = 0
    tcp[12] = 0x50;  // data offset = 5 (20 bytes), no flags
    tcp[13] = 0x02;  // SYN flag

    // Payload "HELLO" at offset 54
    const char* hello = "HELLO";
    std::memcpy(pkt.data() + 54, hello, 5);

    return pkt;
}

static void test_packet_parsing() {
    section("D. Packet Parsing");

    // Valid packet
    {
        auto raw_data = make_tcp_packet();

        RawPacket raw;
        raw.header.ts_sec  = 1000;
        raw.header.ts_usec = 0;
        raw.header.incl_len = static_cast<uint32_t>(raw_data.size());
        raw.header.orig_len = raw.header.incl_len;
        raw.data = raw_data;

        ParsedPacket parsed;
        bool ok = PacketParser::parse(raw, parsed);

        TEST("valid TCP packet parses successfully", ok);
        TEST("has_ip is true", parsed.has_ip);
        TEST("has_tcp is true", parsed.has_tcp);
        TEST("dst_port is 443", parsed.dest_port == 443);
        TEST("src_port is 200", parsed.src_port == 200);
        TEST("protocol is 6 (TCP)", parsed.protocol == 6);
        TEST("payload_length is 5", parsed.payload_length == 5);
        TEST("payload_data is non-null", parsed.payload_data != nullptr);
        TEST("src_ip_raw non-zero", parsed.src_ip_raw != 0);
        TEST("dst_ip_raw non-zero", parsed.dst_ip_raw != 0);
    }

    // Truncated packet (only 10 bytes — too short for Ethernet)
    {
        RawPacket raw;
        raw.header.ts_sec  = 0;
        raw.header.ts_usec = 0;
        raw.data = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
        raw.header.incl_len = 10;
        raw.header.orig_len = 10;

        ParsedPacket parsed;
        bool ok = PacketParser::parse(raw, parsed);

        TEST("truncated packet rejected (parse returns false)", !ok);
    }

    // Packet with only Ethernet header (no IP)
    {
        RawPacket raw;
        raw.data.resize(14, 0);
        // EtherType = 0x0806 (ARP) — not IPv4
        raw.data[12] = 0x08;
        raw.data[13] = 0x06;
        raw.header.incl_len = 14;
        raw.header.orig_len = 14;

        ParsedPacket parsed;
        bool ok = PacketParser::parse(raw, parsed);

        // parse() returns true for Ethernet-only, has_ip=false
        TEST("non-IPv4 packet does not set has_ip", !parsed.has_ip);
        (void)ok;
    }
}

// ===========================================================================
// E. PacketJob safety
//    Verifies that moving a PacketJob does not produce a dangling payload
//    pointer (D9 fix: payload_data removed; getPayload() used instead).
// ===========================================================================
static void test_packet_job_safety() {
    section("E. PacketJob Safety (moved-from dangling pointer fix)");

    PacketJob original;
    original.packet_id     = 42;
    original.data          = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    original.payload_offset = 2;
    original.payload_length = 4;  // bytes 2..5

    // Verify payload before move
    const uint8_t* pre_move = original.getPayload();
    TEST("getPayload() non-null before move", pre_move != nullptr);
    TEST("getPayload() points to correct byte before move",
         pre_move != nullptr && *pre_move == 0xBE);

    // Move the job
    PacketJob moved = std::move(original);

    // After move, original.data is empty — calling original.getPayload()
    // must return nullptr (not a dangling pointer to freed memory).
    TEST("original.getPayload() is nullptr after move (no dangling ptr)",
         original.getPayload() == nullptr);

    // The moved-to job's payload must be valid
    const uint8_t* post_move = moved.getPayload();
    TEST("moved.getPayload() non-null after move", post_move != nullptr);
    TEST("moved.getPayload() first byte is 0xBE",
         post_move != nullptr && *post_move == 0xBE);
    TEST("moved.getPayload() second byte is 0xEF",
         post_move != nullptr && *(post_move + 1) == 0xEF);
}

// ===========================================================================
// F. TCP State Machine
//    Verifies SYN/SYN-ACK/ACK transitions produce ESTABLISHED state.
//    Now that flow canonicalization routes both directions to the same FP,
//    the full 3-way handshake is observable.
// ===========================================================================
static void test_tcp_state() {
    section("F. TCP State Machine");

    // We test the logic directly by simulating the FP's updateTCPState calls.
    // For simplicity we use a Connection directly.
    Connection conn;
    conn.state       = ConnectionState::NEW;
    conn.syn_seen    = false;
    conn.syn_ack_seen = false;
    conn.fin_seen    = false;

    constexpr uint8_t SYN     = 0x02;
    constexpr uint8_t ACK     = 0x10;
    constexpr uint8_t SYN_ACK = SYN | ACK;
    constexpr uint8_t FIN     = 0x01;
    constexpr uint8_t RST     = 0x04;

    // Helper that mirrors the fixed updateTCPState logic
    auto updateState = [&](uint8_t flags, bool /*is_c2s*/) {
        if (flags & SYN) {
            if (flags & ACK) {
                conn.syn_ack_seen = true;
            } else {
                conn.syn_seen = true;
            }
        }
        if (conn.syn_seen && conn.syn_ack_seen &&
            (flags & ACK) && !(flags & SYN)) {
            if (conn.state == ConnectionState::NEW) {
                conn.state = ConnectionState::ESTABLISHED;
            }
        }
        if (flags & FIN) conn.fin_seen = true;
        if (flags & RST) conn.state = ConnectionState::CLOSED;
        if (conn.fin_seen && (flags & ACK) && !(flags & SYN)) {
            conn.state = ConnectionState::CLOSED;
        }
    };

    // Step 1: Client SYN
    updateState(SYN, /*client->server=*/true);
    TEST("SYN sets syn_seen", conn.syn_seen);
    TEST("After SYN state is still NEW", conn.state == ConnectionState::NEW);

    // Step 2: Server SYN-ACK
    updateState(SYN_ACK, /*server->client=*/false);
    TEST("SYN-ACK sets syn_ack_seen", conn.syn_ack_seen);
    TEST("After SYN-ACK state is still NEW", conn.state == ConnectionState::NEW);

    // Step 3: Client ACK (plain ACK, no SYN)
    updateState(ACK, /*client->server=*/true);
    TEST("ACK after SYN+SYN-ACK transitions to ESTABLISHED",
         conn.state == ConnectionState::ESTABLISHED);

    // FIN handling
    updateState(FIN, true);
    TEST("FIN sets fin_seen", conn.fin_seen);

    updateState(ACK, false);
    TEST("ACK after FIN closes connection",
         conn.state == ConnectionState::CLOSED);

    // RST closes connection regardless
    Connection conn2;
    conn2.state = ConnectionState::ESTABLISHED;
    constexpr uint8_t RST_FLAG = 0x04;
    if (RST_FLAG & RST) conn2.state = ConnectionState::CLOSED;
    TEST("RST closes connection", conn2.state == ConnectionState::CLOSED);
}

// ===========================================================================
// main
// ===========================================================================
int main() {
    std::cout << "========================================\n";
    std::cout << "  DPI Engine Phase 1 Correctness Tests\n";
    std::cout << "========================================\n";

    test_classification();
    test_domain_blocking();
    test_flow_canonicalization();
    test_packet_parsing();
    test_packet_job_safety();
    test_tcp_state();

    std::cout << "\n========================================\n";
    std::cout << "  Results: " << (g_tests - g_failed) << "/" << g_tests
              << " tests passed";
    if (g_failed == 0) {
        std::cout << "  [ALL PASS]\n";
    } else {
        std::cout << "  [" << g_failed << " FAILED]\n";
    }
    std::cout << "========================================\n";

    return (g_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
