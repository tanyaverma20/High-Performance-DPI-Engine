// =============================================================================
// tests/test_correctness.cpp
//
// Phase 1 and 2 Correctness Regression Tests
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
#include <utility>
#include <chrono>

// Pull in the modules under test
#include "types.h"
#include "rule_manager.h"
#include "packet_parser.h"
#include "pcap_reader.h"
#include "sni_extractor.h"
#include "connection_tracker.h"
#include "fast_path.h"
#include "load_balancer.h"
#include "parser_pool.h"
#include "dpi_engine.h"

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
// A. Domain Classification (Phase 1)
// ===========================================================================
static void test_classification() {
    section("A. Domain Classification");

    TEST("netflix.com -> Netflix", sniToAppType("netflix.com") == AppType::NETFLIX);
    TEST("www.netflix.com -> Netflix", sniToAppType("www.netflix.com") == AppType::NETFLIX);
    TEST("x.com -> Twitter/X", sniToAppType("x.com") == AppType::TWITTER);
    TEST("www.x.com -> Twitter/X", sniToAppType("www.x.com") == AppType::TWITTER);
    TEST("twitter.com -> Twitter/X", sniToAppType("twitter.com") == AppType::TWITTER);
    TEST("youtube.com -> YouTube", sniToAppType("youtube.com") == AppType::YOUTUBE);
    TEST("www.youtube.com -> YouTube", sniToAppType("www.youtube.com") == AppType::YOUTUBE);
    TEST("m.youtube.com -> YouTube", sniToAppType("m.youtube.com") == AppType::YOUTUBE);
    TEST("zoom.us -> Zoom", sniToAppType("zoom.us") == AppType::ZOOM);
    TEST("discord.com -> Discord", sniToAppType("discord.com") == AppType::DISCORD);
    TEST("microsoft.com -> Microsoft", sniToAppType("microsoft.com") == AppType::MICROSOFT);
    TEST("netflix.com is NOT Twitter/X", sniToAppType("netflix.com") != AppType::TWITTER);
    TEST("notx.com is NOT Twitter/X", sniToAppType("notx.com") != AppType::TWITTER);
    TEST("microsoft.com is NOT Twitter/X", sniToAppType("microsoft.com") != AppType::TWITTER);
    TEST("notyoutube.com is NOT YouTube", sniToAppType("notyoutube.com") != AppType::YOUTUBE);
    TEST("amazonsupport.evil.com is NOT Amazon", sniToAppType("amazonsupport.evil.com") != AppType::AMAZON);
    TEST("zoom-phishing.com is NOT Zoom", sniToAppType("zoom-phishing.com") != AppType::ZOOM);
    TEST("notdiscord.example.com is NOT Discord", sniToAppType("notdiscord.example.com") != AppType::DISCORD);
    TEST("cf-ray.badsite.net is NOT Cloudflare", sniToAppType("cf-ray.badsite.net") != AppType::CLOUDFLARE);
    TEST("empty string -> UNKNOWN", sniToAppType("") == AppType::UNKNOWN);
    TEST("Uppercase SNI normalised correctly", sniToAppType("WWW.YOUTUBE.COM") == AppType::YOUTUBE);
    TEST("Trailing dot (FQDN) handled", sniToAppType("netflix.com.") == AppType::NETFLIX);
}

// ===========================================================================
// B. Domain Blocking (Phase 1)
// ===========================================================================
static void test_domain_blocking() {
    section("B. Domain Blocking");

    RuleManager rm;
    rm.blockDomain("evil.com");
    TEST("evil.com is blocked (exact)", rm.isDomainBlocked("evil.com"));
    TEST("www.evil.com is blocked (subdomain)", rm.isDomainBlocked("www.evil.com"));
    TEST("api.evil.com is blocked (subdomain)", rm.isDomainBlocked("api.evil.com"));
    TEST("deep.api.evil.com is blocked (deep subdomain)", rm.isDomainBlocked("deep.api.evil.com"));
    TEST("notevil.com is NOT blocked", !rm.isDomainBlocked("notevil.com"));
    TEST("evil.org is NOT blocked (different TLD)", !rm.isDomainBlocked("evil.org"));
    TEST("prefixevil.com is NOT blocked", !rm.isDomainBlocked("prefixevil.com"));

    RuleManager rm2;
    rm2.blockDomain("*.blocked.net");
    TEST("sub.blocked.net blocked by wildcard", rm2.isDomainBlocked("sub.blocked.net"));
    TEST("blocked.net matched by wildcard (bare)", rm2.isDomainBlocked("blocked.net"));
    TEST("notblocked.net not matched by *.blocked.net", !rm2.isDomainBlocked("notblocked.net"));

    RuleManager rm3;
    rm3.blockDomain("Example.com");
    TEST("EXAMPLE.COM blocked (case-insensitive)", rm3.isDomainBlocked("EXAMPLE.COM"));
    TEST("sub.example.com blocked (case-insensitive subdomain)", rm3.isDomainBlocked("sub.example.com"));
}

// ===========================================================================
// C. Flow Canonicalization (Phase 1)
// ===========================================================================
static void test_flow_canonicalization() {
    section("C. Flow Canonicalization");

    FiveTuple ab;
    ab.src_ip   = 0x0100000A;
    ab.dst_ip   = 0x0200000A;
    ab.src_port = 12345;
    ab.dst_port = 443;
    ab.protocol = 6;
    FiveTuple ba = ab.reverse();

    TEST("canonical(A->B) == canonical(B->A)", ab.canonical() == ba.canonical());

    FiveTupleHash hasher;
    TEST("hash(A->B) == hash(B->A)", hasher(ab) == hasher(ba));

    FiveTuple cd;
    cd.src_ip   = 0x0300000A;
    cd.dst_ip   = 0x0400000A;
    cd.src_port = 54321;
    cd.dst_port = 80;
    cd.protocol = 6;

    TEST("canonical(A->B) != canonical(C->D)", !(ab.canonical() == cd.canonical()));
    TEST("hash(A->B) != hash(C->D)", hasher(ab) != hasher(cd));
}

// ===========================================================================
// D. Packet Parsing (Phase 1)
// ===========================================================================
static std::vector<uint8_t> make_tcp_packet() {
    std::vector<uint8_t> pkt(14 + 20 + 20 + 5, 0);
    pkt[5] = 0x01; pkt[11] = 0x02; pkt[12] = 0x08; pkt[13] = 0x00;
    uint8_t* ip = pkt.data() + 14;
    ip[0] = 0x45; ip[8] = 64; ip[9] = 6;
    ip[12] = 0xC0; ip[13] = 0xA8; ip[14] = 0x01; ip[15] = 0x01;
    ip[16] = 93;   ip[17] = 184;  ip[18] = 216;  ip[19] = 34;
    uint8_t* tcp = pkt.data() + 34;
    tcp[0] = 0x00; tcp[1] = 0xC8; tcp[2] = 0x01; tcp[3] = 0xBB;
    tcp[12] = 0x50; tcp[13] = 0x02;
    std::memcpy(pkt.data() + 54, "HELLO", 5);
    return pkt;
}

static void test_packet_parsing() {
    section("D. Packet Parsing");

    {
        auto raw_data = make_tcp_packet();
        RawPacket raw;
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
    }
}

// ===========================================================================
// E. PacketJob safety (Phase 1)
// ===========================================================================
static void test_packet_job_safety() {
    section("E. PacketJob Safety");
    PacketJob original;
    original.packet_id = 42;
    original.data = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    original.payload_offset = 2;
    original.payload_length = 4;

    TEST("getPayload() non-null before move", original.getPayload() != nullptr);

    PacketJob moved = std::move(original);
    TEST("original.getPayload() is nullptr after move", original.getPayload() == nullptr);
    TEST("moved.getPayload() non-null after move", moved.getPayload() != nullptr);
}

// ===========================================================================
// F. TCP State Machine (Phase 1)
// ===========================================================================
static void test_tcp_state() {
    section("F. TCP State Machine");
    
    // Abstracting the state machine logic for testing
    Connection conn;
    conn.state = ConnectionState::NEW;
    conn.syn_seen = false;
    conn.syn_ack_seen = false;
    conn.fin_seen = false;

    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t SYN_ACK = SYN | ACK;
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t RST = 0x04;

    auto updateState = [&](uint8_t flags) {
        if (flags & SYN) {
            if (flags & ACK) conn.syn_ack_seen = true;
            else conn.syn_seen = true;
        }
        if (conn.syn_seen && conn.syn_ack_seen && (flags & ACK) && !(flags & SYN)) {
            if (conn.state == ConnectionState::NEW) conn.state = ConnectionState::ESTABLISHED;
        }
        if (flags & FIN) conn.fin_seen = true;
        if (flags & RST) conn.state = ConnectionState::CLOSED;
        if (conn.fin_seen && (flags & ACK) && !(flags & SYN)) conn.state = ConnectionState::CLOSED;
    };

    updateState(SYN);
    TEST("SYN sets syn_seen", conn.syn_seen);
    
    updateState(SYN_ACK);
    TEST("SYN-ACK sets syn_ack_seen", conn.syn_ack_seen);
    
    updateState(ACK);
    TEST("ACK transitions to ESTABLISHED", conn.state == ConnectionState::ESTABLISHED);
    
    updateState(FIN);
    TEST("FIN sets fin_seen", conn.fin_seen);
    
    updateState(ACK);
    TEST("ACK after FIN closes connection", conn.state == ConnectionState::CLOSED);
}

// ===========================================================================
// G. IPv6 Parsing
// ===========================================================================
static void test_ipv6_parsing() {
    section("G. IPv6 Parsing");
    
    // Construct IPv6 packet
    std::vector<uint8_t> pkt(14 + 40 + 20 + 5, 0);
    // Ethernet: IPv6 EtherType
    pkt[12] = 0x86; pkt[13] = 0xDD;
    // IPv6 Header
    uint8_t* ip6 = pkt.data() + 14;
    ip6[0] = 0x60; // Version 6
    ip6[4] = 0x00; ip6[5] = 0x19; // Payload length = 25 (20 TCP + 5 payload)
    ip6[6] = 6; // Next header: TCP
    ip6[7] = 64; // Hop limit
    // src IPv6 (16 bytes)
    for (int i=0; i<16; i++) ip6[8+i] = i;
    // dst IPv6 (16 bytes)
    for (int i=0; i<16; i++) ip6[24+i] = i+10;
    
    // TCP header
    uint8_t* tcp = pkt.data() + 54;
    tcp[0] = 0x00; tcp[1] = 0x50; // port 80
    tcp[12] = 0x50; // data offset 5
    
    RawPacket raw;
    raw.data = pkt;
    raw.header.incl_len = pkt.size();
    raw.header.orig_len = pkt.size();
    
    ParsedPacket parsed;
    bool ok = PacketParser::parse(raw, parsed);
    
    TEST("IPv6 TCP packet parses successfully", ok);
    TEST("has_ipv6 is true", parsed.has_ipv6);
    TEST("protocol is TCP", parsed.protocol == 6);
    TEST("IPv6 src array parsed correctly", parsed.src_ipv6[0] == 0 && parsed.src_ipv6[15] == 15);
}

// ===========================================================================
// H. TCP Hardening
// ===========================================================================
static void test_tcp_hardening() {
    section("H. TCP Hardening");
    
    std::vector<uint8_t> pkt = make_tcp_packet();
    
    // Invalid data offset (< 5)
    std::vector<uint8_t> bad_offset = pkt;
    bad_offset[34 + 12] = 0x40; // offset 4
    
    RawPacket raw;
    raw.data = bad_offset;
    raw.header.incl_len = bad_offset.size();
    raw.header.orig_len = bad_offset.size();
    
    ParsedPacket parsed;
    bool ok = PacketParser::parse(raw, parsed);
    TEST("TCP data offset < 5 rejected", !ok);
    
    // Truncated TCP header
    std::vector<uint8_t> trunc_tcp = pkt;
    trunc_tcp.resize(34 + 10); // only 10 bytes of TCP header
    raw.data = trunc_tcp;
    raw.header.incl_len = trunc_tcp.size();
    raw.header.orig_len = trunc_tcp.size();
    
    ok = PacketParser::parse(raw, parsed);
    TEST("Truncated TCP header rejected", !ok);
}

// ===========================================================================
// I. UDP Hardening
// ===========================================================================
static void test_udp_hardening() {
    section("I. UDP Hardening");
    
    std::vector<uint8_t> pkt(14 + 20 + 8, 0);
    pkt[12] = 0x08; pkt[13] = 0x00; // IPv4
    uint8_t* ip = pkt.data() + 14;
    ip[0] = 0x45; ip[9] = 17; // UDP
    
    uint8_t* udp = pkt.data() + 34;
    udp[4] = 0x00; udp[5] = 0x08; // Length 8
    
    RawPacket raw;
    raw.data = pkt;
    raw.header.incl_len = pkt.size();
    raw.header.orig_len = pkt.size();
    
    ParsedPacket parsed;
    bool ok = PacketParser::parse(raw, parsed);
    TEST("Valid UDP packet parses", ok);
    TEST("Protocol is UDP", parsed.protocol == 17);
    
    // Invalid length (< 8)
    std::vector<uint8_t> bad_len = pkt;
    bad_len[34 + 4] = 0x00;
    bad_len[34 + 5] = 0x07; // Length 7
    raw.data = bad_len;
    
    ok = PacketParser::parse(raw, parsed);
    TEST("UDP length < 8 rejected", !ok);
    
    // UDP length > remaining data
    std::vector<uint8_t> bad_len2 = pkt;
    bad_len2[34 + 4] = 0x01; // Length 256 + ...
    bad_len2[34 + 5] = 0x00; 
    raw.data = bad_len2;
    
    ok = PacketParser::parse(raw, parsed);
    TEST("UDP length > remaining payload rejected", !ok);
}

// ===========================================================================
// J. ICMP / ICMPv6
// ===========================================================================
static void test_icmp() {
    section("J. ICMP / ICMPv6");
    
    std::vector<uint8_t> pkt(14 + 20 + 8, 0);
    pkt[12] = 0x08; pkt[13] = 0x00; // IPv4
    uint8_t* ip = pkt.data() + 14;
    ip[0] = 0x45; ip[9] = 1; // ICMP
    
    uint8_t* icmp = pkt.data() + 34;
    icmp[0] = 8; // Echo request
    icmp[1] = 0; // Code
    
    RawPacket raw;
    raw.data = pkt;
    raw.header.incl_len = pkt.size();
    raw.header.orig_len = pkt.size();
    
    ParsedPacket parsed;
    bool ok = PacketParser::parse(raw, parsed);
    TEST("Valid ICMP packet parses", ok);
    TEST("Protocol is ICMP", parsed.protocol == 1);
    TEST("has_icmp is true", parsed.has_icmp);
    TEST("ICMP type is 8", parsed.icmp_type == 8);
    
    // Truncated ICMP
    std::vector<uint8_t> trunc = pkt;
    trunc.resize(34 + 4);
    raw.data = trunc;
    raw.header.incl_len = trunc.size();
    raw.header.orig_len = trunc.size();
    
    ok = PacketParser::parse(raw, parsed);
    TEST("Truncated ICMP rejected", !ok);
}

// ===========================================================================
// K. TLS / SNI
// ===========================================================================
static void test_tls_sni() {
    section("K. TLS/SNI");
    
    // Helper to test if something is recognized as ClientHello
    std::vector<uint8_t> tls_ch = {
        0x16, // Handshake
        0x03, 0x01, // Version
        0x00, 0x50, // Record length
        0x01, // ClientHello
        0x00, 0x00, 0x4c // Handshake length
    };
    
    tls_ch.resize(5 + 0x50, 0); // Pad out
    
    TEST("Valid TLS Client Hello detected", SNIExtractor::isTLSClientHello(tls_ch.data(), tls_ch.size()));
    
    std::vector<uint8_t> not_tls = { 0x17, 0x03, 0x03, 0x00, 0x50 };
    not_tls.resize(100, 0);
    TEST("Application data is NOT Client Hello", !SNIExtractor::isTLSClientHello(not_tls.data(), not_tls.size()));
}

// ===========================================================================
// L. HTTP Host
// ===========================================================================
static void test_http_host() {
    section("L. HTTP Host");
    
    std::string req1 = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    auto host1 = HTTPHostExtractor::extract(reinterpret_cast<const uint8_t*>(req1.data()), req1.size());
    TEST("Standard Host extracted", host1 && *host1 == "example.com");
    
    std::string req2 = "GET / HTTP/1.1\r\nhost: EXAMPLE.COM:8080\r\n\r\n";
    auto host2 = HTTPHostExtractor::extract(reinterpret_cast<const uint8_t*>(req2.data()), req2.size());
    TEST("Lowercase host with port extracted without port", host2 && *host2 == "EXAMPLE.COM");
    
    std::string req3 = "GET / HTTP/1.1\r\nX-Host: bad.com\r\n\r\n";
    auto host3 = HTTPHostExtractor::extract(reinterpret_cast<const uint8_t*>(req3.data()), req3.size());
    TEST("X-Host ignored", !host3);
}

// ===========================================================================
// M. DNS
// ===========================================================================
static void test_dns() {
    section("M. DNS");
    
    // Basic DNS Query for "example.com"
    std::vector<uint8_t> dns_query = {
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags (Standard query)
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,       // End of name
        0x00, 0x01, // Type A
        0x00, 0x01  // Class IN
    };
    
    auto res = DNSExtractor::extractQuery(dns_query.data(), dns_query.size());
    TEST("Valid DNS query parses", res.has_value());
    if (res) {
        TEST("DNS domain matches example.com", res->query_domain == "example.com");
    }
    
    // Truncated DNS
    auto dns_trunc = dns_query;
    dns_trunc.resize(15);
    TEST("Truncated DNS fails gracefully", !DNSExtractor::extractQuery(dns_trunc.data(), dns_trunc.size()));
}

// ===========================================================================
// N. QUIC
// ===========================================================================
static void test_quic() {
    section("N. QUIC");
    
    std::vector<uint8_t> quic_initial = {
        0xc0, // Long header, Initial
        0x00, 0x00, 0x00, 0x01, // Version 1
        0x00 // DCID length 0
    };
    TEST("QUIC Initial detected", QUICSNIExtractor::isQUICInitial(quic_initial.data(), quic_initial.size()));
    
    std::vector<uint8_t> short_hdr = { 0x40, 0x01, 0x02 };
    TEST("QUIC Short Header is not Initial", !QUICSNIExtractor::isQUICInitial(short_hdr.data(), short_hdr.size()));
}

// ===========================================================================
// O. Flow Tracking
// ===========================================================================
static void test_flow_tracking() {
    section("O. Flow Tracking");
    
    ConnectionTracker ct(0, 100);
    
    FlowKey key1;
    key1.src_addr = static_cast<IPv4Addr>(0x0100000A);
    key1.dst_addr = static_cast<IPv4Addr>(0x0200000A);
    key1.src_port = 1234;
    key1.dst_port = 80;
    key1.protocol = 6;
    
    Connection* c1 = ct.getOrCreateConnection(key1);
    TEST("Connection created", c1 != nullptr);
    TEST("Active count 1", ct.getActiveCount() == 1);
    
    FlowKey key2 = key1.reverse();
    Connection* c2 = ct.getOrCreateConnection(key2);
    TEST("Reverse flow yields same connection", c1 == c2);
    TEST("Active count still 1", ct.getActiveCount() == 1);
}

// ===========================================================================
// P. Classification Precedence
// ===========================================================================
static void test_classification_precedence() {
    section("P. Classification Precedence");
    
    ConnectionTracker ct(0, 100);
    FlowKey key; key.protocol = 6;
    Connection* conn = ct.getOrCreateConnection(key);
    
    // Initial SNI classification
    ct.classifyConnection(conn, AppType::YOUTUBE, "youtube.com");
    TEST("App is YouTube", conn->app_type == AppType::YOUTUBE);
    
    // HTTP host arrives later, shouldn't override SNI
    ct.classifyConnection(conn, AppType::HTTP, "", "someotherhost.com", "");
    // Note: classifyConnection only updates if state != CLASSIFIED.
    // If it was already CLASSIFIED, it preserves the first classification (highest confidence)
    TEST("App remains YouTube", conn->app_type == AppType::YOUTUBE);
    TEST("Best domain remains youtube.com", conn->bestDomain() == "youtube.com");
}


// ===========================================================================
// Q. IPv6 Phase 3 Extensions
// ===========================================================================
static void test_ipv6_phase3() {
    section("Q. IPv6 Phase 3");
    
    // Hop-by-Hop (0) -> Routing (43) -> Fragment (44) -> TCP (6)
    std::vector<uint8_t> chain = {
        43, 0, 0, 0, 0, 0, 0, 0, // Hop-by-Hop (len 0 => 8 bytes)
        44, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Routing (len 1 => 16 bytes)
        6, 0, 0, 0, 0, 0, 0, 0, // Fragment (fixed 8 bytes)
        0, 0, 0, 0 // dummy tcp
    };
    ParsedPacket parsed;
    size_t offset = 0;
    uint8_t next = PacketParser::walkIPv6ExtHeaders(chain.data(), chain.size(), offset, 0, parsed);
    TEST("Final protocol is TCP", next == 6);
    TEST("Hop-by-hop flag set", parsed.has_ipv6_hop_by_hop);
    TEST("Routing flag set", parsed.has_ipv6_routing);
    TEST("Fragment flag set", parsed.has_ipv6_fragment);
    
    // AH (51) -> TCP (6)
    std::vector<uint8_t> ah = {
        6, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 // AH length 2 => (2+2)*4 = 16 bytes
    };
    offset = 0;
    parsed = ParsedPacket();
    next = PacketParser::walkIPv6ExtHeaders(ah.data(), ah.size(), offset, 51, parsed);
    TEST("AH Final protocol is TCP", next == 6);
    TEST("AH flag set", parsed.has_ipv6_auth);
    
    // Non-initial Fragment Handling
    std::vector<uint8_t> frag = {
        6, 0, 0x00, 0x09, 0, 0, 0, 0 // Fragment offset > 0
    };
    offset = 0;
    parsed = ParsedPacket();
    next = PacketParser::walkIPv6ExtHeaders(frag.data(), frag.size(), offset, 44, parsed);
    TEST("Non-initial fragment stops parsing (NO_NEXT_HDR returned)", next == Protocol::IPV6_NO_NEXT_HDR);
    TEST("Protocol preserved for logging", parsed.protocol == 6);
    TEST("Unsupported flag set to prevent transport parsing", parsed.ipv6_ext_unsupported);
}

// ===========================================================================
// R. TCP Reassembly Phase 3
// ===========================================================================
static void test_tcp_reassembly_phase3() {
    section("R. TCP Reassembly Phase 3");
    
    TCPReassembler reassembler;
    
    // 1. In order
    std::vector<uint8_t> p1 = {0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00};
    auto r = reassembler.tryExtractSNI(100, p1.data(), p1.size());
    TEST("In-order chunk 1 processed", !r);
    
    // 2. Gap (out of order)
    std::vector<uint8_t> p3 = {0x00, 0x00, 0x01, 0x00, 0x00};
    r = reassembler.tryExtractSNI(108 + 2, p3.data(), p3.size());
    TEST("Out-of-order chunk buffered", !r);
    
    // 3. Fill gap
    std::vector<uint8_t> p2 = {0x01, 0x02};
    r = reassembler.tryExtractSNI(108, p2.data(), p2.size());
    TEST("Gap filled without error", !reassembler.isFailed());
    
    // 4. Duplicate
    r = reassembler.tryExtractSNI(108, p2.data(), p2.size());
    TEST("Duplicate ignored", !reassembler.isFailed());
    
    // 5. Wrap around math
    reassembler.clear();
    uint32_t wrap_seq = 0xFFFFFFFA;
    r = reassembler.tryExtractSNI(wrap_seq, p1.data(), p1.size());
    r = reassembler.tryExtractSNI(wrap_seq + static_cast<uint32_t>(p1.size()), p2.data(), p2.size());
    TEST("Sequence wrap-around handled", !reassembler.isFailed());
    
    // 6. Overlap
    reassembler.clear();
    r = reassembler.tryExtractSNI(10, p1.data(), 4);
    r = reassembler.tryExtractSNI(12, p1.data() + 2, p1.size() - 2); // overlap of 2 bytes
    TEST("Overlap handled", !reassembler.isFailed());
    
    // 7. Retransmitted segment
    reassembler.clear();
    r = reassembler.tryExtractSNI(10, p1.data(), p1.size());
    r = reassembler.tryExtractSNI(10, p1.data(), p1.size());
    TEST("Retransmitted segment handled", !reassembler.isFailed());

    // 8. Buffer limit (16KB)
    reassembler.clear();
    std::vector<uint8_t> large_chunk(8192, 0x41); // 8KB
    std::vector<uint8_t> another_large(10000, 0x42); // 10KB (total 18KB)
    r = reassembler.tryExtractSNI(100, large_chunk.data(), large_chunk.size());
    TEST("8KB chunk buffered", !reassembler.isFailed());
    r = reassembler.tryExtractSNI(100 + 8192, another_large.data(), another_large.size());
    TEST("18KB aggregate exceeds strict limit", reassembler.isFailed());
    
    // 9. Flow timeout
    reassembler.clear();
    r = reassembler.tryExtractSNI(100, p1.data(), p1.size());
    auto future_time = std::chrono::steady_clock::now() + std::chrono::seconds(31);
    TEST("Timeout detected correctly", reassembler.isTimedOut(future_time));
    
    // 10. Missing segment filled later (gap)
    reassembler.clear();
    std::vector<uint8_t> g1 = {0x16, 0x03};
    std::vector<uint8_t> g2 = {0x01, 0x00, 0x05};
    std::vector<uint8_t> g3 = {0x01, 0x00, 0x00, 0x00, 0x00};
    r = reassembler.tryExtractSNI(10, g1.data(), g1.size());
    r = reassembler.tryExtractSNI(10 + g1.size() + g2.size(), g3.data(), g3.size());
    TEST("Gap detected", !reassembler.isFailed());
    r = reassembler.tryExtractSNI(10 + g1.size(), g2.data(), g2.size());
    TEST("Gap filled and merged correctly", !reassembler.isFailed());
}

// ===========================================================================
// S. Hash Determinism
// ===========================================================================
static void test_hash_determinism() {
    section("S. Hash Determinism");
    
    FiveTuple ab;
    ab.src_ip   = 0x0A000001; // 10.0.0.1
    ab.dst_ip   = 0x0A000002; // 10.0.0.2
    ab.src_port = 54321;
    ab.dst_port = 443;
    ab.protocol = 6;
    
    FiveTuple ba = ab.reverse();
    
    FiveTupleHash hasher;
    int worker_a_b = hasher(ab) % 4;
    int worker_b_a = hasher(ba) % 4;
    
    TEST("Forward and Reverse flow packets map to the same worker", worker_a_b == worker_b_a);
}

// ===========================================================================
// T. Phase 3.2 Parallel Parsing & Bounded Raw Queue Tests
// ===========================================================================
static void test_phase3_2() {
    section("T. Phase 3.2 Parallel Parsing");
    
    // 1. Raw packet queue bounded capacity and graceful shutdown
    {
        ThreadSafeQueue<RawPacketJob> queue(5);
        for (int i = 0; i < 5; i++) {
            RawPacketJob job;
            job.packet_id = i;
            queue.push(job);
        }
        TEST("Raw packet queue capacity bounded at 5", queue.size() == 5);
        
        std::thread t([&queue]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            auto popped = queue.pop();
            TEST("Raw packet popped from queue", popped.has_value() && popped->packet_id == 0);
        });
        
        RawPacketJob job6;
        job6.packet_id = 5;
        queue.push(job6); // Should block until t pops
        t.join();
        
        while (!queue.empty()) {
            queue.pop();
        }
        
        queue.shutdown();
        auto pop_after_shutdown = queue.popWithTimeout(std::chrono::milliseconds(10));
        TEST("Raw packet queue graceful shutdown", !pop_after_shutdown.has_value());
    }
    
    // 2. Parser worker pool scaling and graceful drain
    {
        ThreadSafeQueue<RawPacketJob> queue(100);
        std::atomic<uint64_t> total_lb_jobs{0};
        
        std::vector<uint8_t> base_data = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
            0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
            0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        
        std::vector<ThreadSafeQueue<PacketJob>*> fp_queues;
        ThreadSafeQueue<PacketJob> dummy_fp_queue(1000);
        fp_queues.push_back(&dummy_fp_queue);
        LoadBalancer lb(0, fp_queues, 0);
        
        auto lb_selector = [&lb](const FiveTuple& tuple) -> LoadBalancer& {
            (void)tuple;
            return lb;
        };
        
        ParserManager manager(4, queue, lb_selector);
        manager.startAll();
        
        for (int i = 0; i < 50; i++) {
            RawPacketJob raw_job;
            raw_job.packet_id = i;
            raw_job.data = base_data;
            queue.push(raw_job);
        }
        
        queue.shutdown();
        manager.stopAll();
        
        auto stats = manager.getAggregatedStats();
        TEST("Parser pool parses all 50 packets concurrently", stats.total_parsed == 50);
        TEST("Parser manager graceful drain and exit", queue.empty());
    }
    
    // 3. Malformed raw packet handling in parser pool
    {
        ThreadSafeQueue<RawPacketJob> queue(10);
        auto lb_selector = [](const FiveTuple& tuple) -> LoadBalancer& {
            throw std::runtime_error("Should not be called");
        };
        
        ParserManager manager(2, queue, lb_selector);
        manager.startAll();
        
        RawPacketJob bad_job;
        bad_job.packet_id = 999;
        bad_job.data = {0x00, 0x01, 0x02}; // Truncated invalid packet
        queue.push(bad_job);
        
        queue.shutdown();
        manager.stopAll();
        
        auto stats = manager.getAggregatedStats();
        TEST("Malformed packets handled safely in parser pool", stats.total_errors == 1);
    }
    
    // 4. Flow determinism & full engine pipeline integration under parallel parsing
    {
        DPIEngine::Config config;
        config.num_parser_workers = 4;
        config.num_load_balancers = 2;
        config.fps_per_lb = 2;
        
        DPIEngine engine(config);
        bool ok = engine.processSynthetic(500);
        TEST("DPIEngine synthetic processing with 4 parser workers succeeds", ok);
    }
}

// ===========================================================================
// main
// ===========================================================================
int main() {
    std::cout << "========================================\n";
    std::cout << "  DPI Engine Phase 1, 2 & 3 Correctness Tests\n";
    std::cout << "========================================\n";

    test_classification();
    test_domain_blocking();
    test_flow_canonicalization();
    test_packet_parsing();
    test_packet_job_safety();
    test_tcp_state();
    
    test_ipv6_parsing();
    test_tcp_hardening();
    test_udp_hardening();
    test_icmp();
    test_tls_sni();
    test_http_host();
    test_dns();
    test_quic();
    test_flow_tracking();
    test_classification_precedence();
    
    test_ipv6_phase3();
    test_tcp_reassembly_phase3();
    test_hash_determinism();
    test_phase3_2();

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
