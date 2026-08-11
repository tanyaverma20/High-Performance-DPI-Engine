#ifndef SNI_EXTRACTOR_H
#define SNI_EXTRACTOR_H

#include <string>
#include <cstdint>
#include <optional>
#include <vector>
#include <chrono>
#include "types.h"

namespace DPI {

// ============================================================================
// SNI Extractor - Parses TLS Client Hello to extract Server Name Indication
// ============================================================================
class SNIExtractor {
public:
    // Extract SNI from a TLS Client Hello packet
    // payload should point to the start of TCP payload (after TCP header)
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);
    
    // Check if this looks like a TLS Client Hello
    static bool isTLSClientHello(const uint8_t* payload, size_t length);
    
    // Extract all extensions (for debugging/logging)
    static std::vector<std::pair<uint16_t, std::string>> extractExtensions(
        const uint8_t* payload, size_t length);

private:
    static constexpr uint8_t CONTENT_TYPE_HANDSHAKE = 0x16;
    static constexpr uint8_t HANDSHAKE_CLIENT_HELLO = 0x01;
    static constexpr uint16_t EXTENSION_SNI = 0x0000;
    static constexpr uint8_t SNI_TYPE_HOSTNAME = 0x00;
    
    static uint16_t readUint16BE(const uint8_t* data);
    static uint32_t readUint24BE(const uint8_t* data);
};

// ============================================================================
// QUIC SNI Extractor - For QUIC/HTTP3 traffic
// ============================================================================
class QUICSNIExtractor {
public:
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);
    static bool isQUICInitial(const uint8_t* payload, size_t length);
};

// ============================================================================
// HTTP Host Header Extractor (for unencrypted HTTP)
// ============================================================================
class HTTPHostExtractor {
public:
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);
    static bool isHTTPRequest(const uint8_t* payload, size_t length);
};

// ============================================================================
// DNS Query Extractor
// ============================================================================
struct DnsResult {
    uint16_t transaction_id = 0;
    uint16_t flags = 0;
    uint16_t question_count = 0;
    uint16_t answer_count = 0;
    std::string query_domain;
};

class DNSExtractor {
public:
    // Safely extract DNS query details, handling compression pointers
    static std::optional<DnsResult> extractQuery(const uint8_t* payload, size_t length);
    
    static bool isDNSQuery(const uint8_t* payload, size_t length);
    
private:
    // Helper to safely read a domain name handling compression pointers
    static bool readDomainName(const uint8_t* payload, size_t length, size_t& offset, std::string& domain);
};

// TCPReassembler has been moved to tcp_reassembler.h

} // namespace DPI

#endif // SNI_EXTRACTOR_H
