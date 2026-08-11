#include "sni_extractor.h"
#include <cstring>
#include <algorithm>
#include <cctype>

namespace DPI {

// ============================================================================
// TLS SNI Extractor Implementation
// ============================================================================

uint16_t SNIExtractor::readUint16BE(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}

uint32_t SNIExtractor::readUint24BE(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 16) |
           (static_cast<uint32_t>(data[1]) << 8) |
           data[2];
}

bool SNIExtractor::isTLSClientHello(const uint8_t* payload, size_t length) {
    if (length < 9) return false;
    
    if (payload[0] != CONTENT_TYPE_HANDSHAKE) return false;
    
    uint16_t version = readUint16BE(payload + 1);
    if (version < 0x0300 || version > 0x0304) return false;
    
    uint16_t record_length = readUint16BE(payload + 3);
    if (record_length > length - 5) return false;
    
    if (payload[5] != HANDSHAKE_CLIENT_HELLO) return false;
    
    return true;
}

std::optional<std::string> SNIExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isTLSClientHello(payload, length)) {
        return std::nullopt;
    }
    
    size_t offset = 5;
    
    // Handshake header length check
    if (offset + 4 > length) return std::nullopt;
    uint32_t handshake_length = readUint24BE(payload + offset + 1);
    offset += 4;
    
    // Check if handshake fits in the buffer
    if (offset + handshake_length > length) return std::nullopt;
    
    // Client version
    if (offset + 2 > length) return std::nullopt;
    offset += 2;
    
    // Random
    if (offset + 32 > length) return std::nullopt;
    offset += 32;
    
    // Session ID
    if (offset >= length) return std::nullopt;
    uint8_t session_id_length = payload[offset];
    offset += 1 + session_id_length;
    if (offset > length) return std::nullopt;
    
    // Cipher suites
    if (offset + 2 > length) return std::nullopt;
    uint16_t cipher_suites_length = readUint16BE(payload + offset);
    offset += 2 + cipher_suites_length;
    if (offset > length) return std::nullopt;
    
    // Compression methods
    if (offset >= length) return std::nullopt;
    uint8_t compression_methods_length = payload[offset];
    offset += 1 + compression_methods_length;
    if (offset > length) return std::nullopt;
    
    // Extensions
    if (offset + 2 > length) return std::nullopt;
    uint16_t extensions_length = readUint16BE(payload + offset);
    offset += 2;
    
    size_t extensions_end = offset + extensions_length;
    if (extensions_end > length) {
        return std::nullopt; // Strictly reject truncated extensions
    }
    
    while (offset + 4 <= extensions_end) {
        uint16_t extension_type = readUint16BE(payload + offset);
        uint16_t extension_length = readUint16BE(payload + offset + 2);
        offset += 4;
        
        if (offset + extension_length > extensions_end) break;
        
        if (extension_type == EXTENSION_SNI) {
            if (extension_length < 5) break;
            
            uint16_t sni_list_length = readUint16BE(payload + offset);
            if (sni_list_length < 3) break;
            
            uint8_t sni_type = payload[offset + 2];
            uint16_t sni_length = readUint16BE(payload + offset + 3);
            
            if (sni_type != SNI_TYPE_HOSTNAME) break;
            if (sni_length > extension_length - 5) break;
            
            std::string sni(reinterpret_cast<const char*>(payload + offset + 5), sni_length);
            return sni;
        }
        
        offset += extension_length;
    }
    
    return std::nullopt;
}

std::vector<std::pair<uint16_t, std::string>> SNIExtractor::extractExtensions(
    const uint8_t* payload, size_t length) {
    // Stubbed out for brevity, not required for correctness
    return {};
}

// ============================================================================
// HTTP Host Header Extractor Implementation
// ============================================================================

bool HTTPHostExtractor::isHTTPRequest(const uint8_t* payload, size_t length) {
    if (length < 4) return false;
    
    const char* methods[] = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
    
    for (const char* method : methods) {
        if (std::memcmp(payload, method, 4) == 0) {
            return true;
        }
    }
    
    return false;
}

std::optional<std::string> HTTPHostExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isHTTPRequest(payload, length)) {
        return std::nullopt;
    }
    
    // Look for "\nHost:" or "\r\nHost:" (case insensitive) to avoid matching "X-Host:"
    for (size_t i = 0; i + 6 < length; ++i) {
        if (payload[i] == '\n') {
            size_t start = i + 1;
            if (start + 5 <= length && 
                std::tolower(payload[start]) == 'h' &&
                std::tolower(payload[start+1]) == 'o' &&
                std::tolower(payload[start+2]) == 's' &&
                std::tolower(payload[start+3]) == 't' &&
                payload[start+4] == ':') {
                
                size_t val_start = start + 5;
                while (val_start < length && (payload[val_start] == ' ' || payload[val_start] == '\t')) {
                    val_start++;
                }
                
                size_t val_end = val_start;
                while (val_end < length && payload[val_end] != '\r' && payload[val_end] != '\n') {
                    val_end++;
                }
                
                // Trim trailing whitespace
                while (val_end > val_start && (payload[val_end - 1] == ' ' || payload[val_end - 1] == '\t')) {
                    val_end--;
                }
                
                if (val_end > val_start) {
                    std::string host(reinterpret_cast<const char*>(payload + val_start), val_end - val_start);
                    size_t colon_pos = host.find(':');
                    if (colon_pos != std::string::npos) {
                        host = host.substr(0, colon_pos);
                    }
                    return host;
                }
            }
        }
    }
    
    return std::nullopt;
}

// ============================================================================
// DNS Extractor Implementation
// ============================================================================

bool DNSExtractor::isDNSQuery(const uint8_t* payload, size_t length) {
    if (length < 12) return false;
    uint8_t flags = payload[2];
    if (flags & 0x80) return false;  // Response
    uint16_t qdcount = (static_cast<uint16_t>(payload[4]) << 8) | payload[5];
    return qdcount > 0;
}

bool DNSExtractor::readDomainName(const uint8_t* payload, size_t length, size_t& offset, std::string& domain) {
    size_t original_offset = offset;
    bool jumped = false;
    int jumps = 0;
    const int MAX_JUMPS = 10; // Prevent infinite loops
    
    domain.clear();
    
    while (offset < length) {
        uint8_t len = payload[offset];
        
        if (len == 0) {
            if (!jumped) original_offset = offset + 1;
            break;
        }
        
        if ((len & 0xC0) == 0xC0) { // Pointer
            if (offset + 1 >= length) return false; // Truncated pointer
            uint16_t ptr = ((len & 0x3F) << 8) | payload[offset + 1];
            if (ptr >= length || ptr < 12) return false; // Invalid pointer
            
            if (!jumped) original_offset = offset + 2;
            offset = ptr;
            jumped = true;
            
            if (++jumps > MAX_JUMPS) return false; // Too many jumps
            continue;
        }
        
        // Normal label
        offset++;
        if (offset + len > length) return false; // Truncated label
        
        if (!domain.empty()) domain += '.';
        domain += std::string(reinterpret_cast<const char*>(payload + offset), len);
        offset += len;
    }
    
    offset = jumped ? original_offset : offset;
    return !domain.empty();
}

std::optional<DnsResult> DNSExtractor::extractQuery(const uint8_t* payload, size_t length) {
    if (!isDNSQuery(payload, length)) {
        return std::nullopt;
    }
    
    DnsResult result;
    result.transaction_id = (static_cast<uint16_t>(payload[0]) << 8) | payload[1];
    result.flags = (static_cast<uint16_t>(payload[2]) << 8) | payload[3];
    result.question_count = (static_cast<uint16_t>(payload[4]) << 8) | payload[5];
    result.answer_count = (static_cast<uint16_t>(payload[6]) << 8) | payload[7];
    
    size_t offset = 12; // Start of questions
    if (!readDomainName(payload, length, offset, result.query_domain)) {
        return std::nullopt; // Failed to parse domain
    }
    
    return result;
}

// ============================================================================
// QUIC SNI Extractor
// ============================================================================

bool QUICSNIExtractor::isQUICInitial(const uint8_t* payload, size_t length) {
    if (length < 5) return false;
    uint8_t first_byte = payload[0];
    if ((first_byte & 0x80) == 0) return false; // Long header form only
    
    // Check for QUIC version (bytes 1-4)
    // Common versions: 0x00000001 (v1), 0xff000000+ (drafts)
    uint32_t version = (static_cast<uint32_t>(payload[1]) << 24) |
                       (static_cast<uint32_t>(payload[2]) << 16) |
                       (static_cast<uint32_t>(payload[3]) << 8) |
                       payload[4];
                       
    // Note: Version validation can be added here if strictness is required.
    (void)version;
    return true;
}

std::optional<std::string> QUICSNIExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isQUICInitial(payload, length)) {
        return std::nullopt;
    }

    constexpr size_t MIN_TLS_LOOKAHEAD = 50;
    for (size_t i = 5; i < length && (length - i) >= MIN_TLS_LOOKAHEAD; i++) {
        if (payload[i] == 0x01) { 
            const uint8_t* sub = payload + i - 5;
            size_t sub_len     = length - (i - 5);
            auto result = SNIExtractor::extract(sub, sub_len);
            if (result) return result;
        }
    }

    return std::nullopt;
}

// TCPReassembler implementation moved to tcp_reassembler.cpp

} // namespace DPI
