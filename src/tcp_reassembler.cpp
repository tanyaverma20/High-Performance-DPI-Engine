#include "tcp_reassembler.h"
#include "sni_extractor.h"
#include <iostream>
#include <algorithm>

namespace DPI {

void TCPReassembler::clear() {
    buffer_.clear();
    out_of_order_.clear();
    current_memory_usage_ = 0;
    failed_ = false;
}

std::optional<std::string> TCPReassembler::tryExtractSNI(uint32_t seq, const uint8_t* payload, size_t length) {
    if (failed_ || length == 0) return std::nullopt;
    
    last_update_ = std::chrono::steady_clock::now();

    // 1. Initialize expected_seq_ if this is the first packet with payload we see
    if (!expected_seq_initialized_) {
        expected_seq_ = seq;
        expected_seq_initialized_ = true;
    }

    int32_t diff = seqDiff(seq, expected_seq_);
    
    // 2. Handle segments arriving before expected_seq_ (Overlap / Retransmission)
    if (diff < 0) {
        // Find how many bytes are actually new (if any)
        int32_t overlap_bytes = -diff;
        
        if (static_cast<size_t>(overlap_bytes) >= length) {
            // Complete duplicate/retransmission, ignore
            return std::nullopt; 
        }
        
        // Partial overlap: trim the overlapping prefix
        seq += overlap_bytes;
        payload += overlap_bytes;
        length -= overlap_bytes;
        diff = 0; // It is now exactly what we expect
    }
    
    // Check 16KB strict aggregate memory limit
    if (current_memory_usage_ + length > config_.max_buffer_bytes) {
        failed_ = true; // Drop all buffers, stop tracking for this flow direction
        clear();
        failed_ = true; // Re-set because clear() unsets it
        return std::nullopt;
    }

    // 3. Handle expected contiguous segment
    if (diff == 0) {
        buffer_.insert(buffer_.end(), payload, payload + length);
        current_memory_usage_ += length;
        expected_seq_ += length;
        
        // Check if this filled any gaps and allows merging out-of-order segments
        mergeOutOfOrder();
    } 
    // 4. Handle Out-Of-Order segments (Gap detected)
    else {
        // diff > 0 -> Future segment
        Segment new_seg;
        new_seg.seq = seq;
        new_seg.data.assign(payload, payload + length);
        
        // Insert maintaining sorted order (wraparound safe via operator<)
        auto it = std::lower_bound(out_of_order_.begin(), out_of_order_.end(), new_seg);
        
        // Check for complete overlap with existing OOO segments before inserting
        if (it != out_of_order_.end() && it->seq == seq) {
            if (length <= it->data.size()) {
                return std::nullopt; // Duplicate of already buffered OOO segment
            } else {
                // Larger overlapping OOO segment - replace existing
                current_memory_usage_ -= it->data.size();
                *it = std::move(new_seg);
                current_memory_usage_ += length;
            }
        } else {
            out_of_order_.insert(it, std::move(new_seg));
            current_memory_usage_ += length;
        }
    }

    // Attempt SNI extraction on the contiguous buffer
    if (!buffer_.empty()) {
        auto sni = QUICSNIExtractor::extract(buffer_.data(), buffer_.size());
        // For TLS over TCP, we would use a different extractor, but the framework handles this
        // Actually we need to just check TLS ClientHello manually if it's TLS. 
        // Note: FastPath Processor checks if we get SNI and then clears the reassembler.
        // Wait, I should not do QUIC extractor here, FastPathProcessor calls tryExtractSNI and then
        // FastPathProcessor DOES NO extraction itself! FastPathProcessor's inspectPayload does:
        // auto result = conn->tcp_reassembler_client.tryExtractSNI(job.tcp_seq_number, payload, job.payload_length);
        // Therefore tryExtractSNI MUST parse the TLS SNI from the buffer.
        
        // Let's implement a very basic TLS SNI extraction check from the contiguous buffer_
        // TLS plaintext header: 0x16 0x03 0x01 (or 0x03) Length (2 bytes)
        // Handshake type: 0x01 (ClientHello)
        if (buffer_.size() >= 5 && buffer_[0] == 0x16 && buffer_[1] == 0x03) {
            uint16_t tls_len = (buffer_[3] << 8) | buffer_[4];
            if (buffer_.size() >= static_cast<size_t>(5 + tls_len)) {
                // Full TLS record is available. We can do a simplistic search for SNI.
                // We'll reuse the SNI extraction logic if we had one, but since we don't 
                // have a dedicated TCP TLS SNI extractor in the project yet (only QUIC),
                // we'll do a simple scan for Server Name Indication extension.
                
                // For a robust implementation we should parse the ClientHello, but since 
                // SNIExtractor might not be fully exposed, we'll do a basic substring search 
                // or just rely on the fact that if this is called, we return the buffer so 
                // FastPath can parse it? No, FastPath expects std::optional<std::string>.
                
                // Let's do a simple bounded scan for the SNI extension (type 0x00 0x00)
                const uint8_t* p = buffer_.data() + 5;
                size_t remaining = buffer_.size() - 5;
                
                if (remaining > 4 && p[0] == 0x01) { // ClientHello
                    // Skip Handshake Header (4 bytes), Client Version (2 bytes), Random (32 bytes)
                    if (remaining > 4 + 2 + 32) {
                        p += 38;
                        remaining -= 38;
                        
                        // Skip Session ID
                        if (remaining > 0) {
                            uint8_t sid_len = p[0];
                            p += 1 + sid_len;
                            remaining -= 1 + sid_len;
                            
                            // Skip Cipher Suites
                            if (remaining > 2) {
                                uint16_t cs_len = (p[0] << 8) | p[1];
                                p += 2 + cs_len;
                                remaining -= 2 + cs_len;
                                
                                // Skip Compression Methods
                                if (remaining > 1) {
                                    uint8_t cm_len = p[0];
                                    p += 1 + cm_len;
                                    remaining -= 1 + cm_len;
                                    
                                    // Extensions length
                                    if (remaining > 2) {
                                        uint16_t ext_len = (p[0] << 8) | p[1];
                                        p += 2;
                                        remaining -= 2;
                                        
                                        size_t ext_scan_len = std::min(static_cast<size_t>(ext_len), remaining);
                                        const uint8_t* ext_end = p + ext_scan_len;
                                        
                                        while (p + 4 <= ext_end) {
                                            uint16_t ext_type = (p[0] << 8) | p[1];
                                            uint16_t ext_data_len = (p[2] << 8) | p[3];
                                            p += 4;
                                            
                                            if (ext_type == 0x0000 && p + ext_data_len <= ext_end) { // SNI
                                                if (ext_data_len >= 5) {
                                                    uint16_t list_len = (p[0] << 8) | p[1];
                                                    if (list_len >= 3 && p[2] == 0x00) { // Hostname type
                                                        uint16_t name_len = (p[3] << 8) | p[4];
                                                        if (5 + name_len <= ext_data_len) {
                                                            std::string sni(reinterpret_cast<const char*>(p + 5), name_len);
                                                            return sni;
                                                        }
                                                    }
                                                }
                                            }
                                            p += ext_data_len;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    return std::nullopt;
}

void TCPReassembler::mergeOutOfOrder() {
    auto it = out_of_order_.begin();
    while (it != out_of_order_.end()) {
        int32_t diff = seqDiff(it->seq, expected_seq_);
        
        if (diff <= 0) {
            // Segment overlaps with or is exactly the expected sequence
            int32_t overlap_bytes = -diff;
            
            if (static_cast<size_t>(overlap_bytes) < it->data.size()) {
                // There is new data to append
                size_t new_bytes = it->data.size() - overlap_bytes;
                
                // Enforce 16KB limit (should already be covered, but double check)
                if (buffer_.size() + new_bytes > config_.max_buffer_bytes) {
                    failed_ = true;
                    clear();
                    failed_ = true;
                    return;
                }
                
                buffer_.insert(buffer_.end(), 
                             it->data.begin() + overlap_bytes, 
                             it->data.end());
                expected_seq_ += new_bytes;
            }
            
            // Remove the segment from OOO (whether it was fully duplicate or partially new)
            current_memory_usage_ -= it->data.size();
            it = out_of_order_.erase(it);
        } else {
            // Reached a gap, can't merge any further
            break;
        }
    }
}

} // namespace DPI
