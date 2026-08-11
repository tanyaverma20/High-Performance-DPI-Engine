#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include "types.h"
#include <unordered_map>
#include <shared_mutex>
#include <vector>
#include <chrono>
#include <functional>

namespace DPI {

// ============================================================================
// Connection Tracker - Maintains flow table for all active connections
// ============================================================================
class ConnectionTracker {
public:
    ConnectionTracker(int fp_id, size_t max_connections = 100000);
    
    // Phase 2: FlowKey is the canonical key
    Connection* getOrCreateConnection(const FlowKey& tuple);
    Connection* getConnection(const FlowKey& tuple);
    
    // For backwards compatibility during transition
    Connection* getOrCreateConnection(const FiveTuple& tuple);
    Connection* getConnection(const FiveTuple& tuple);
    
    void updateConnection(Connection* conn, size_t packet_size, bool is_client_to_server);
    
    void classifyConnection(Connection* conn, AppType app, const std::string& sni, const std::string& http_host = "", const std::string& dns_query = "");
    
    void blockConnection(Connection* conn);
    void closeConnection(const FlowKey& tuple);
    void closeConnection(const FiveTuple& tuple);
    
    size_t cleanupStale(std::chrono::seconds default_timeout = std::chrono::seconds(300));
    
    std::vector<Connection> getAllConnections() const;
    size_t getActiveCount() const;
    
    struct TrackerStats {
        size_t active_connections;
        size_t total_connections_seen;
        size_t classified_connections;
        size_t blocked_connections;
    };
    
    TrackerStats getStats() const;
    void clear();
    void forEach(std::function<void(const Connection&)> callback) const;

private:
    int fp_id_;
    size_t max_connections_;
    
    std::unordered_map<FlowKey, Connection, FlowKeyHash> connections_;
    
    size_t total_seen_ = 0;
    size_t classified_count_ = 0;
    size_t blocked_count_ = 0;
    
    void evictOldest();
};

// ============================================================================
// Global Connection Table - Aggregates stats from all FP trackers
// ============================================================================
class GlobalConnectionTable {
public:
    GlobalConnectionTable(size_t num_fps);
    void registerTracker(int fp_id, ConnectionTracker* tracker);
    
    struct GlobalStats {
        size_t total_active_connections;
        size_t total_connections_seen;
        std::unordered_map<AppType, size_t> app_distribution;
        std::vector<std::pair<std::string, size_t>> top_domains;
    };
    
    GlobalStats getGlobalStats() const;
    std::string generateReport() const;

private:
    std::vector<ConnectionTracker*> trackers_;
    mutable std::shared_mutex mutex_;
};

} // namespace DPI

#endif // CONNECTION_TRACKER_H
