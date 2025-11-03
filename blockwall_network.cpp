/*
 * Blockwall: Network Intrusion Detection Engine
 * Author: Michael Semera
 * Description: Advanced IDS with deep packet inspection and pattern recognition
 * 
 * Core Components:
 * - Packet Capture and Analysis
 * - Pattern Matching Engine
 * - Threat Detection Algorithms
 * - Multi-threaded Processing
 * - Real-time Alert System
 */

#ifndef BLOCKWALL_H
#define BLOCKWALL_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <memory>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <atomic>
#include <algorithm>
#include <regex>
#include <ctime>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>

// Threat severity levels
enum class ThreatLevel {
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

// Attack types
enum class AttackType {
    PORT_SCAN,
    SYN_FLOOD,
    DOS_ATTACK,
    BRUTE_FORCE,
    SQL_INJECTION,
    XSS_ATTACK,
    MALFORMED_PACKET,
    SUSPICIOUS_PAYLOAD,
    UNKNOWN
};

/*
 * Packet structure for network data
 */
struct Packet {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::string protocol;
    size_t size;
    std::vector<uint8_t> payload;
    std::chrono::system_clock::time_point timestamp;
    
    Packet() : src_port(0), dst_port(0), size(0), 
               timestamp(std::chrono::system_clock::now()) {}
};

/*
 * Threat detection event
 */
struct ThreatEvent {
    std::string id;
    AttackType type;
    ThreatLevel severity;
    std::string src_ip;
    std::string dst_ip;
    std::string description;
    std::chrono::system_clock::time_point timestamp;
    std::map<std::string, std::string> metadata;
    
    ThreatEvent() : type(AttackType::UNKNOWN), 
                    severity(ThreatLevel::LOW),
                    timestamp(std::chrono::system_clock::now()) {}
};

/*
 * Statistics tracking
 */
struct NetworkStats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    std::atomic<uint64_t> threats_detected{0};
    std::atomic<uint64_t> blocked_ips{0};
    std::chrono::system_clock::time_point start_time;
    
    NetworkStats() : start_time(std::chrono::system_clock::now()) {}
    
    void reset() {
        total_packets = 0;
        total_bytes = 0;
        tcp_packets = 0;
        udp_packets = 0;
        threats_detected = 0;
        blocked_ips = 0;
        start_time = std::chrono::system_clock::now();
    }
};

/*
 * IP tracking for behavior analysis
 */
struct IPBehavior {
    std::string ip_address;
    uint32_t packet_count;
    uint32_t connection_attempts;
    std::vector<uint16_t> scanned_ports;
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_seen;
    bool is_suspicious;
    
    IPBehavior() : packet_count(0), connection_attempts(0), 
                   is_suspicious(false),
                   first_seen(std::chrono::system_clock::now()),
                   last_seen(std::chrono::system_clock::now()) {}
};

/*
 * Pattern matching engine for threat detection
 */
class PatternMatcher {
private:
    struct Pattern {
        std::string name;
        std::regex pattern;
        AttackType type;
        ThreatLevel severity;
    };
    
    std::vector<Pattern> patterns;
    
public:
    PatternMatcher() {
        initialize_patterns();
    }
    
    void initialize_patterns() {
        // SQL Injection patterns
        add_pattern("SQL Injection - UNION", 
                   std::regex("UNION.*SELECT", std::regex::icase),
                   AttackType::SQL_INJECTION, ThreatLevel::HIGH);
        
        add_pattern("SQL Injection - OR 1=1",
                   std::regex("OR\\s+1\\s*=\\s*1", std::regex::icase),
                   AttackType::SQL_INJECTION, ThreatLevel::HIGH);
        
        // XSS patterns
        add_pattern("XSS - Script Tag",
                   std::regex("<script[^>]*>", std::regex::icase),
                   AttackType::XSS_ATTACK, ThreatLevel::MEDIUM);
        
        add_pattern("XSS - Javascript",
                   std::regex("javascript:", std::regex::icase),
                   AttackType::XSS_ATTACK, ThreatLevel::MEDIUM);
        
        // Suspicious payloads
        add_pattern("Shell Command Injection",
                   std::regex("(\\||;|`|\\$\\(|\\&\\&)", std::regex::icase),
                   AttackType::SUSPICIOUS_PAYLOAD, ThreatLevel::HIGH);
    }
    
    void add_pattern(const std::string& name, const std::regex& pattern,
                    AttackType type, ThreatLevel severity) {
        patterns.push_back({name, pattern, type, severity});
    }
    
    std::vector<std::pair<std::string, AttackType>> match(const std::string& data) {
        std::vector<std::pair<std::string, AttackType>> matches;
        
        for (const auto& p : patterns) {
            if (std::regex_search(data, p.pattern)) {
                matches.push_back({p.name, p.type});
            }
        }
        
        return matches;
    }
};

/*
 * Threat detector with multiple detection algorithms
 */
class ThreatDetector {
private:
    std::map<std::string, IPBehavior> ip_tracker;
    std::mutex tracker_mutex;
    PatternMatcher pattern_matcher;
    
    // Detection thresholds
    const uint32_t PORT_SCAN_THRESHOLD = 10;
    const uint32_t CONNECTION_RATE_THRESHOLD = 100;
    const std::chrono::seconds TIME_WINDOW{60};
    
public:
    std::vector<ThreatEvent> analyze_packet(const Packet& packet) {
        std::vector<ThreatEvent> threats;
        
        // Update IP tracking
        update_ip_behavior(packet);
        
        // Check for port scanning
        if (auto threat = detect_port_scan(packet)) {
            threats.push_back(*threat);
        }
        
        // Check for SYN flood
        if (auto threat = detect_syn_flood(packet)) {
            threats.push_back(*threat);
        }
        
        // Check payload for malicious patterns
        if (!packet.payload.empty()) {
            auto payload_threats = detect_malicious_payload(packet);
            threats.insert(threats.end(), payload_threats.begin(), payload_threats.end());
        }
        
        // Check for connection rate abuse
        if (auto threat = detect_connection_abuse(packet)) {
            threats.push_back(*threat);
        }
        
        return threats;
    }
    
    void update_ip_behavior(const Packet& packet) {
        std::lock_guard<std::mutex> lock(tracker_mutex);
        
        auto& behavior = ip_tracker[packet.src_ip];
        behavior.ip_address = packet.src_ip;
        behavior.packet_count++;
        behavior.last_seen = std::chrono::system_clock::now();
        
        if (behavior.packet_count == 1) {
            behavior.first_seen = packet.timestamp;
        }
        
        // Track port scanning behavior
        if (std::find(behavior.scanned_ports.begin(), 
                     behavior.scanned_ports.end(), 
                     packet.dst_port) == behavior.scanned_ports.end()) {
            behavior.scanned_ports.push_back(packet.dst_port);
        }
        
        behavior.connection_attempts++;
    }
    
    std::optional<ThreatEvent> detect_port_scan(const Packet& packet) {
        std::lock_guard<std::mutex> lock(tracker_mutex);
        
        auto it = ip_tracker.find(packet.src_ip);
        if (it == ip_tracker.end()) return std::nullopt;
        
        const auto& behavior = it->second;
        
        // Check if scanning multiple ports
        if (behavior.scanned_ports.size() > PORT_SCAN_THRESHOLD) {
            ThreatEvent event;
            event.id = generate_threat_id();
            event.type = AttackType::PORT_SCAN;
            event.severity = ThreatLevel::HIGH;
            event.src_ip = packet.src_ip;
            event.dst_ip = packet.dst_ip;
            event.description = "Port scan detected from " + packet.src_ip + 
                              " - scanned " + std::to_string(behavior.scanned_ports.size()) + 
                              " ports";
            event.metadata["scanned_ports"] = std::to_string(behavior.scanned_ports.size());
            
            return event;
        }
        
        return std::nullopt;
    }
    
    std::optional<ThreatEvent> detect_syn_flood(const Packet& packet) {
        if (packet.protocol != "TCP") return std::nullopt;
        
        std::lock_guard<std::mutex> lock(tracker_mutex);
        auto it = ip_tracker.find(packet.src_ip);
        if (it == ip_tracker.end()) return std::nullopt;
        
        const auto& behavior = it->second;
        auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(
            behavior.last_seen - behavior.first_seen
        );
        
        // High rate of connections in short time
        if (time_diff.count() > 0 && 
            behavior.connection_attempts / time_diff.count() > 50) {
            
            ThreatEvent event;
            event.id = generate_threat_id();
            event.type = AttackType::SYN_FLOOD;
            event.severity = ThreatLevel::CRITICAL;
            event.src_ip = packet.src_ip;
            event.dst_ip = packet.dst_ip;
            event.description = "Possible SYN flood attack from " + packet.src_ip;
            event.metadata["rate"] = std::to_string(
                behavior.connection_attempts / time_diff.count()
            );
            
            return event;
        }
        
        return std::nullopt;
    }
    
    std::vector<ThreatEvent> detect_malicious_payload(const Packet& packet) {
        std::vector<ThreatEvent> threats;
        
        // Convert payload to string for pattern matching
        std::string payload_str(packet.payload.begin(), packet.payload.end());
        
        auto matches = pattern_matcher.match(payload_str);
        
        for (const auto& match : matches) {
            ThreatEvent event;
            event.id = generate_threat_id();
            event.type = match.second;
            event.severity = ThreatLevel::HIGH;
            event.src_ip = packet.src_ip;
            event.dst_ip = packet.dst_ip;
            event.description = "Malicious pattern detected: " + match.first;
            event.metadata["pattern"] = match.first;
            
            threats.push_back(event);
        }
        
        return threats;
    }
    
    std::optional<ThreatEvent> detect_connection_abuse(const Packet& packet) {
        std::lock_guard<std::mutex> lock(tracker_mutex);
        
        auto it = ip_tracker.find(packet.src_ip);
        if (it == ip_tracker.end()) return std::nullopt;
        
        const auto& behavior = it->second;
        auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now() - behavior.first_seen
        );
        
        // Too many connections in time window
        if (time_diff < TIME_WINDOW && 
            behavior.connection_attempts > CONNECTION_RATE_THRESHOLD) {
            
            ThreatEvent event;
            event.id = generate_threat_id();
            event.type = AttackType::DOS_ATTACK;
            event.severity = ThreatLevel::CRITICAL;
            event.src_ip = packet.src_ip;
            event.dst_ip = packet.dst_ip;
            event.description = "Connection rate abuse detected from " + packet.src_ip;
            event.metadata["connections"] = std::to_string(behavior.connection_attempts);
            
            return event;
        }
        
        return std::nullopt;
    }
    
    std::string generate_threat_id() {
        static std::atomic<uint64_t> counter{0};
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()
        ).count();
        
        std::stringstream ss;
        ss << "THR-" << ms << "-" << counter++;
        return ss.str();
    }
    
    std::map<std::string, IPBehavior> get_tracked_ips() {
        std::lock_guard<std::mutex> lock(tracker_mutex);
        return ip_tracker;
    }
};

/*
 * Alert manager for threat notifications
 */
class AlertManager {
private:
    std::queue<ThreatEvent> alert_queue;
    std::mutex queue_mutex;
    std::condition_variable queue_cv;
    std::vector<ThreatEvent> alert_history;
    const size_t MAX_HISTORY = 1000;
    
public:
    void add_alert(const ThreatEvent& event) {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            alert_queue.push(event);
            
            // Add to history
            alert_history.push_back(event);
            if (alert_history.size() > MAX_HISTORY) {
                alert_history.erase(alert_history.begin());
            }
        }
        queue_cv.notify_one();
    }
    
    std::optional<ThreatEvent> get_next_alert(std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(queue_mutex);
        
        if (queue_cv.wait_for(lock, timeout, [this] { return !alert_queue.empty(); })) {
            auto event = alert_queue.front();
            alert_queue.pop();
            return event;
        }
        
        return std::nullopt;
    }
    
    std::vector<ThreatEvent> get_recent_alerts(size_t count) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        
        size_t start = alert_history.size() > count ? 
                      alert_history.size() - count : 0;
        
        return std::vector<ThreatEvent>(
            alert_history.begin() + start,
            alert_history.end()
        );
    }
    
    size_t get_alert_count() {
        std::lock_guard<std::mutex> lock(queue_mutex);
        return alert_history.size();
    }
};

/*
 * Main Blockwall IDS Engine
 */
class BlockwallEngine {
private:
    std::atomic<bool> running{false};
    std::vector<std::thread> worker_threads;
    std::queue<Packet> packet_queue;
    std::mutex queue_mutex;
    std::condition_variable queue_cv;
    
    ThreatDetector detector;
    AlertManager alert_manager;
    NetworkStats stats;
    
    const size_t NUM_WORKERS = 4;
    const size_t MAX_QUEUE_SIZE = 10000;
    
public:
    BlockwallEngine() = default;
    
    ~BlockwallEngine() {
        stop();
    }
    
    void start() {
        if (running) return;
        
        running = true;
        stats.reset();
        
        std::cout << "🛡️  Starting Blockwall IDS Engine..." << std::endl;
        std::cout << "   Workers: " << NUM_WORKERS << std::endl;
        std::cout << "   Queue capacity: " << MAX_QUEUE_SIZE << std::endl;
        
        // Start worker threads
        for (size_t i = 0; i < NUM_WORKERS; ++i) {
            worker_threads.emplace_back(&BlockwallEngine::worker_thread, this, i);
        }
        
        std::cout << "✓ Blockwall IDS is running" << std::endl;
    }
    
    void stop() {
        if (!running) return;
        
        std::cout << "\n🛑 Stopping Blockwall IDS..." << std::endl;
        
        running = false;
        queue_cv.notify_all();
        
        for (auto& thread : worker_threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        
        worker_threads.clear();
        
        std::cout << "✓ Blockwall IDS stopped" << std::endl;
    }
    
    void process_packet(const Packet& packet) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            
            // Drop packets if queue is full
            if (packet_queue.size() >= MAX_QUEUE_SIZE) {
                return;
            }
            
            packet_queue.push(packet);
        }
        
        queue_cv.notify_one();
        
        // Update statistics
        stats.total_packets++;
        stats.total_bytes += packet.size;
        
        if (packet.protocol == "TCP") {
            stats.tcp_packets++;
        } else if (packet.protocol == "UDP") {
            stats.udp_packets++;
        }
    }
    
    NetworkStats get_stats() const {
        return stats;
    }
    
    std::vector<ThreatEvent> get_recent_threats(size_t count = 10) {
        return alert_manager.get_recent_alerts(count);
    }
    
    std::map<std::string, IPBehavior> get_tracked_ips() {
        return detector.get_tracked_ips();
    }
    
private:
    void worker_thread(size_t id) {
        while (running) {
            std::unique_lock<std::mutex> lock(queue_mutex);
            
            if (queue_cv.wait_for(lock, std::chrono::milliseconds(100),
                                 [this] { return !packet_queue.empty() || !running; })) {
                
                if (!running && packet_queue.empty()) {
                    break;
                }
                
                if (packet_queue.empty()) {
                    continue;
                }
                
                auto packet = packet_queue.front();
                packet_queue.pop();
                lock.unlock();
                
                // Analyze packet for threats
                auto threats = detector.analyze_packet(packet);
                
                // Generate alerts for detected threats
                for (const auto& threat : threats) {
                    alert_manager.add_alert(threat);
                    stats.threats_detected++;
                }
            }
        }
    }
};

/*
 * Report generator
 */
class ReportGenerator {
public:
    static void generate_report(const BlockwallEngine& engine, 
                               const std::string& filename) {
        std::ofstream file(filename);
        
        if (!file.is_open()) {
            std::cerr << "Failed to create report file" << std::endl;
            return;
        }
        
        auto stats = engine.get_stats();
        auto threats = engine.get_recent_threats(50);
        
        file << "╔══════════════════════════════════════════════════════════════╗\n";
        file << "║            BLOCKWALL IDS SECURITY REPORT                     ║\n";
        file << "║                 Author: Michael Semera                       ║\n";
        file << "╚══════════════════════════════════════════════════════════════╝\n\n";
        
        // Statistics
        file << "NETWORK STATISTICS\n";
        file << "─────────────────────────────────────────────────────────────\n";
        file << "Total Packets:     " << stats.total_packets << "\n";
        file << "Total Bytes:       " << stats.total_bytes << "\n";
        file << "TCP Packets:       " << stats.tcp_packets << "\n";
        file << "UDP Packets:       " << stats.udp_packets << "\n";
        file << "Threats Detected:  " << stats.threats_detected << "\n";
        file << "Blocked IPs:       " << stats.blocked_ips << "\n\n";
        
        // Recent threats
        file << "RECENT THREATS (" << threats.size() << ")\n";
        file << "─────────────────────────────────────────────────────────────\n";
        
        for (const auto& threat : threats) {
            file << "ID: " << threat.id << "\n";
            file << "Type: " << attack_type_to_string(threat.type) << "\n";
            file << "Severity: " << threat_level_to_string(threat.severity) << "\n";
            file << "Source: " << threat.src_ip << "\n";
            file << "Description: " << threat.description << "\n";
            file << "───────────────────────────────────────\n";
        }
        
        file.close();
        std::cout << "✓ Report saved to: " << filename << std::endl;
    }
    
private:
    static std::string attack_type_to_string(AttackType type) {
        switch (type) {
            case AttackType::PORT_SCAN: return "Port Scan";
            case AttackType::SYN_FLOOD: return "SYN Flood";
            case AttackType::DOS_ATTACK: return "DoS Attack";
            case AttackType::BRUTE_FORCE: return "Brute Force";
            case AttackType::SQL_INJECTION: return "SQL Injection";
            case AttackType::XSS_ATTACK: return "XSS Attack";
            case AttackType::MALFORMED_PACKET: return "Malformed Packet";
            case AttackType::SUSPICIOUS_PAYLOAD: return "Suspicious Payload";
            default: return "Unknown";
        }
    }
    
    static std::string threat_level_to_string(ThreatLevel level) {
        switch (level) {
            case ThreatLevel::LOW: return "Low";
            case ThreatLevel::MEDIUM: return "Medium";
            case ThreatLevel::HIGH: return "High";
            case ThreatLevel::CRITICAL: return "Critical";
            default: return "Unknown";
        }
    }
};

#endif // BLOCKWALL_H