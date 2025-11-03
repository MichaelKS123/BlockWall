/*
 * Blockwall Main Application
 * Author: Michael Semera
 * 
 * Usage: ./blockwall [options]
 */

#include "blockwall.h"
#include <signal.h>
#include <unistd.h>

BlockwallEngine* global_engine = nullptr;

void signal_handler(int signum) {
    std::cout << "\n\nReceived signal " << signum << std::endl;
    if (global_engine) {
        global_engine->stop();
    }
    exit(signum);
}

void print_banner() {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    🛡️  BLOCKWALL 🛡️                         ║\n";
    std::cout << "║         Network Intrusion Detection Engine                   ║\n";
    std::cout << "║                Author: Michael Semera                        ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
}

void print_menu() {
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                        MAIN MENU                             ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  1. Start IDS Engine                                         ║\n";
    std::cout << "║  2. View Statistics                                          ║\n";
    std::cout << "║  3. View Recent Threats                                      ║\n";
    std::cout << "║  4. View Tracked IPs                                         ║\n";
    std::cout << "║  5. Generate Report                                          ║\n";
    std::cout << "║  6. Simulate Traffic (Demo)                                  ║\n";
    std::cout << "║  7. Stop IDS Engine                                          ║\n";
    std::cout << "║  8. Exit                                                     ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    std::cout << "Enter choice: ";
}

void display_statistics(const NetworkStats& stats) {
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                     NETWORK STATISTICS                       ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        now - stats.start_time
    );
    
    std::cout << "║  Uptime:          " << std::left << std::setw(42) 
              << (std::to_string(duration.count()) + " seconds") << "║\n";
    std::cout << "║  Total Packets:   " << std::left << std::setw(42) 
              << stats.total_packets.load() << "║\n";
    std::cout << "║  Total Bytes:     " << std::left << std::setw(42) 
              << stats.total_bytes.load() << "║\n";
    std::cout << "║  TCP Packets:     " << std::left << std::setw(42) 
              << stats.tcp_packets.load() << "║\n";
    std::cout << "║  UDP Packets:     " << std::left << std::setw(42) 
              << stats.udp_packets.load() << "║\n";
    std::cout << "║  Threats:         " << std::left << std::setw(42) 
              << stats.threats_detected.load() << "║\n";
    std::cout << "║  Blocked IPs:     " << std::left << std::setw(42) 
              << stats.blocked_ips.load() << "║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
}

void display_threats(const std::vector<ThreatEvent>& threats) {
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                      RECENT THREATS                          ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
    
    if (threats.empty()) {
        std::cout << "No threats detected.\n";
        return;
    }
    
    for (const auto& threat : threats) {
        std::cout << "───────────────────────────────────────────────────────────────\n";
        std::cout << "ID:          " << threat.id << "\n";
        std::cout << "Source IP:   " << threat.src_ip << "\n";
        std::cout << "Destination: " << threat.dst_ip << "\n";
        std::cout << "Description: " << threat.description << "\n";
        
        auto time_t = std::chrono::system_clock::to_time_t(threat.timestamp);
        std::cout << "Time:        " << std::ctime(&time_t);
    }
    std::cout << "───────────────────────────────────────────────────────────────\n";
}

void display_tracked_ips(const std::map<std::string, IPBehavior>& ips) {
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                      TRACKED IPS                             ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
    
    std::cout << std::left << std::setw(20) << "IP Address"
              << std::setw(15) << "Packets"
              << std::setw(15) << "Connections"
              << std::setw(15) << "Ports Scanned" << "\n";
    std::cout << std::string(65, '─') << "\n";
    
    for (const auto& [ip, behavior] : ips) {
        std::cout << std::left << std::setw(20) << ip
                  << std::setw(15) << behavior.packet_count
                  << std::setw(15) << behavior.connection_attempts
                  << std::setw(15) << behavior.scanned_ports.size() << "\n";
    }
}

void simulate_traffic(BlockwallEngine& engine) {
    std::cout << "\n🎬 Simulating network traffic...\n";
    
    std::vector<std::string> ips = {
        "192.168.1.100", "10.0.0.50", "172.16.0.20",
        "192.168.1.105", "10.0.0.55"
    };
    
    std::vector<std::string> suspicious_ips = {
        "203.0.113.10", "198.51.100.25"
    };
    
    // Simulate normal traffic
    for (int i = 0; i < 50; ++i) {
        Packet packet;
        packet.src_ip = ips[rand() % ips.size()];
        packet.dst_ip = "192.168.1.1";
        packet.src_port = 40000 + rand() % 10000;
        packet.dst_port = 80;
        packet.protocol = "TCP";
        packet.size = 100 + rand() % 1400;
        
        engine.process_packet(packet);
    }
    
    std::cout << "  ✓ Generated 50 normal packets\n";
    
    // Simulate port scan
    std::string scanner_ip = suspicious_ips[0];
    for (int port = 20; port < 35; ++port) {
        Packet packet;
        packet.src_ip = scanner_ip;
        packet.dst_ip = "192.168.1.1";
        packet.src_port = 50000;
        packet.dst_port = port;
        packet.protocol = "TCP";
        packet.size = 64;
        
        engine.process_packet(packet);
    }
    
    std::cout << "  ⚠️  Simulated port scan from " << scanner_ip << "\n";
    
    // Simulate SQL injection attempt
    Packet sql_packet;
    sql_packet.src_ip = suspicious_ips[1];
    sql_packet.dst_ip = "192.168.1.1";
    sql_packet.src_port = 45000;
    sql_packet.dst_port = 80;
    sql_packet.protocol = "TCP";
    
    std::string malicious_payload = "GET /login?user=admin' UNION SELECT * FROM users--";
    sql_packet.payload = std::vector<uint8_t>(malicious_payload.begin(), 
                                               malicious_payload.end());
    sql_packet.size = sql_packet.payload.size();
    
    engine.process_packet(sql_packet);
    
    std::cout << "  ⚠️  Simulated SQL injection from " << suspicious_ips[1] << "\n";
    
    // Simulate connection flood
    for (int i = 0; i < 120; ++i) {
        Packet packet;
        packet.src_ip = "203.0.113.50";
        packet.dst_ip = "192.168.1.1";
        packet.src_port = 50000 + i;
        packet.dst_port = 80;
        packet.protocol = "TCP";
        packet.size = 64;
        
        engine.process_packet(packet);
    }
    
    std::cout << "  ⚠️  Simulated connection flood\n";
    std::cout << "✓ Traffic simulation complete\n";
    std::cout << "\nNote: Check 'View Recent Threats' to see detected attacks\n";
}

int main(int argc, char* argv[]) {
    // Register signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    print_banner();
    
    BlockwallEngine engine;
    global_engine = &engine;
    
    bool running = true;
    
    while (running) {
        print_menu();
        
        int choice;
        std::cin >> choice;
        
        switch (choice) {
            case 1: {
                engine.start();
                std::cout << "\n✓ IDS Engine started. Monitoring network traffic...\n";
                break;
            }
            
            case 2: {
                auto stats = engine.get_stats();
                display_statistics(stats);
                break;
            }
            
            case 3: {
                auto threats = engine.get_recent_threats(10);
                display_threats(threats);
                break;
            }
            
            case 4: {
                auto ips = engine.get_tracked_ips();
                display_tracked_ips(ips);
                break;
            }
            
            case 5: {
                std::string filename = "blockwall_report_" + 
                                      std::to_string(std::time(nullptr)) + ".txt";
                ReportGenerator::generate_report(engine, filename);
                break;
            }
            
            case 6: {
                simulate_traffic(engine);
                // Give time for processing
                std::this_thread::sleep_for(std::chrono::seconds(2));
                break;
            }
            
            case 7: {
                engine.stop();
                std::cout << "\n✓ IDS Engine stopped\n";
                break;
            }
            
            case 8: {
                std::cout << "\n👋 Shutting down Blockwall...\n";
                engine.stop();
                running = false;
                break;
            }
            
            default: {
                std::cout << "\n❌ Invalid choice. Please try again.\n";
            }
        }
        
        if (running && choice != 8) {
            std::cout << "\nPress Enter to continue...";
            std::cin.ignore();
            std::cin.get();
        }
    }
    
    return 0;
}