#ifndef SERVER
#define SERVER

#include "general.h"

// server.h

namespace Server
{
    struct PacketLogEntry
    {
        std::string status;             // "received" or "sent"
        std::string timestamp;          // Timestamp as a string
        std::vector<std::string> flags; // Array of TCP flags
        std::vector<int> options;       // Array of TCP option kinds
    };

    struct PacketData
    {
        std::vector<unsigned char> data;
        size_t length;
        struct sockaddr_ll socket_address;
        char dest_ip[INET_ADDRSTRLEN];
        unsigned char dest_mac[6];s
    };

    struct Data
    {
        quill::Logger *logger;
        struct timeval prev_timestamp;
        size_t total_payload_length;
        std::mutex queue_mutex;
        std::vector<Server::PacketData> packet_queue;

        // Existing members for TCP option counts
        std::unordered_map<int, size_t> tcp_option_counts;
        std::mutex counts_mutex;

        // Existing members for TCP flag counts
        std::unordered_map<std::string, size_t> tcp_flag_counts;
        std::mutex flags_mutex;

        // New member for packet tracking
        std::unordered_map<std::string, PacketLogEntry> packet_log;
        std::mutex packet_log_mutex;
    };
} // namespace Server

void packet_handler_from(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
void capture_packets_from(std::shared_ptr<Server::Data> internal, quill::Logger *logger, ConfigManager &config);
bool apply_filter(pcap_t *handle, quill::Logger *logger);
long compute_time_difference(const struct timeval &prev, const struct timeval &curr);
void send_queued_packets(std::shared_ptr<Server::Data> internal);
void send_packet(const Server::PacketData &pkt, quill::Logger *logger);
void queue_packet(std::shared_ptr<Server::Data> internal, const struct pcap_pkthdr *header, const u_char *packet);
void timer_thread(std::shared_ptr<Server::Data> internal);

#endif