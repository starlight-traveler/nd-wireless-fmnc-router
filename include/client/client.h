#ifndef CLIENT_H
#define CLIENT_H

#include <unordered_map>
#include <vector>
#include <string>
#include <mutex>
#include <memory>
#include <chrono>
#include <nlohmann/json.hpp>
#include "logger.h"

// A structure to store per-packet info, similar to Server::PacketLogEntry
struct ClientPacketLogEntry
{
    std::string status;
    std::string timestamp;
    std::vector<std::string> flags;
    std::vector<int> options;
};

// A data structure similar to Server::Data for the client
namespace Client
{
    struct Data
    {
        quill::Logger *logger;

        // Mutexes for thread-safety
        std::mutex flags_mutex;
        std::mutex counts_mutex;
        std::mutex packet_log_mutex;

        // TCP flag and option counts
        std::unordered_map<std::string, size_t> tcp_flag_counts;
        std::unordered_map<int, size_t> tcp_option_counts;

        // Packet logs
        std::unordered_map<std::string, ClientPacketLogEntry> packet_log;
    };

    struct Configuration
    {
        quill::Logger *logger;
        std::shared_ptr<Client::Data> data; // Add a pointer to Client::Data
    };
}

// Function to capture packets going 'to' the destination
void capture_packets_to(quill::Logger *logger);

// Packet handler function
void packet_handler_to(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

// Serialization manager for client
void serialization_manager_client(std::shared_ptr<Client::Data> data);

// Dumping functions for client data
void dump_client_tcp_option_counts(std::shared_ptr<Client::Data> data);
void dump_client_tcp_flag_counts(std::shared_ptr<Client::Data> data);
void dump_client_packet_log(std::shared_ptr<Client::Data> data);

#endif // CLIENT_H
