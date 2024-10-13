#ifndef SERVER
#define SERVER

#include "general.h"

namespace Server
{
    struct PacketData
    {
        std::vector<unsigned char> data;
        size_t length;
        struct sockaddr_ll socket_address;
        char dest_ip[INET_ADDRSTRLEN];
    };

    struct Configuration
    {
        quill::Logger *logger;
        std::vector<PacketData> packet_queue;
        struct timeval prev_timestamp;
        size_t total_payload_length;
        std::mutex queue_mutex;
    };
}

void capture_packets_from(quill::Logger *logger);
bool apply_filter(pcap_t *handle, quill::Logger *logger);
long compute_time_difference(const struct timeval &prev, const struct timeval &curr);
void send_queued_packets(Server::Configuration *args);
void send_packet(const Server::PacketData &pkt, quill::Logger *logger);
void queue_packet(Server::Configuration *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif