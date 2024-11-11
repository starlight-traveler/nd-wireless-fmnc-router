// sender.cpp

#include "sender.h"
#include <algorithm> // For std::shuffle
#include <random>    // For random number generator
#include <mutex>
#include "logger.h"
#include "utilities.h"

// External variables (Assumed to be defined elsewhere)
extern int raw_socket;
extern std::mutex raw_socket_mutex;

// Function to reverse and send queued packets
void send_queued_packets(std::shared_ptr<Server::Data> internal)
{
    // Lock the queue to safely access and modify it
    {
        std::lock_guard<std::mutex> lock(internal->queue_mutex);

        if (internal->packet_queue.empty())
        {
            LOG_DEBUG(internal->logger, "Packet queue is empty. Nothing to send.");
            return;
        }

        // Reverse the packet queue to flip the order of packets
        std::reverse(internal->packet_queue.begin(), internal->packet_queue.end());

        // Iterate over the reversed packets and send each one
        for (const auto &pkt : internal->packet_queue)
        {
            send_packet(pkt, internal->logger, internal);
        }

        // Clear the queue and reset total payload length
        internal->packet_queue.clear();
        internal->total_payload_length = 0;

        LOG_INFO(internal->logger, "All queued packets have been sent and the queue is now cleared.");
    }
}

// Function to send a single packet
void send_packet(const Server::PacketData &pkt, quill::Logger *logger, std::shared_ptr<Server::Data> internal)
{
    // Generate packet ID
    struct iphdr *ip_header = (struct iphdr *)(pkt.data.data() + sizeof(struct ethhdr));
    int ip_header_length = ip_header->ihl * 4;
    struct tcphdr *tcp_header = (struct tcphdr *)(pkt.data.data() + sizeof(struct ethhdr) + ip_header_length);

    std::string packet_id = generate_packet_id(ip_header, tcp_header);
    std::string timestamp = get_current_timestamp();

    {
        std::lock_guard<std::mutex> lock(internal->packet_log_mutex);
        auto it = internal->packet_log.find(packet_id);
        if (it != internal->packet_log.end())
        {
            it->second.status = "sent";
            it->second.timestamp = timestamp;
        }
        else
        {
            // If packet wasn't logged when received, log it now
            internal->packet_log[packet_id] = {"sent", timestamp};
        }
    }

    LOG_DEBUG(logger, "Packet with ID {} sent at {}", packet_id, timestamp);

    // Existing code to send the packet...
    std::lock_guard<std::mutex> raw_lock(raw_socket_mutex);

    ssize_t sent = sendto(raw_socket, pkt.data.data(), pkt.length, 0,
                          (struct sockaddr *)&pkt.socket_address, sizeof(pkt.socket_address));
    if (sent == -1)
    {
        LOG_CRITICAL(logger, "Failed to send packet to {}", pkt.dest_ip);
    }
    else
    {
        LOG_INFO(logger, "Forwarded packet to {}, length: {} bytes", pkt.dest_ip, sent);
    }
}