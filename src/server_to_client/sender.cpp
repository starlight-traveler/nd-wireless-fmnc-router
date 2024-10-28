// sender.cpp

#include "sender.h"
#include <algorithm> // For std::shuffle
#include <random>    // For random number generator
#include <mutex>
#include "logger.h"

// External variables (Assumed to be defined elsewhere)
extern int raw_socket;
extern std::mutex raw_socket_mutex;

// Function to shuffle and send queued packets
void send_queued_packets(std::shared_ptr<Server::Data> internal)
{
    // Create a random number generator
    std::random_device rd;
    std::mt19937 g(rd());

    // Lock the queue to safely access and modify it
    {
        std::lock_guard<std::mutex> lock(internal->queue_mutex);

        if (internal->packet_queue.empty())
        {
            LOG_DEBUG(internal->logger, "Packet queue is empty. Nothing to send.");
            return;
        }

        // Shuffle the packet queue to send packets out of order
        std::shuffle(internal->packet_queue.begin(), internal->packet_queue.end(), g);

        // Iterate over the shuffled packets and send each one
        for (const auto &pkt : internal->packet_queue)
        {
            send_packet(pkt, internal->logger);
        }

        // Clear the queue and reset total payload length
        internal->packet_queue.clear();
        internal->total_payload_length = 0;

        LOG_INFO(internal->logger, "All queued packets have been sent and the queue is now cleared.");
    }
}

// Function to send a single packet
void send_packet(const Server::PacketData &pkt, quill::Logger *logger)
{
    // Lock the raw socket mutex to ensure thread-safe access
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
