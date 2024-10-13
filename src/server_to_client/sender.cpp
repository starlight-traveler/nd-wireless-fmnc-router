#include "sender.h"

void send_queued_packets(Server::Data *internal)
{
    for (const auto &pkt : internal->packet_queue)
    {
        send_packet(pkt, internal->logger);
    }
    // Clear the queue and reset total payload length
    internal->packet_queue.clear();
    internal->total_payload_length = 0;
}

void send_packet(const Server::PacketData &pkt, quill::Logger *logger)
{
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