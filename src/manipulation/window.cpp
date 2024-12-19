#include "window.h"
#include "server.h"
#include "utilities.h"
#include "packeting.h"
#include "timing.h"
#include <mutex>
#include <chrono>
#include "logger.h"

void window(std::shared_ptr<Server::Data> internal, const Server::PacketData &original_packet)
{
    TimingInfo timing;
    start_timing(timing);

    // Copy the TCP/IP headers from 'original_packet'
    size_t ip_header_length = 0;
    size_t tcp_header_length = 0;
    {
        struct iphdr *ip_header = (struct iphdr *)(original_packet.data.data() + sizeof(struct ethhdr));
        ip_header_length = ip_header->ihl * 4;
        struct tcphdr *tcp_header = (struct tcphdr *)(original_packet.data.data() + sizeof(struct ethhdr) + ip_header_length);
        tcp_header_length = tcp_header->doff * 4;
    }

    size_t total_header_length = sizeof(struct ethhdr) + ip_header_length + tcp_header_length;

    // Lock the payload buffer
    LOG_DEBUG(internal->logger, "Locking payload buffer mutex");
    std::lock_guard<std::mutex> lock(internal->payload_buffer_mutex);

    // Get the total payload size
    size_t total_payload_size = internal->payload_buffer.size();
    LOG_DEBUG(internal->logger, "Total payload size: {}", total_payload_size);

    // Split the payload into packets
    LOG_DEBUG(internal->logger, "Splitting payload into packets");
    std::vector<size_t> chunk_sizes = split_payload_randomly(total_payload_size, MIN_PAYLOAD_SIZE);

    // Get the original TCP sequence number
    struct iphdr *orig_ip_header = (struct iphdr *)(original_packet.data.data() + sizeof(struct ethhdr));
    size_t orig_ip_header_length = orig_ip_header->ihl * 4;
    struct tcphdr *orig_tcp_header = (struct tcphdr *)(original_packet.data.data() + sizeof(struct ethhdr) + orig_ip_header_length);
    uint32_t orig_seq = ntohl(orig_tcp_header->seq);

    // Create packet info
    LOG_DEBUG(internal->logger, "Creating packet info structures");
    auto packets_info = create_packet_info(chunk_sizes);

    // Reorder packets
    LOG_DEBUG(internal->logger, "Reordering packets");
    reorder_packets(packets_info);

    // Send packets
    LOG_DEBUG(internal->logger, "Sending packets in final order");
    uint32_t current_seq = orig_seq;
    size_t payload_offset = 0;

    for (size_t i = 0; i < packets_info.size(); ++i)
    {
        const auto &pkt = packets_info[i];
        LOG_DEBUG(internal->logger, "Building packet {} with payload offset: {}, size: {}", i, pkt.offset, pkt.size);

        // The sequence number should be the original + the current offset
        uint32_t seq_number = current_seq;
        current_seq += (uint32_t)pkt.size;

        auto new_packet = build_packet(original_packet, internal->payload_buffer, pkt.offset, pkt.size, seq_number);

        LOG_DEBUG(internal->logger, "Sending packet {} with seq: {}", i, seq_number);
        send_packet(new_packet, internal->logger, internal);

        // Add a small delay between packets to simulate timing
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Clear the payload buffer after sending all packets
    LOG_DEBUG(internal->logger, "Clearing payload buffer");
    internal->payload_buffer.clear();

    end_timing(timing);
    LOG_DEBUG(internal->logger, "Finished processing window()");
}
