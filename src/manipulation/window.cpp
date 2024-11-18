// In a new file, e.g., packet_sender.cpp

#include "window.h"
#include "server.h"
#include "utilities.h" // For checksum functions
#include <random>

// Define a minimum payload size for new packets
#define MIN_PAYLOAD_SIZE 1


void window(std::shared_ptr<Server::Data> internal, const Server::PacketData &original_packet)
{
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
    std::lock_guard<std::mutex> lock(internal->payload_buffer_mutex);

    // Get the total payload size
    size_t total_payload_size = internal->payload_buffer.size();

    // Decide how many packets to send (send more than we received)
    size_t num_packets = total_payload_size / MIN_PAYLOAD_SIZE + 1;

    // Split the payload buffer into 'num_packets' chunks with random sizes
    std::vector<size_t> chunk_sizes(num_packets, 0);

    // Use random number generator
    std::random_device rd;
    std::mt19937 gen(rd());

    size_t remaining_size = total_payload_size;
    for (size_t i = 0; i < num_packets - 1; ++i)
    {
        // Generate a random size between MIN_PAYLOAD_SIZE and remaining_size / (num_packets - i)
        size_t max_size = remaining_size - MIN_PAYLOAD_SIZE * (num_packets - i - 1);
        std::uniform_int_distribution<size_t> dis(MIN_PAYLOAD_SIZE, max_size);

        size_t chunk_size = dis(gen);
        chunk_sizes[i] = chunk_size;
        remaining_size -= chunk_size;
    }
    // Last chunk gets the remaining size
    chunk_sizes[num_packets - 1] = remaining_size;

    // Get the original TCP sequence number
    struct iphdr *orig_ip_header = (struct iphdr *)(original_packet.data.data() + sizeof(struct ethhdr));
    size_t orig_ip_header_length = orig_ip_header->ihl * 4;
    struct tcphdr *orig_tcp_header = (struct tcphdr *)(original_packet.data.data() + sizeof(struct ethhdr) + orig_ip_header_length);

    uint32_t orig_seq = ntohl(orig_tcp_header->seq);

    // Now construct and send the new packets
    size_t payload_offset = 0;
    uint32_t seq_offset = 0;
    for (size_t i = 0; i < num_packets; ++i)
    {
        size_t chunk_size = chunk_sizes[i];

        // Create new packet data
        Server::PacketData new_packet;
        new_packet.length = total_header_length + chunk_size;
        new_packet.data.resize(new_packet.length);

        // Copy Ethernet header
        memcpy(new_packet.data.data(), original_packet.data.data(), sizeof(struct ethhdr));

        // Copy IP header
        memcpy(new_packet.data.data() + sizeof(struct ethhdr),
               original_packet.data.data() + sizeof(struct ethhdr),
               ip_header_length);

        // Copy TCP header
        memcpy(new_packet.data.data() + sizeof(struct ethhdr) + ip_header_length,
               original_packet.data.data() + sizeof(struct ethhdr) + ip_header_length,
               tcp_header_length);

        // Copy payload
        memcpy(new_packet.data.data() + total_header_length,
               internal->payload_buffer.data() + payload_offset,
               chunk_size);

        // Update payload offset
        payload_offset += chunk_size;

        // Update IP header (total length)
        struct iphdr *ip_header = (struct iphdr *)(new_packet.data.data() + sizeof(struct ethhdr));
        ip_header->tot_len = htons(new_packet.length - sizeof(struct ethhdr)); // Total length excluding Ethernet header

        // Update TCP header (sequence number)
        struct tcphdr *tcp_header = (struct tcphdr *)(new_packet.data.data() + sizeof(struct ethhdr) + ip_header_length);
        tcp_header->seq = htonl(orig_seq + seq_offset);

        // Update sequence offset for the next packet
        seq_offset += chunk_size;

        // Compute IP checksum using your existing function
        compute_ip_checksum(ip_header);

        // Compute TCP checksum using your existing function
        compute_tcp_checksum(ip_header, tcp_header);

        // Copy socket_address and destination info
        new_packet.socket_address = original_packet.socket_address;
        strcpy(new_packet.dest_ip, original_packet.dest_ip);
        memcpy(new_packet.dest_mac, original_packet.dest_mac, 6);

        // Send the packet
        send_packet(new_packet, internal->logger, internal);

        // Wait for specified time interval (e.g., 10ms)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Clear the payload buffer
    internal->payload_buffer.clear();
}
