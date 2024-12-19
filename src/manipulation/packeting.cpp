#include "packeting.h"
#include "utilities.h"
#include "server.h"
#include <random>
#include <algorithm>
#include <cstring>
#include "logger.h"

std::vector<size_t> split_payload_randomly(size_t total_payload_size, size_t min_size)
{
    // Decide how many packets to send
    size_t num_packets = total_payload_size / min_size + 1;
    std::vector<size_t> chunk_sizes(num_packets, 0);

    if (num_packets == 0)
    {
        return chunk_sizes;
    }

    std::random_device rd;
    std::mt19937 gen(rd());

    size_t remaining_size = total_payload_size;
    for (size_t i = 0; i < num_packets - 1; ++i)
    {
        size_t max_size = remaining_size - min_size * (num_packets - i - 1);
        std::uniform_int_distribution<size_t> dis(min_size, max_size);
        size_t chunk_size = dis(gen);
        chunk_sizes[i] = chunk_size;
        remaining_size -= chunk_size;
    }
    // Last chunk gets the remaining size
    chunk_sizes[num_packets - 1] = remaining_size;
    return chunk_sizes;
}

std::vector<PacketInfo> create_packet_info(const std::vector<size_t> &chunk_sizes)
{
    std::vector<PacketInfo> packets_info;
    packets_info.reserve(chunk_sizes.size());

    size_t offset = 0;
    for (auto csize : chunk_sizes)
    {
        packets_info.push_back({offset, csize});
        offset += csize;
    }

    return packets_info;
}

void reorder_packets(std::vector<PacketInfo> &packets_info)
{
    if (packets_info.size() > 1)
    {
        // Reverse the entire order of packets
        std::reverse(packets_info.begin(), packets_info.end());
    }
}

Server::PacketData build_packet(const Server::PacketData &original_packet,
                                const std::vector<uint8_t> &payload_buffer,
                                size_t payload_offset,
                                size_t chunk_size,
                                uint32_t seq_offset)
{
    // Determine header lengths
    struct iphdr *orig_ip_header = (struct iphdr *)(original_packet.data.data() + sizeof(struct ethhdr));
    size_t orig_ip_header_length = orig_ip_header->ihl * 4;
    struct tcphdr *orig_tcp_header = (struct tcphdr *)(original_packet.data.data() + sizeof(struct ethhdr) + orig_ip_header_length);
    size_t orig_tcp_header_length = orig_tcp_header->doff * 4;

    size_t total_header_length = sizeof(struct ethhdr) + orig_ip_header_length + orig_tcp_header_length;

    // Create new packet data
    Server::PacketData new_packet;
    new_packet.length = total_header_length + chunk_size;
    new_packet.data.resize(new_packet.length);

    // Copy Ethernet header
    memcpy(new_packet.data.data(), original_packet.data.data(), sizeof(struct ethhdr));

    // Copy IP header
    memcpy(new_packet.data.data() + sizeof(struct ethhdr),
           original_packet.data.data() + sizeof(struct ethhdr),
           orig_ip_header_length);

    // Copy TCP header
    memcpy(new_packet.data.data() + sizeof(struct ethhdr) + orig_ip_header_length,
           original_packet.data.data() + sizeof(struct ethhdr) + orig_ip_header_length,
           orig_tcp_header_length);

    // Copy payload
    memcpy(new_packet.data.data() + total_header_length,
           payload_buffer.data() + payload_offset,
           chunk_size);

    // Update IP total length
    struct iphdr *ip_header = (struct iphdr *)(new_packet.data.data() + sizeof(struct ethhdr));
    ip_header->tot_len = htons(new_packet.length - sizeof(struct ethhdr));

    // Update TCP header
    struct tcphdr *tcp_header = (struct tcphdr *)(new_packet.data.data() + sizeof(struct ethhdr) + orig_ip_header_length);
    tcp_header->seq = htonl(seq_offset);

    // Zero out TCP options if necessary
    if (tcp_header->doff > 5)
    {
        uint8_t *options_start = (uint8_t *)tcp_header + sizeof(struct tcphdr);
        size_t options_length = (tcp_header->doff * 4) - sizeof(struct tcphdr);
        memset(options_start, 0, options_length);
        tcp_header->doff = 5;
    }

    // Compute checksums
    compute_ip_checksum(ip_header);
    compute_tcp_checksum(ip_header, tcp_header);

    // Copy socket_address and destination info
    new_packet.socket_address = original_packet.socket_address;
    strcpy(new_packet.dest_ip, original_packet.dest_ip);
    memcpy(new_packet.dest_mac, original_packet.dest_mac, 6);

    return new_packet;
}
