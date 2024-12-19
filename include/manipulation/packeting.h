#ifndef PACKETING_H
#define PACKETING_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>
#include "server.h"

#define MIN_PAYLOAD_SIZE 1

struct PacketInfo
{
    size_t offset;
    size_t size;
};

std::vector<size_t> split_payload_randomly(size_t total_payload_size, size_t min_size = 1);
std::vector<PacketInfo> create_packet_info(const std::vector<size_t> &chunk_sizes);

void reorder_packets(std::vector<PacketInfo> &packets_info);

Server::PacketData build_packet(const Server::PacketData &original_packet,
                                const std::vector<uint8_t> &payload_buffer,
                                size_t payload_offset,
                                size_t chunk_size,
                                uint32_t seq_offset);

#endif // PACKETING_H
