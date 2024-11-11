#include "utilities.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <chrono>

// Function to generate a unique packet ID
std::string generate_packet_id(const struct iphdr *ip_header, const struct tcphdr *tcp_header)
{
    std::ostringstream oss;
    oss << ip_header->saddr << ":" << ntohs(tcp_header->source)
        << "->" << ip_header->daddr << ":" << ntohs(tcp_header->dest)
        << ":" << ntohl(tcp_header->seq);
    return oss.str();
}

// Function to get the current timestamp as a string
std::string get_current_timestamp()
{
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    struct tm buf;
    localtime_r(&in_time_t, &buf);

    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &buf);

    return std::string(time_str);
}

// Function to compute IP checksum
void compute_ip_checksum(struct iphdr *ip_header)
{
    ip_header->check = 0;
    uint16_t *header = (uint16_t *)ip_header;
    uint32_t checksum = 0;
    for (int i = 0; i < (ip_header->ihl * 2); i++)
    {
        checksum += ntohs(header[i]);
    }
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum = ~checksum & 0xFFFF;
    ip_header->check = htons((uint16_t)checksum);
}

// Function to compute TCP checksum
void compute_tcp_checksum(struct iphdr *ip_header, struct tcphdr *tcp_header)
{
    uint16_t *tcp_segment;
    uint32_t checksum = 0;
    uint16_t tcp_length = ntohs(ip_header->tot_len) - ip_header->ihl * 4;

    // Pseudo-header fields
    struct
    {
        uint32_t src_addr;
        uint32_t dest_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_length;
    } pseudo_header;

    pseudo_header.src_addr = ip_header->saddr;
    pseudo_header.dest_addr = ip_header->daddr;
    pseudo_header.zero = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(tcp_length);

    // Calculate checksum over pseudo-header
    uint16_t *pseudo_header_ptr = (uint16_t *)&pseudo_header;
    for (int i = 0; i < sizeof(pseudo_header) / 2; i++)
    {
        checksum += ntohs(pseudo_header_ptr[i]);
    }

    // Calculate checksum over TCP header and data
    tcp_segment = (uint16_t *)tcp_header;
    for (int i = 0; i < (tcp_length / 2); i++)
    {
        checksum += ntohs(tcp_segment[i]);
    }

    if (tcp_length % 2)
    {
        // Add padding if length is odd
        checksum += ntohs(((uint8_t *)tcp_segment)[tcp_length - 1] << 8);
    }

    // Finalize checksum
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum = ~checksum & 0xFFFF;
    tcp_header->th_sum = htons((uint16_t)checksum);
}
