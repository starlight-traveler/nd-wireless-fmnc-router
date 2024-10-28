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
