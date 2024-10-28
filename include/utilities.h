#ifndef UTILITIES
#define UTILITIES

#include "general.h"

std::string generate_packet_id(const struct iphdr *ip_header, const struct tcphdr *tcp_header);
std::string get_current_timestamp();

#endif