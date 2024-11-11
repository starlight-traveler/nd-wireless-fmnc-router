#ifndef UTILITIES
#define UTILITIES

#include "general.h"

std::string generate_packet_id(const struct iphdr *ip_header, const struct tcphdr *tcp_header);
std::string get_current_timestamp();
void compute_ip_checksum(struct iphdr *ip_header);
void compute_tcp_checksum(struct iphdr *ip_header, struct tcphdr *tcp_header);

#endif