#ifndef GENERAL
#define GENERAL

#include <pcap.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <iostream>
#include <sys/socket.h>
#include <netinet/ip.h>      // For iphdr
#include <netinet/tcp.h>     // For tcphdr
#include <netinet/udp.h>     // For udphdr
#include <netinet/ip_icmp.h> // For icmphdr
#include <net/ethernet.h>    // For Ethernet header
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <thread>
#include <net/if_arp.h>
#include <mutex>
#include <unordered_map>
#include <array>
#include <csignal>

#include "threading.tpp"

#define MAX_PACKET_SIZE 65536

void setup_raw_socket();
unsigned char *get_mac_address(const char *ip_address);

void packet_handler_to_192_168_2_2(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void packet_handler_from_192_168_2_2(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

// Global variables
inline int raw_socket;
inline int if_index;
inline unsigned char src_mac[6];
inline const char *interface = "enp3s0";
inline std::mutex raw_socket_mutex;

#endif
