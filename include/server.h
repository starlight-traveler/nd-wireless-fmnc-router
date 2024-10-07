#ifndef SERVER
#define SERVER

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <thread>
#include <cstring>
#include <iostream>
#include <unistd.h> // For close
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include "client.h"

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void server(int src_fd, int dest_fd);

#endif
