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

#define MAX_PACKET_SIZE 65536

// Global variables
int raw_socket;
int if_index;
unsigned char src_mac[6];
const char *interface = "enp3s0"; // Replace with your network interface

// Function prototypes
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void setup_raw_socket();

unsigned char *get_mac_address(const char *ip_address)
{
    // Replace with the actual MAC address of 192.168.2.2
    static unsigned char dest_mac[6] = {0x2C, 0xCF, 0x67, 0x03, 0x31, 0xFF};
    return dest_mac;
}

int main()
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the device for packet capture
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, error_buffer);
    if (handle == nullptr)
    {
        std::cerr << "Could not open device " << interface << ": " << error_buffer << std::endl;
        return 1;
    }

    // Compile and apply the filter if needed
    // Example filter: capture all IP packets
    struct bpf_program filter;
    char filter_exp[] = "dst host 192.168.2.2";
    if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        std::cerr << "Bad filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }
    if (pcap_setfilter(handle, &filter) == -1)
    {
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    // Setup raw socket for packet forwarding
    setup_raw_socket();

    // Start packet capture loop
    pcap_loop(handle, 0, packet_handler, nullptr);

    // Cleanup
    pcap_close(handle);
    close(raw_socket);

    return 0;
}

void setup_raw_socket()
{
    // Create a raw socket
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket == -1)
    {
        perror("Failed to create raw socket");
        exit(EXIT_FAILURE);
    }

    // Get the interface index
    struct ifreq ifr
    {
    };
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(raw_socket, SIOCGIFINDEX, &ifr) == -1)
    {
        perror("Failed to get interface index");
        close(raw_socket);
        exit(EXIT_FAILURE);
    }
    if_index = ifr.ifr_ifindex;

    // Get the source MAC address
    if (ioctl(raw_socket, SIOCGIFHWADDR, &ifr) == -1)
    {
        perror("Failed to get MAC address");
        close(raw_socket);
        exit(EXIT_FAILURE);
    }
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // Copy the packet
    unsigned char buffer[MAX_PACKET_SIZE];
    memcpy(buffer, packet, header->len);

    // Parse Ethernet header
    struct ethhdr *eth = (struct ethhdr *)buffer;

    // Only process IP packets
    if (ntohs(eth->h_proto) != ETH_P_IP)
    {
        return;
    }

    // Get the MAC address of 192.168.2.2
    unsigned char *dest_mac = get_mac_address("192.168.2.2");
    if (!dest_mac)
    {
        std::cerr << "Failed to get MAC address for 192.168.2.2" << std::endl;
        return;
    }

    // Update Ethernet header
    memcpy(eth->h_source, src_mac, 6); // Set source MAC to our interface's MAC
    memcpy(eth->h_dest, dest_mac, 6);  // Set destination MAC to 192.168.2.2's MAC

    // Log source and destination IP addresses
    struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct in_addr src_ip_addr, dest_ip_addr;
    src_ip_addr.s_addr = ip_header->saddr;
    dest_ip_addr.s_addr = ip_header->daddr;
    char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(src_ip_addr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(dest_ip_addr), dest_ip, INET_ADDRSTRLEN);

    std::cout << "Captured packet from " << src_ip << " to " << dest_ip << std::endl;

    // Send the packet
    struct sockaddr_ll socket_address
    {
    };
    socket_address.sll_ifindex = if_index;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, dest_mac, 6);

    ssize_t sent = sendto(raw_socket, buffer, header->len, 0, (struct sockaddr *)&socket_address, sizeof(socket_address));
    if (sent == -1)
    {
        perror("Failed to send packet");
    }
    else
    {
        std::cout << "Forwarded packet of length " << sent << " bytes" << std::endl;
    }
}
