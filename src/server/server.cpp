#include "server.h"
#include <sys/time.h>
#include <queue>

struct PacketData
{
    u_char *packet;
    int length;
};

// Queue to store packets temporarily
std::queue<PacketData> packet_queue;

// Global variable to store the timestamp of the previous packet
struct timeval prev_packet_time = {0, 0};

// Function to send all packets in the queue
void flush_packet_queue(int sock, struct sockaddr_in *dest_addr)
{
    while (!packet_queue.empty())
    {
        PacketData packet_data = packet_queue.front();

        // Send the packet
        if (sendto(sock, packet_data.packet + 14, packet_data.length - 14, 0, (struct sockaddr *)dest_addr, sizeof(*dest_addr)) < 0)
        {
            perror("Sendto error");
        }

        // Clean up and remove the packet from the queue
        delete[] packet_data.packet;
        packet_queue.pop();
    }
}

// Function to calculate the time difference in microseconds
long calculate_time_diff(struct timeval *start, struct timeval *end)
{
    long seconds = end->tv_sec - start->tv_sec;
    long microseconds = end->tv_usec - start->tv_usec;
    return seconds * 1000000 + microseconds;
}

unsigned short calculate_tcp_checksum(struct ip *ip_header, struct tcphdr *tcp_header, unsigned char *payload, int payload_len)
{
    unsigned short *buf;
    unsigned int sum = 0;
    unsigned short tcp_len = ntohs(ip_header->ip_len) - ip_header->ip_hl * 4;

    // Pseudo-header fields
    struct pseudo_header
    {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t placeholder;
        uint8_t protocol;
        uint16_t tcp_length;
    };

    pseudo_header psh;
    psh.src_addr = ip_header->ip_src.s_addr;
    psh.dst_addr = ip_header->ip_dst.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(tcp_len);

    int psize = sizeof(psh) + tcp_len;
    buf = (unsigned short *)malloc(psize);
    memcpy(buf, &psh, sizeof(psh));
    memcpy((unsigned char *)buf + sizeof(psh), tcp_header, tcp_len);

    // Calculate checksum
    for (int i = 0; i < psize / 2; i++)
        sum += buf[i];

    if (psize % 2)
        sum += ((unsigned char *)buf)[psize - 1];

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    free(buf);
    return (unsigned short)(~sum);
}

unsigned short calculate_ip_checksum(unsigned short *buf, int length)
{
    unsigned long sum = 0;
    for (sum = 0; length > 0; length -= 2)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const int ETHERNET_HEADER_SIZE = 14;

    // Make a copy of the packet to modify
    u_char *modified_packet = new u_char[header->len];
    memcpy(modified_packet, packet, header->len);

    // Get the IP header from the copied packet
    struct ip *ip_header = (struct ip *)(modified_packet + ETHERNET_HEADER_SIZE);
    int ip_header_length = ip_header->ip_hl * 4;

    // Check if it's a TCP packet
    if (ip_header->ip_p != IPPROTO_TCP)
    {
        delete[] modified_packet;
        std::cout << "Not a tcp packet!";
        return;
    }

    // Get the TCP header
    struct tcphdr *tcp_header = (struct tcphdr *)(modified_packet + ETHERNET_HEADER_SIZE + ip_header_length);

    // Modify the destination IP address
    const char *new_ip = "192.168.1.100"; // Replace with your desired IP
    inet_pton(AF_INET, new_ip, &(ip_header->ip_dst));

    // Modify the destination port
    const uint16_t new_port = htons(8081); // Replace with your desired port
    tcp_header->th_dport = new_port;

    // Update the total length field in IP header
    ip_header->ip_len = htons(header->len - ETHERNET_HEADER_SIZE);

    // Recalculate IP checksum
    ip_header->ip_sum = 0;
    ip_header->ip_sum = calculate_ip_checksum((unsigned short *)ip_header, ip_header_length);

    // Recalculate TCP checksum
    int tcp_header_length = tcp_header->th_off * 4;
    unsigned char *payload = (unsigned char *)(modified_packet + ETHERNET_HEADER_SIZE + ip_header_length + tcp_header_length);
    int payload_length = header->len - ETHERNET_HEADER_SIZE - ip_header_length - tcp_header_length;

    tcp_header->th_sum = 0;
    tcp_header->th_sum = calculate_tcp_checksum(ip_header, tcp_header, payload, payload_length);

    // Debugging output
    printf("===========================\n");
    int total_packet_size = header->len - ETHERNET_HEADER_SIZE;
    printf("Total packet size: %d\n", total_packet_size);
    printf("IP header length: %d\n", ip_header_length);
    printf("TCP header length: %d\n", tcp_header_length);
    printf("Payload length: %d\n", payload_length);

    // Send the modified packet
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
    {
        perror("Socket error");
        delete[] modified_packet;
        return;
    }

    // Set the IP_HDRINCL option
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        perror("Setsockopt error");
        close(sock);
        delete[] modified_packet;
        return;
    }

    // Prepare destination address structure
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = ip_header->ip_dst;
    // No need to set dest_addr.sin_port when using raw sockets with IP_HDRINCL

    // Send the modified packet
    if (sendto(sock, modified_packet + ETHERNET_HEADER_SIZE, header->len - ETHERNET_HEADER_SIZE, 0,
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
    {
        perror("Sendto error");
    }

    // Clean up
    delete[] modified_packet;
    close(sock);
}
