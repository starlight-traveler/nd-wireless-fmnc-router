#include "server.h"
#include "logger.h"
#include <cstring>

#define MAX_PACKET_SIZE 65536    // Maximum packet size
#define MAX_PAYLOAD_SIZE 1000000 // 1 MB

// Adjusted function signature
void packet_handler_from(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

void capture_packets_from(quill::Logger *logger)
{
    // Initialize Server::Configuration with zeroed timestamp and payload length
    Server::Configuration conf = {};
    conf.logger = logger;
    conf.prev_timestamp.tv_sec = 0;
    conf.prev_timestamp.tv_usec = 0;
    conf.total_payload_length = 0;

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the device for packet capture with a timeout of 1 ms
    handle = pcap_open_live(interface, BUFSIZ, 1, 1, error_buffer);
    if (handle == nullptr)
    {
        LOG_ERROR(logger, "Could not open device {}: {}", interface, error_buffer);
        return;
    }

    // Compile and apply the filter with MAC exclusion
    if (!apply_filter(handle, logger))
    {
        pcap_close(handle);
        return;
    }

    // Start packet capture loop
    pcap_loop(handle, 0, packet_handler_from, (u_char *)&conf);

    // Cleanup
    pcap_close(handle);
}

bool apply_filter(pcap_t *handle, quill::Logger *logger)
{
    struct bpf_program filter;
    char filter_exp_from[150];
    snprintf(filter_exp_from, sizeof(filter_exp_from),
             "src host 192.168.2.2 and not ether src %02x:%02x:%02x:%02x:%02x:%02x",
             src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);

    if (pcap_compile(handle, &filter, filter_exp_from, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        LOG_ERROR(logger, "Bad filter: {}", pcap_geterr(handle));
        return false;
    }
    if (pcap_setfilter(handle, &filter) == -1)
    {
        LOG_ERROR(logger, "Error setting filter: {}", pcap_geterr(handle));
        return false;
    }

    LOG_INFO(logger, "Successfully applied packet filter: {}", filter_exp_from);
    return true;
}

long compute_time_difference(const struct timeval &prev, const struct timeval &curr)
{
    return (curr.tv_sec - prev.tv_sec) * 1000000 + (curr.tv_usec - prev.tv_usec);
}

void packet_handler_from(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    // Cast user parameter back to Server::Configuration
    Server::Configuration *args = (Server::Configuration *)user;

    // Lock the queue mutex
    std::lock_guard<std::mutex> lock(args->queue_mutex);

    // Get current timestamp
    struct timeval curr_timestamp = header->ts;

    // Compute time difference in microseconds
    long time_diff_us = compute_time_difference(args->prev_timestamp, curr_timestamp);

    // If prev_timestamp is zero, this is the first packet
    if (args->prev_timestamp.tv_sec == 0 && args->prev_timestamp.tv_usec == 0)
    {
        time_diff_us = 0;
    }

    // If time difference > 1000 microseconds (1 ms), send all queued packets
    if (time_diff_us > 1000)
    {
        send_queued_packets(args);
    }

    // Update prev_timestamp
    args->prev_timestamp = curr_timestamp;

    // Add the packet to the queue
    queue_packet(args, header, packet);

    // Check if total_payload_length exceeds MAX_PAYLOAD_SIZE
    if (args->total_payload_length > MAX_PAYLOAD_SIZE)
    {
        send_queued_packets(args);
    }
}

void send_queued_packets(Server::Configuration *args)
{
    for (const auto &pkt : args->packet_queue)
    {
        send_packet(pkt, args->logger);
    }
    // Clear the queue and reset total payload length
    args->packet_queue.clear();
    args->total_payload_length = 0;
}

void send_packet(const Server::PacketData &pkt, quill::Logger *logger)
{
    std::lock_guard<std::mutex> raw_lock(raw_socket_mutex);
    ssize_t sent = sendto(raw_socket, pkt.data.data(), pkt.length, 0,
                          (struct sockaddr *)&pkt.socket_address, sizeof(pkt.socket_address));
    if (sent == -1)
    {
        LOG_CRITICAL(logger, "Failed to send packet to {}", pkt.dest_ip);
    }
    else
    {
        LOG_INFO(logger, "Forwarded packet to {}, length: {} bytes", pkt.dest_ip, sent);
    }
}

void queue_packet(Server::Configuration *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // Copy the packet data
    Server::PacketData packet_data;
    packet_data.length = header->len;
    packet_data.data.resize(header->len);
    memcpy(packet_data.data.data(), packet, header->len);

    // Parse Ethernet header
    struct ethhdr *eth = (struct ethhdr *)packet_data.data.data();

    // Only process IP packets
    if (ntohs(eth->h_proto) != ETH_P_IP)
    {
        return;
    }

    // Get IP header
    struct iphdr *ip_header = (struct iphdr *)(packet_data.data.data() + sizeof(struct ethhdr));

    // Get destination IP address
    struct in_addr dest_ip_addr;
    dest_ip_addr.s_addr = ip_header->daddr;
    inet_ntop(AF_INET, &(dest_ip_addr), packet_data.dest_ip, INET_ADDRSTRLEN);

    // Get the MAC address of the destination IP
    unsigned char *dest_mac = get_mac_address(packet_data.dest_ip, args->logger);
    if (!dest_mac)
    {
        LOG_CRITICAL(args->logger, "Failed to get MAC address for {}", packet_data.dest_ip);
        return;
    }

    // Update Ethernet header
    memcpy(eth->h_source, src_mac, 6); // Set source MAC to our interface's MAC
    memcpy(eth->h_dest, dest_mac, 6);  // Set destination MAC to destination IP's MAC

    // Prepare socket_address for sending
    packet_data.socket_address = {};
    packet_data.socket_address.sll_ifindex = if_index;
    packet_data.socket_address.sll_halen = ETH_ALEN;
    memcpy(packet_data.socket_address.sll_addr, dest_mac, 6);

    // Add packet to queue
    args->packet_queue.push_back(std::move(packet_data));

    // Update total_payload_length
    args->total_payload_length += header->len;

    LOG_DEBUG(args->logger, "Queued packet to {}, length: {} bytes, total queued payload: {} bytes",
              packet_data.dest_ip, header->len, args->total_payload_length);
}