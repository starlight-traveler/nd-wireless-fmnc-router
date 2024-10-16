#include "client.h"

// Adjusted function signature
void packet_handler_to(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

void capture_packets_to(quill::Logger *logger)
{
    
    // Use a single instance of Client::Configuration
    Client::Configuration conf = {logger};

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the device for packet capture
    handle = pcap_open_live(interface, BUFSIZ, 1, 50, error_buffer);
    if (handle == nullptr)
    {
        LOG_ERROR(logger, "Could not open device {}: {}", interface, error_buffer);
        return;
    }

    // Compile and apply the filter with MAC exclusion
    struct bpf_program filter;
    char filter_exp_to[150];
    snprintf(filter_exp_to, sizeof(filter_exp_to),
             "dst host 192.168.2.2 and not ether src %02x:%02x:%02x:%02x:%02x:%02x",
             src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);

    if (pcap_compile(handle, &filter, filter_exp_to, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        LOG_ERROR(logger, "Bad filter: {}", pcap_geterr(handle));
        pcap_close(handle);
        return;
    }
    if (pcap_setfilter(handle, &filter) == -1)
    {
        LOG_ERROR(logger, "Error setting filter: {}", pcap_geterr(handle));
        pcap_close(handle);
        return;
    }

    // Start packet capture loop
    pcap_loop(handle, 0, packet_handler_to, (u_char *)&conf);

    // Cleanup
    pcap_close(handle);
}

void packet_handler_to(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    // Cast user parameter back to Client::Configuration
    Client::Configuration *args = (Client::Configuration *)user;

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
    unsigned char *dest_mac = get_mac_address("192.168.2.2", args->logger);
    if (!dest_mac)
    {
        LOG_CRITICAL(args->logger, "Failed to get MAC address for 192.168.2.2");
        return;
    }

    // Update Ethernet header
    memcpy(eth->h_source, src_mac, 6); // Set source MAC to our interface's MAC
    memcpy(eth->h_dest, dest_mac, 6);  // Set destination MAC to 192.168.2.2's MAC

    // Send the packet
    struct sockaddr_ll socket_address = {};
    socket_address.sll_ifindex = if_index;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, dest_mac, 6);

    {
        std::lock_guard<std::mutex> lock(raw_socket_mutex);
        ssize_t sent = sendto(raw_socket, buffer, header->len, 0, (struct sockaddr *)&socket_address, sizeof(socket_address));
        if (sent == -1)
        {
            LOG_CRITICAL(args->logger, "Failed to send packet");
        }
        else
        {
            LOG_DEBUG(args->logger, "Forwarded packet, length: {} bytes", sent);
        }
    }
}
