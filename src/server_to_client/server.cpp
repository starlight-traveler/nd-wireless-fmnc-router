#include "server.h"

void capture_packets_from_192_168_2_2(quill::Logger *logger)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the device for packet capture
    handle = pcap_open_live(interface, BUFSIZ, 1, 50, error_buffer);
    if (handle == nullptr)
    {
        std::cerr << "Could not open device " << interface << ": " << error_buffer << std::endl;
        return;
    }

    // Compile and apply the filter with MAC exclusion
    struct bpf_program filter;
    char filter_exp_from[150];
    snprintf(filter_exp_from, sizeof(filter_exp_from),
             "src host 192.168.2.2 and not ether src %02x:%02x:%02x:%02x:%02x:%02x",
             src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);

    if (pcap_compile(handle, &filter, filter_exp_from, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        std::cerr << "Bad filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }
    if (pcap_setfilter(handle, &filter) == -1)
    {
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }

    // Start packet capture loop
    pcap_loop(handle, 0, packet_handler_from_192_168_2_2, nullptr);

    // Cleanup
    pcap_close(handle);
}

void packet_handler_from_192_168_2_2(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
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

    // Get IP header
    struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    // Get destination IP address
    struct in_addr dest_ip_addr;
    dest_ip_addr.s_addr = ip_header->daddr;
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(dest_ip_addr), dest_ip, INET_ADDRSTRLEN);

    // Get the MAC address of the destination IP
    unsigned char *dest_mac = get_mac_address(dest_ip);
    if (!dest_mac)
    {
        std::cerr << "Failed to get MAC address for " << dest_ip << std::endl;
        return;
    }

    // Update Ethernet header
    memcpy(eth->h_source, src_mac, 6); // Set source MAC to our interface's MAC
    memcpy(eth->h_dest, dest_mac, 6);  // Set destination MAC to destination IP's MAC

    // Send the packet
    struct sockaddr_ll socket_address
    {
    };

    socket_address.sll_ifindex = if_index;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, dest_mac, 6);

    {
        std::lock_guard<std::mutex> lock(raw_socket_mutex);
        ssize_t sent = sendto(raw_socket, buffer, header->len, 0, (struct sockaddr *)&socket_address, sizeof(socket_address));
        if (sent == -1)
        {
            perror("Failed to send packet");
        }
        else
        {
            std::cout << "Forwarded packet from 192.168.2.2 to " << dest_ip << ", length: " << sent << " bytes" << std::endl;
        }
    }
}
