#include "server.h"
#include "logger.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <chrono>
#include "utilities.h"

#define MAX_PACKET_SIZE 65536    // Maximum packet size
#define MAX_PAYLOAD_SIZE 1000000 // 1 MB

void capture_packets_from(std::shared_ptr<Server::Data> internal, quill::Logger *logger, ConfigManager &config)
{

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
    pcap_loop(handle, 0, packet_handler_from, reinterpret_cast<u_char *>(&internal));

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

// Modified packet handler
// Global or within your Server::Data class
std::mutex queue_mutex;
std::condition_variable cv;
bool exit_timer_thread = false;

// Timer thread function
void timer_thread(std::shared_ptr<Server::Data> internal)
{
    while (!exit_timer_thread)
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        cv.wait_for(lock, std::chrono::microseconds(1000), []
                    { return exit_timer_thread; });

        // Get current time
        struct timeval curr_time;
        gettimeofday(&curr_time, NULL);

        // Compute time difference in microseconds
        long time_diff_us = compute_time_difference(internal->last_send_timestamp, curr_time);

        if (time_diff_us >= 1000)
        {
            // Send queued packets
            send_queued_packets(internal);
            // Update last_send_timestamp
            internal->last_send_timestamp = curr_time;
        }
    }
}

// Modify your packet handler
void packet_handler_from(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    // Existing code to retrieve internal pointer
    std::shared_ptr<Server::Data> *internal_ptr = reinterpret_cast<std::shared_ptr<Server::Data> *>(user);
    if (!internal_ptr || !*internal_ptr)
    {
        std::cout << "Internal pointer failure";
        return;
    }
    std::shared_ptr<Server::Data> internal = *internal_ptr;

    // Lock the queue mutex
    std::lock_guard<std::mutex> lock(queue_mutex);

    // Add the packet to the queue
    queue_packet(internal, header, packet);

}

// // When starting your application, start the timer thread
// std::thread timer(timer_thread, internal);

std::vector<std::string> get_tcp_flag_names(uint8_t flags)
{
    static const std::unordered_map<uint8_t, std::string> tcp_flag_names = {
        {0x01, "FIN"},
        {0x02, "SYN"},
        {0x04, "RST"},
        {0x08, "PSH"},
        {0x10, "ACK"},
        {0x20, "URG"},
        {0x40, "ECE"},
        {0x80, "CWR"},
    };

    std::vector<std::string> flag_names;
    for (const auto &kv : tcp_flag_names)
    {
        if (flags & kv.first)
        {
            flag_names.push_back(kv.second);
        }
    }
    return flag_names;
}

// Helper function to copy packet data
void copy_packet_data(Server::PacketData &packet_data, const struct pcap_pkthdr *header, const u_char *packet, quill::Logger *logger)
{
    packet_data.length = header->len;
    packet_data.data.resize(header->len);
    memcpy(packet_data.data.data(), packet, header->len);
    LOG_DEBUG(logger, "Packet data copied, length: {}", packet_data.length);
}

// Helper function to parse Ethernet header
struct ethhdr *parse_ethernet_header(Server::PacketData &packet_data, quill::Logger *logger)
{
    struct ethhdr *eth = (struct ethhdr *)packet_data.data.data();
    LOG_DEBUG(logger, "Parsed Ethernet header, protocol: 0x{:04x}", ntohs(eth->h_proto));
    return eth;
}

// Helper function to check if the packet is IP
bool is_ip_packet(struct ethhdr *eth, quill::Logger *logger)
{
    if (ntohs(eth->h_proto) != ETH_P_IP)
    {
        LOG_DEBUG(logger, "Non-IP packet received, protocol: 0x{:04x}", ntohs(eth->h_proto));
        return false;
    }
    LOG_DEBUG(logger, "IP packet received");
    return true;
}

// Helper function to parse IP header
struct iphdr *parse_ip_header(Server::PacketData &packet_data, quill::Logger *logger)
{
    struct iphdr *ip_header = (struct iphdr *)(packet_data.data.data() + sizeof(struct ethhdr));
    char src_ip_str[INET_ADDRSTRLEN];
    char dest_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->saddr), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dest_ip_str, INET_ADDRSTRLEN);
    LOG_DEBUG(logger, "Parsed IP header, source IP: {}, destination IP: {}, protocol: {}",
              src_ip_str, dest_ip_str, ip_header->protocol);
    return ip_header;
}

// Helper function to get destination IP address
bool get_destination_ip(struct iphdr *ip_header, Server::PacketData &packet_data, quill::Logger *logger)
{
    struct in_addr dest_ip_addr;
    dest_ip_addr.s_addr = ip_header->daddr;
    if (inet_ntop(AF_INET, &(dest_ip_addr), packet_data.dest_ip, INET_ADDRSTRLEN) == nullptr)
    {
        LOG_ERROR(logger, "Failed to convert destination IP address");
        return false;
    }
    LOG_DEBUG(logger, "Destination IP address: {}", packet_data.dest_ip);
    return true;
}

// Helper function to get destination MAC address
bool get_destination_mac(Server::PacketData &packet_data, quill::Logger *logger)
{
    unsigned char *dest_mac = get_mac_address(packet_data.dest_ip, logger);
    if (!dest_mac)
    {
        LOG_CRITICAL(logger, "Failed to get MAC address for {}", packet_data.dest_ip);
        return false;
    }
    memcpy(packet_data.dest_mac, dest_mac, 6);
    LOG_DEBUG(logger, "Destination MAC address obtained: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
              dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);
    return true;
}

// Helper function to update Ethernet header
void update_ethernet_header(struct ethhdr *eth, Server::PacketData &packet_data, quill::Logger *logger)
{
    memcpy(eth->h_source, src_mac, 6);
    memcpy(eth->h_dest, packet_data.dest_mac, 6);
    LOG_DEBUG(logger, "Ethernet header updated");
}

// Helper function to prepare socket address
void prepare_socket_address(Server::PacketData &packet_data)
{
    packet_data.socket_address = {};
    packet_data.socket_address.sll_ifindex = if_index;
    packet_data.socket_address.sll_halen = ETH_ALEN;
    memcpy(packet_data.socket_address.sll_addr, packet_data.dest_mac, 6);
}

// Helper function to process TCP flags
void process_tcp_flags(std::shared_ptr<Server::Data> internal, uint8_t tcp_flags)
{
    std::vector<std::string> flag_names = get_tcp_flag_names(tcp_flags);

    {
        std::lock_guard<std::mutex> lock(internal->flags_mutex);
        for (const auto &flag_name : flag_names)
        {
            internal->tcp_flag_counts[flag_name]++;
            LOG_DEBUG(internal->logger, "Incremented count for TCP flag {}: total count now {}", flag_name, internal->tcp_flag_counts[flag_name]);
        }
    }
}

// Helper function to process TCP options
void process_tcp_options(std::shared_ptr<Server::Data> internal, u_char *options, int tcp_options_length, std::vector<int> &option_kinds)
{
    int parsed_length = 0;
    while (parsed_length < tcp_options_length)
    {
        u_char kind = options[parsed_length];
        option_kinds.push_back(kind); // Store the option kind
        LOG_DEBUG(internal->logger, "Parsing TCP option at position {}, kind: {}", parsed_length, (int)kind);

        if (kind == 0)
        {
            // End of options list
            LOG_DEBUG(internal->logger, "End of TCP options list");
            parsed_length++;
            break;
        }
        else if (kind == 1)
        {
            // No-Operation (NOP), 1 byte
            LOG_DEBUG(internal->logger, "TCP No-Operation (NOP) option encountered");
            parsed_length++;
            continue;
        }
        else
        {
            // Other options with kind and length
            if (parsed_length + 1 >= tcp_options_length)
            {
                // Malformed option: not enough bytes for length
                LOG_DEBUG(internal->logger, "Malformed TCP option: insufficient length for kind {}", (int)kind);
                break;
            }
            u_char length = options[parsed_length + 1];
            LOG_DEBUG(internal->logger, "TCP option kind: {}, length: {}", (int)kind, (int)length);

            if (length < 2 || parsed_length + length > tcp_options_length)
            {
                // Malformed option: invalid length
                LOG_DEBUG(internal->logger, "Malformed TCP option: invalid length {} for kind {}", (int)length, (int)kind);
                break;
            }

            // Update TCP option counts in a thread-safe manner
            {
                std::lock_guard<std::mutex> lock(internal->counts_mutex);
                internal->tcp_option_counts[kind]++;
                LOG_DEBUG(internal->logger, "Incremented count for TCP option kind {}: total count now {}", (int)kind, internal->tcp_option_counts[kind]);
            }

            // Move to the next option
            parsed_length += length;
        }
    }
}

// Helper function to process TCP packet
void process_tcp_packet(std::shared_ptr<Server::Data> internal, Server::PacketData &packet_data, struct iphdr *ip_header)
{
    // Extract TCP header
    int ip_header_length = ip_header->ihl * 4;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet_data.data.data() + sizeof(struct ethhdr) + ip_header_length);

    // Process flags
    uint8_t tcp_flags = tcp_header->th_flags;
    std::vector<std::string> flag_names = get_tcp_flag_names(tcp_flags);

    if (!flag_names.empty())
    {
        process_tcp_flags(internal, tcp_flags);
    }

    // Process options
    int tcp_header_length = tcp_header->doff * 4;
    int tcp_options_length = tcp_header_length - sizeof(struct tcphdr);
    std::vector<int> option_kinds; // Vector to hold TCP option kinds

    if (tcp_options_length > 0)
    {
        u_char *options = (u_char *)tcp_header + sizeof(struct tcphdr);
        process_tcp_options(internal, options, tcp_options_length, option_kinds);
    }

    // If packet has flags or options, log it
    if (!flag_names.empty() || !option_kinds.empty())
    {
        std::string packet_id = generate_packet_id(ip_header, tcp_header);
        std::string timestamp = get_current_timestamp();

        {
            std::lock_guard<std::mutex> lock(internal->packet_log_mutex);
            Server::PacketLogEntry log_entry;
            log_entry.status = "received";
            log_entry.timestamp = timestamp;
            log_entry.flags = flag_names;
            log_entry.options = option_kinds;
            internal->packet_log[packet_id] = log_entry;
        }

        LOG_DEBUG(internal->logger, "Packet with ID {} received at {}", packet_id, timestamp);
    }
}

// Helper function to add packet to the queue
void add_packet_to_queue(std::shared_ptr<Server::Data> internal, Server::PacketData &packet_data, const struct pcap_pkthdr *header)
{
    {
        std::lock_guard<std::mutex> lock(internal->queue_mutex);
        internal->packet_queue.push_back(std::move(packet_data));

        // Update total_payload_length
        internal->total_payload_length += header->len;
        LOG_DEBUG(internal->logger, "Packet added to queue. Queue size: {}, Total payload length: {}",
                  internal->packet_queue.size(), internal->total_payload_length);
    }
}

void queue_packet(std::shared_ptr<Server::Data> internal, const struct pcap_pkthdr *header, const u_char *packet)
{
    LOG_DEBUG(internal->logger, "Entering queue_packet with packet length: {}", header->len);

    // Create a PacketData object
    Server::PacketData packet_data;

    // Step 1: Copy the packet data
    copy_packet_data(packet_data, header, packet, internal->logger);

    // Step 2: Parse Ethernet header
    struct ethhdr *eth = parse_ethernet_header(packet_data, internal->logger);

    // Step 3: Only process IP packets
    if (!is_ip_packet(eth, internal->logger))
    {
        return;
    }

    // Step 4: Get IP header
    struct iphdr *ip_header = parse_ip_header(packet_data, internal->logger);

    // Step 5: Get destination IP address
    if (!get_destination_ip(ip_header, packet_data, internal->logger))
    {
        return;
    }

    // Step 6: Get the MAC address of the destination IP
    if (!get_destination_mac(packet_data, internal->logger))
    {
        return;
    }

    // Step 7: Update Ethernet header
    update_ethernet_header(eth, packet_data, internal->logger);

    // Step 8: Prepare socket_address for sending
    prepare_socket_address(packet_data);
    LOG_DEBUG(internal->logger, "Prepared socket address for sending");

    // Step 9: Process TCP packet if applicable
    if (ip_header->protocol == IPPROTO_TCP)
    {
        LOG_DEBUG(internal->logger, "Processing TCP packet");
        process_tcp_packet(internal, packet_data, ip_header);
    }
    else
    {
        LOG_DEBUG(internal->logger, "Non-TCP packet, protocol: {}", ip_header->protocol);
    }

    // Step 10: Remove SACK options if present and recompute checksums
    if (ip_header->protocol == IPPROTO_TCP)
    {
        LOG_DEBUG(internal->logger, "Checking for SACK options to remove");

        // Extract TCP header again if not already available
        int ip_header_length = ip_header->ihl * 4;
        struct tcphdr *tcp_header = (struct tcphdr *)(packet_data.data.data() + sizeof(struct ethhdr) + ip_header_length);

        // Get the original TCP header length
        int original_tcp_header_length = tcp_header->doff * 4;

        // Calculate TCP options length
        int tcp_options_length = original_tcp_header_length - sizeof(struct tcphdr);

        if (tcp_options_length > 0)
        {
            u_char *options = (u_char *)tcp_header + sizeof(struct tcphdr);
            int parsed_length = 0;
            bool sack_option_found = false;

            // Create a new options buffer to store modified options
            std::vector<u_char> new_options;

            while (parsed_length < tcp_options_length)
            {
                u_char kind = options[parsed_length];

                if (kind == 0)
                {
                    // End of options list
                    new_options.push_back(0);
                    parsed_length++;
                    break;
                }
                else if (kind == 1)
                {
                    // No-Operation (NOP), 1 byte
                    new_options.push_back(1);
                    parsed_length++;
                    continue;
                }
                else
                {
                    // Other options with kind and length
                    if (parsed_length + 1 >= tcp_options_length)
                    {
                        // Malformed option
                        LOG_DEBUG(internal->logger, "Malformed TCP option at position {}", parsed_length);
                        break;
                    }

                    u_char length = options[parsed_length + 1];

                    if (length < 2 || parsed_length + length > tcp_options_length)
                    {
                        // Invalid length
                        LOG_DEBUG(internal->logger, "Invalid TCP option length at position {}", parsed_length);
                        break;
                    }
                    else
                    {
                        // Copy other options
                        new_options.insert(new_options.end(), &options[parsed_length], &options[parsed_length + length]);
                    }

                    parsed_length += length;
                }
            }

            if (sack_option_found)
            {
                // Calculate the new TCP header length
                int new_tcp_options_length = new_options.size();
                int new_tcp_header_length = sizeof(struct tcphdr) + new_tcp_options_length;

                // Update the data buffer to reflect the new TCP options
                int tcp_header_offset = sizeof(struct ethhdr) + ip_header_length;

                // Create a new packet data buffer
                std::vector<u_char> new_data(packet_data.data.size() - tcp_options_length + new_tcp_options_length);

                // Copy data before TCP options
                memcpy(new_data.data(), packet_data.data.data(), tcp_header_offset + sizeof(struct tcphdr));

                // Copy new TCP options
                memcpy(new_data.data() + tcp_header_offset + sizeof(struct tcphdr), new_options.data(), new_tcp_options_length);

                // Copy data after original TCP header
                int data_after_tcp_header = packet_data.data.size() - (tcp_header_offset + original_tcp_header_length);
                memcpy(new_data.data() + tcp_header_offset + new_tcp_header_length,
                       packet_data.data.data() + tcp_header_offset + original_tcp_header_length,
                       data_after_tcp_header);

                // Update packet data
                packet_data.data = std::move(new_data);
                packet_data.length = packet_data.data.size();

                // Update TCP header length
                tcp_header = (struct tcphdr *)(packet_data.data.data() + tcp_header_offset);
                tcp_header->doff = new_tcp_header_length / 4;

                // Recompute checksums
                // Recompute TCP checksum
                tcp_header->th_sum = 0;
                compute_tcp_checksum(ip_header, tcp_header);

                // Recompute IP checksum
                ip_header = (struct iphdr *)(packet_data.data.data() + sizeof(struct ethhdr));
                ip_header->check = 0;
                compute_ip_checksum(ip_header);

                LOG_DEBUG(internal->logger, "Removed SACK options and recomputed checksums");
            }
        }
    }

    // Step 11: Add packet to the queue
    add_packet_to_queue(internal, packet_data, header);

    // Step 12: Log the queuing action
    LOG_DEBUG(internal->logger, "Queued packet, length: {} bytes, total queued payload: {} bytes",
              header->len, internal->total_payload_length);
}
