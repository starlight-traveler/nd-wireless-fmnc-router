#include "client.h"
#include "utilities.h"
#include <pcap.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <thread>
#include <chrono>
#include <cstring>
#include <fstream>
#include <filesystem>

extern unsigned char src_mac[6]; // Defined elsewhere
extern int if_index;             // Defined elsewhere
extern std::mutex raw_socket_mutex;
extern int raw_socket;
extern const char *interface; // Defined elsewhere

namespace fs = std::filesystem;

static void delete_old_json(const std::string &filename, quill::Logger *logger)
{
    try
    {
        if (fs::exists(filename))
        {
            fs::remove(filename);
            LOG_INFO(logger, "Deleted old file: {}", filename);
        }
        else
        {
            LOG_INFO(logger, "No old file found to delete: {}", filename);
        }
    }
    catch (const fs::filesystem_error &e)
    {
        LOG_ERROR(logger, "Failed to delete file: {}, Error: {}", filename, e.what());
    }
}

void dump_client_tcp_option_counts(std::shared_ptr<Client::Data> data)
{
    std::lock_guard<std::mutex> lock(data->counts_mutex);
    nlohmann::json j;
    for (auto &kv : data->tcp_option_counts)
    {
        j[std::to_string(kv.first)] = kv.second;
    }

    std::ofstream ofs("client_tcp_option_counts.json");
    ofs << j.dump(4);
    LOG_DEBUG(data->logger, "Dumped client TCP option counts to client_tcp_option_counts.json");
}

void dump_client_tcp_flag_counts(std::shared_ptr<Client::Data> data)
{
    std::lock_guard<std::mutex> lock(data->flags_mutex);
    nlohmann::json j;
    for (auto &kv : data->tcp_flag_counts)
    {
        j[kv.first] = kv.second;
    }

    std::ofstream ofs("client_tcp_flag_counts.json");
    ofs << j.dump(4);
    LOG_DEBUG(data->logger, "Dumped client TCP flag counts to client_tcp_flag_counts.json");
}

void dump_client_packet_log(std::shared_ptr<Client::Data> data)
{
    std::lock_guard<std::mutex> lock(data->packet_log_mutex);
    nlohmann::json j;
    for (auto &kv : data->packet_log)
    {
        nlohmann::json entry;
        entry["status"] = kv.second.status;
        entry["timestamp"] = kv.second.timestamp;
        entry["flags"] = kv.second.flags;
        entry["options"] = kv.second.options;
        j[kv.first] = entry;
    }

    std::ofstream ofs("client_packet_log.json");
    ofs << j.dump(4);
    LOG_DEBUG(data->logger, "Dumped client packet log to client_packet_log.json");
}

// Client serialization manager thread
void serialization_manager_client(std::shared_ptr<Client::Data> data)
{
    // Delete old JSON files on startup
    delete_old_json("client_tcp_option_counts.json", data->logger);
    delete_old_json("client_tcp_flag_counts.json", data->logger);
    delete_old_json("client_packet_log.json", data->logger);

    // Periodically dump client data
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        dump_client_tcp_option_counts(data);
        dump_client_tcp_flag_counts(data);
        dump_client_packet_log(data);
    }
}

// A helper function to extract TCP flags and options, similar to server side
static std::vector<std::string> get_tcp_flag_names(uint8_t flags)
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

// Similar to server, process flags and options on the client side
static void process_tcp_flags_client(std::shared_ptr<Client::Data> data, uint8_t tcp_flags)
{
    std::vector<std::string> flag_names = get_tcp_flag_names(tcp_flags);
    if (!flag_names.empty())
    {
        std::lock_guard<std::mutex> lock(data->flags_mutex);
        for (const auto &f : flag_names)
        {
            data->tcp_flag_counts[f]++;
        }
    }
}

static void process_tcp_options_client(std::shared_ptr<Client::Data> data, u_char *options, int tcp_options_length, std::vector<int> &option_kinds)
{
    int parsed_length = 0;
    while (parsed_length < tcp_options_length)
    {
        u_char kind = options[parsed_length];
        option_kinds.push_back(kind);

        if (kind == 0) // End of options
        {
            parsed_length++;
            break;
        }
        else if (kind == 1) // NOP
        {
            parsed_length++;
            continue;
        }
        else
        {
            if (parsed_length + 1 >= tcp_options_length)
            {
                break; // malformed
            }
            u_char length = options[parsed_length + 1];
            if (length < 2 || parsed_length + length > tcp_options_length)
            {
                break; // malformed
            }

            {
                std::lock_guard<std::mutex> lock(data->counts_mutex);
                data->tcp_option_counts[kind]++;
            }

            parsed_length += length;
        }
    }
}

// For logging packets, we need a unique packet_id, similar to server side
static std::string generate_packet_id(struct iphdr *ip_header, struct tcphdr *tcp_header)
{
    std::stringstream ss;
    ss << std::hex << (int)ip_header->saddr << "_" << (int)ip_header->daddr << "_" << (int)ntohs(tcp_header->source) << "_" << (int)ntohs(tcp_header->dest) << "_" << ntohl(tcp_header->seq);
    return ss.str();
}

// Handle packets going to 192.168.2.2
void capture_packets_to(quill::Logger *logger)
{
    // Create the client data object
    auto data = std::make_shared<Client::Data>();
    data->logger = logger;

    // Start a serialization manager thread for the client
    std::thread serialization_thread(serialization_manager_client, data);
    serialization_thread.detach();

    Client::Configuration conf = {logger, data};

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the device for packet capture
    handle = pcap_open_live(interface, BUFSIZ, 1, 50, error_buffer);
    if (handle == nullptr)
    {
        LOG_ERROR(logger, "Could not open device {}: {}", interface, error_buffer);
        return;
    }

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

    // Parse IP header
    struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    // Parse TCP header if protocol == TCP
    if (ip_header->protocol == IPPROTO_TCP)
    {
        int ip_header_length = ip_header->ihl * 4;
        struct tcphdr *tcp_header = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + ip_header_length);

        uint8_t tcp_flags = tcp_header->th_flags;
        process_tcp_flags_client(args->data, tcp_flags);

        int tcp_header_length = tcp_header->doff * 4;
        int tcp_options_length = tcp_header_length - sizeof(struct tcphdr);
        std::vector<int> option_kinds;
        if (tcp_options_length > 0)
        {
            u_char *options = (u_char *)tcp_header + sizeof(struct tcphdr);
            process_tcp_options_client(args->data, options, tcp_options_length, option_kinds);
        }

        // Log the packet in the packet_log
        std::string packet_id = generate_packet_id(ip_header, tcp_header);
        std::string timestamp = get_current_timestamp();
        {
            std::lock_guard<std::mutex> lock(args->data->packet_log_mutex);
            ClientPacketLogEntry log_entry;
            log_entry.status = "received_client";
            log_entry.timestamp = timestamp;
            log_entry.flags = get_tcp_flag_names(tcp_flags);
            log_entry.options = option_kinds;
            args->data->packet_log[packet_id] = log_entry;
        }
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
