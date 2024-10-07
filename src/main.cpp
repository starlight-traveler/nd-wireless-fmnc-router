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

#define MAX_PACKET_SIZE 65536

// Global variables
int raw_socket;
int if_index;
unsigned char src_mac[6];
const char *interface = "enp3s0";
std::mutex raw_socket_mutex;

// Function prototypes
void setup_raw_socket();
unsigned char *get_mac_address(const char *ip_address);

void capture_packets_to_192_168_2_2();
void capture_packets_from_192_168_2_2();

void packet_handler_to_192_168_2_2(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void packet_handler_from_192_168_2_2(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

// Define a structure for cache entries
struct MacCacheEntry
{
    std::array<unsigned char, 6> mac;
    std::chrono::steady_clock::time_point timestamp;
};

// Global MAC address cache and mutex
std::unordered_map<std::string, MacCacheEntry> mac_cache;
std::mutex mac_cache_mutex;

int main()
{
    // Setup raw socket for packet forwarding
    setup_raw_socket();

    // Start packet capture threads
    std::thread thread_to_192_168_2_2(capture_packets_to_192_168_2_2);
    std::thread thread_from_192_168_2_2(capture_packets_from_192_168_2_2);

    // Wait for threads to finish (they won't, as pcap_loop runs indefinitely)
    thread_to_192_168_2_2.join();
    thread_from_192_168_2_2.join();

    // Cleanup
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

unsigned char *get_mac_address(const char *ip_address)
{
    static unsigned char dest_mac[6];
    auto now = std::chrono::steady_clock::now();
    bool found_in_cache = false;

    {
        // Lock the cache for thread-safe access
        std::lock_guard<std::mutex> lock(mac_cache_mutex);

        // Check if the MAC address is in the cache
        auto it = mac_cache.find(ip_address);
        if (it != mac_cache.end())
        {
            // Optional: Check if the cache entry is still valid (e.g., valid for 60 seconds)
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.timestamp).count();
            if (elapsed < 60)
            {
                // Cache entry is valid
                memcpy(dest_mac, it->second.mac.data(), 6);
                return dest_mac;
            }
            else
            {
                // Cache entry is stale; remove it
                mac_cache.erase(it);
            }
        }
    }

    // If not found in cache or cache is stale, read /proc/net/arp
    FILE *fp = fopen("/proc/net/arp", "r");
    if (!fp)
    {
        perror("Failed to open /proc/net/arp");
        return nullptr;
    }

    char line[256];
    // Skip the header line
    fgets(line, sizeof(line), fp);

    while (fgets(line, sizeof(line), fp))
    {
        char ip[64], hw_type[64], flags[64], mac[64], mask[64], device[64];
        sscanf(line, "%63s %63s %63s %63s %63s %63s", ip, hw_type, flags, mac, mask, device);
        if (strcmp(ip, ip_address) == 0)
        {
            // Parse the MAC address
            sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &dest_mac[0], &dest_mac[1], &dest_mac[2],
                   &dest_mac[3], &dest_mac[4], &dest_mac[5]);
            fclose(fp);

            // Store the MAC address in the cache
            MacCacheEntry entry;
            memcpy(entry.mac.data(), dest_mac, 6);
            entry.timestamp = now;

            {
                std::lock_guard<std::mutex> lock(mac_cache_mutex);
                mac_cache[ip_address] = entry;
            }

            return dest_mac;
        }
    }

    fclose(fp);
    return nullptr;
}

void capture_packets_to_192_168_2_2()
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
    char filter_exp_to[150];
    snprintf(filter_exp_to, sizeof(filter_exp_to),
             "dst host 192.168.2.2 and not ether src %02x:%02x:%02x:%02x:%02x:%02x",
             src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);

    if (pcap_compile(handle, &filter, filter_exp_to, 0, PCAP_NETMASK_UNKNOWN) == -1)
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
    pcap_loop(handle, 0, packet_handler_to_192_168_2_2, nullptr);

    // Cleanup
    pcap_close(handle);
}

void capture_packets_from_192_168_2_2()
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

void packet_handler_to_192_168_2_2(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
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
            std::cout << "Forwarded packet to 192.168.2.2, length: " << sent << " bytes" << std::endl;
        }
    }
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
