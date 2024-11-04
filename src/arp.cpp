#include "mac_arp.h"
#include "logger.h"
#include <cstdlib>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>

unsigned char *get_mac_address(const char *ip_address, quill::Logger *logger)
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
        LOG_CRITICAL(logger, "Failed to open /proc/net/arp.");
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

    // If the MAC address is not found in /proc/net/arp, ping the required IPs
    const char *ping_ips[] = {"192.168.1.40", "192.168.2.2"};
    for (const auto &ping_ip : ping_ips)
    {
        std::string ping_command = "ping -c 1 -W 1 " + std::string(ping_ip) + " > /dev/null 2>&1";
        int result = std::system(ping_command.c_str());
        if (result == 0)
        {
            LOG_INFO(logger, "Pinged IP: {}", ping_ip);
        }
        else
        {
            LOG_WARNING(logger, "Failed to ping IP: {}", ping_ip);
        }
    }

    // Retry reading /proc/net/arp after pinging to check if the MAC address is now available
    fp = fopen("/proc/net/arp", "r");
    if (!fp)
    {
        LOG_CRITICAL(logger, "Failed to open /proc/net/arp after pinging.");
        return nullptr;
    }

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
    LOG_WARNING(logger, "MAC address for IP {} not found even after pinging.", ip_address);
    return nullptr;
}
