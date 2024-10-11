#include "mac_arp.h"

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