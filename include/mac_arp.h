#ifndef MAC_ARP
#define MAC_ARP

#include "general.h"

// Define a structure for cache entries
struct MacCacheEntry
{
    std::array<unsigned char, 6> mac;
    std::chrono::steady_clock::time_point timestamp;
};

// Global MAC address cache and mutex
std::unordered_map<std::string, MacCacheEntry> mac_cache;
std::mutex mac_cache_mutex;

#endif