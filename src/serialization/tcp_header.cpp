// serialization_manager.cpp

#include "serialization_manager.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <mutex>
#include <ctime>
#include <iomanip>
#include <sstream>
#include "logger.h"

// Function to get the name of a TCP option based on its kind
std::string get_tcp_option_name(int option_kind)
{
    static const std::unordered_map<int, std::string> tcp_option_names = {
        {0, "End of Option List"},
        {1, "No-Operation"},
        {2, "Maximum Segment Size"},
        {3, "Window Scale"},
        {4, "Selective Acknowledgment Permitted"},
        {5, "Selective Acknowledgment (SACK)"}, // SACK Option, multiple blocks
        {6, "Echo (obsoleted)"},                // Used for early TCP testing, obsolete
        {7, "Echo Reply (obsoleted)"},          // Used for early TCP testing, obsolete
        {8, "Timestamp"},                       // TCP Timestamp Option
        {9, "Partial Order Connection Permitted (obsolete)"},
        {10, "Partial Order Service Profile (obsolete)"},
        {11, "CC (Connection Count, experimental)"}, // Used in experimental congestion control schemes
        {12, "Alternate Checksum Request"},
        {13, "Alternate Checksum Data"},
        {14, "TCP Fast Open"},
        {15, "TCP Fast Open (Cookie Echo)"},
        {16, "TCP Fast Open (Cookie Request)"},
        {18, "Trailer Checksum Option"}, // Used in some non-standard TCP implementations
        {19, "MD5 Signature Option"},    // Used for BGP authentication
        {20, "SCPS Capabilities"},       // Used in SCPS for space communication
        {21, "Selective Negative Acknowledgements (SNACK)"},
        {22, "Record Boundaries"},
        {23, "Corruption Experienced"},             // Used in some SCPS implementations
        {24, "Quick-Start Response"},               // Experimental; used for Quick-Start TCP
        {25, "User Timeout Option (UTO)"},          // Used to specify user-specified timeouts
        {26, "TCP Authentication Option (TCP-AO)"}, // Replaces MD5 for TCP-level security
        {27, "Multipath TCP (MPTCP)"},              // Multiple paths for TCP connection
        {28, "TCP Fast Open Key"},
        {29, "Fast Open Cookie Request"},
        {30, "Fast Open Cookie Echo"},
        {31, "Fast Retransmit Option"}, // Allows indicating packet retransmission, experimental use
    };

    auto it = tcp_option_names.find(option_kind);
    if (it != tcp_option_names.end())
    {
        return it->second;
    }
    else
    {
        return "Unknown";
    }
}

// Function to dump packet log entries to JSON
void dump_packet_log(std::shared_ptr<Server::Data> internal)
{
    std::unordered_map<std::string, Server::PacketLogEntry> packet_log_copy;

    {
        std::lock_guard<std::mutex> lock(internal->packet_log_mutex);
        packet_log_copy = internal->packet_log;
        internal->packet_log.clear();
    }

    // Check if there's any data to log
    if (packet_log_copy.empty())
    {
        LOG_DEBUG(internal->logger, "No packet logs to dump.");
        return; // Exit early to prevent writing empty JSON
    }

    // Create JSON object
    nlohmann::json j;

    for (const auto &kv : packet_log_copy)
    {
        const std::string &packet_id = kv.first;
        const Server::PacketLogEntry &entry = kv.second;

        // Convert option kinds to their names if desired
        std::vector<std::string> option_names;
        for (const auto &opt_kind : entry.options)
        {
            option_names.push_back(get_tcp_option_name(opt_kind));
        }

        j[packet_id] = {
            {"status", entry.status},
            {"timestamp", entry.timestamp},
            {"flags", entry.flags},
            {"options", option_names}};
    }

    // Append to the file to avoid overwriting
    std::ofstream ofs("packet_log.json", std::ios::app);
    if (!ofs)
    {
        LOG_ERROR(internal->logger, "Failed to open packet_log.json for writing.");
        return;
    }

    try
    {
        ofs << j.dump(4) << std::endl; // Pretty print with 4 spaces indentation
    }
    catch (const std::exception &e)
    {
        LOG_ERROR(internal->logger, "Failed to write JSON to file: {}", e.what());
        ofs.close();
        return;
    }

    ofs.close();

    LOG_INFO(internal->logger, "Packet log written to packet_log.json");
}

void dump_tcp_flag_counts(std::shared_ptr<Server::Data> internal)
{
    std::unordered_map<std::string, size_t> flag_counts_copy;

    {
        std::lock_guard<std::mutex> lock(internal->flags_mutex);
        flag_counts_copy = internal->tcp_flag_counts;
        internal->tcp_flag_counts.clear();
    }

    // Create or load existing JSON data
    nlohmann::json j;

    // Open existing file if it exists to append new counts
    std::ifstream ifs("tcp_flag_counts.json");
    if (ifs)
    {
        try
        {
            ifs >> j;
        }
        catch (const std::exception &e)
        {
            LOG_ERROR(internal->logger, "Failed to read existing JSON file: {}", e.what());
            ifs.close();
            return;
        }
    }
    ifs.close();

    // Ensure we have an object to work with
    if (!j.is_object())
    {
        j = nlohmann::json::object();
    }

    // Append new data to existing JSON
    for (const auto &kv : flag_counts_copy)
    {
        const std::string &flag_name = kv.first;
        size_t count = kv.second;

        if (j.contains(flag_name))
        {
            j[flag_name] = j[flag_name].get<size_t>() + count;
        }
        else
        {
            j[flag_name] = count;
        }
    }

    // Write updated JSON back to file
    std::ofstream ofs("tcp_flag_counts.json");
    if (!ofs)
    {
        LOG_ERROR(internal->logger, "Failed to open tcp_flag_counts.json for writing.");
        return;
    }

    try
    {
        ofs << j.dump(4); // Pretty print with indent of 4 spaces
    }
    catch (const std::exception &e)
    {
        LOG_ERROR(internal->logger, "Failed to write JSON to file: {}", e.what());
        ofs.close();
        return;
    }

    ofs.close();

    // LOG_INFO(internal->logger, "TCP flag counts appended to tcp_flag_counts.json");
}

// Function to dump TCP option counts to a JSON file with option names
void dump_tcp_option_counts(std::shared_ptr<Server::Data> internal)
{
    std::unordered_map<int, size_t> counts_copy;

    {
        std::lock_guard<std::mutex> lock(internal->counts_mutex);
        counts_copy = internal->tcp_option_counts;
        internal->tcp_option_counts.clear();
    }

    // Create or load existing JSON data
    nlohmann::json j;

    // Open existing file if it exists to append new counts
    std::ifstream ifs("tcp_option_counts.json");
    if (ifs)
    {
        try
        {
            ifs >> j;
        }
        catch (const std::exception &e)
        {
            LOG_ERROR(internal->logger, "Failed to read existing JSON file: {}", e.what());
            ifs.close();
            return;
        }
    }
    ifs.close();

    // Ensure we have an array to work with
    if (!j.is_array())
    {
        j = nlohmann::json::array();
    }

    // Append new data to existing JSON
    for (const auto &kv : counts_copy)
    {
        int option_kind = kv.first;
        size_t count = kv.second;
        std::string option_name = get_tcp_option_name(option_kind);

        bool updated = false;
        for (auto &entry : j)
        {
            if (entry["kind"].get<int>() == option_kind)
            {
                entry["count"] = entry["count"].get<size_t>() + count;
                updated = true;
                break;
            }
        }

        if (!updated)
        {
            // Add a new entry if this kind doesn't exist yet
            nlohmann::json option_entry;
            option_entry["kind"] = option_kind;
            option_entry["name"] = option_name;
            option_entry["count"] = count;
            j.push_back(option_entry);
        }
    }

    // Sort the JSON array by option kind
    std::sort(j.begin(), j.end(), [](const nlohmann::json &a, const nlohmann::json &b)
              { return a["kind"].get<int>() < b["kind"].get<int>(); });

    // Write updated JSON back to file
    std::ofstream ofs("tcp_option_counts.json");
    if (!ofs)
    {
        LOG_ERROR(internal->logger, "Failed to open tcp_option_counts.json for writing.");
        return;
    }

    try
    {
        ofs << j.dump(4); // Pretty print with indent of 4 spaces
    }
    catch (const std::exception &e)
    {
        LOG_ERROR(internal->logger, "Failed to write JSON to file: {}", e.what());
        ofs.close();
        return;
    }

    ofs.close();

    // LOG_INFO(internal->logger, "TCP option counts appended to tcp_option_counts.json");
}
