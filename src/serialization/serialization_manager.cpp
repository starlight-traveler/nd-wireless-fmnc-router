#include "serialization_manager.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem> // C++17 feature for file operations
#include <mutex>
#include <thread>
#include <chrono>
#include <cstdio>
#include "logger.h"

namespace fs = std::filesystem;

void delete_old_json(const std::string &filename, quill::Logger *logger)
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

// Function to manage serialization periodically
void serialization_manager(std::shared_ptr<Server::Data> internal)
{
    // Define the name of the JSON files to delete
    const std::string option_filename = "tcp_option_counts.json";
    const std::string flag_filename = "tcp_flag_counts.json";

    // Delete old JSON files on startup
    delete_old_json(option_filename, internal->logger);
    delete_old_json(flag_filename, internal->logger);

    // Periodically dump the TCP option and flag counts to the files
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(5)); // Adjust the interval as needed
        dump_tcp_option_counts(internal);
        dump_tcp_flag_counts(internal);
    }
}
