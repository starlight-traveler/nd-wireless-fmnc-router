#include "config.h"

// Adding a new variable to config, add fields hereby:

// 1) Update config.h private field
// 2) Add field to Config Manager Decleration for default
// 3) Add to try function
// 4) Add getter

// Get via:
// int packetCaptureTime = config.getPacketCaptureTime();

ConfigManager::ConfigManager(const std::string &filename, quill::Logger *logger)
    : filename(filename), logLevel("TRACE_L3"), logger(logger) {}

bool ConfigManager::loadConfig()
{
    try
    {
        cfg.readFile(filename.c_str());
        LOG_INFO(logger, "Successfully read configuration file: {}", filename);
    }
    catch (const libconfig::FileIOException &fioex)
    {
        LOG_ERROR(logger, "I/O error while reading file: {}", filename);
        return false;
    }
    catch (const libconfig::ParseException &pex)
    {
        LOG_ERROR(logger, "Parse error at {}:{} - {}", pex.getFile(), pex.getLine(), pex.getError());
        return false;
    }

    // Retrieve settings from the config file
    try
    {
        logLevel = cfg.lookup("log_level").c_str(); // Cast to string

        // LOG_INFO(logger, "Loaded packet_capture_time: {}, buffer_size: {}", packetCaptureTime, bufferSize);
    }
    catch (const libconfig::SettingNotFoundException &nfex)
    {
        LOG_ERROR(logger, "Setting not found in configuration file: {}", filename);
        return false;
    }

    return true;
}

std::string ConfigManager::getLogLevel() const
{
    return logLevel;
}
