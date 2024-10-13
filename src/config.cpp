#include "config.h"

// Adding a new variable to config, add fields hereby:

// 1) Update config.h private field
// 2) Add field to Config Manager Decleration for default
// 3) Add to try function
// 4) Add getter

// Get via:
// int packetCaptureTime = config.getPacketCaptureTime();

ConfigManager::ConfigManager(const std::string &filename, quill::Logger *logger)
    : filename(filename), logLevel("TRACE_L3"), logDirectory("."), timeWait(1), reorderPackets(false), manageSSL(true), logger(logger) {}

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
        logLevel = cfg.lookup("log_level").c_str();
        logDirectory = cfg.lookup("log_directory").c_str(); // Cast to string
        timeWait = cfg.lookup("time_wait_ms");
        reorderPackets = cfg.lookup("reorder_packets");
        manageSSL = cfg.lookup("manage_ssl");
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

std::string ConfigManager::getLogDirectory() const
{
    return logDirectory;
}

int ConfigManager::getTimeWait() const
{
    return timeWait;
}

bool ConfigManager::getReorderPackets() const
{
    return reorderPackets;
}

bool ConfigManager::getManageSSL() const
{
    return manageSSL;
}
