#include "config.h"

ConfigManager::ConfigManager(const std::string &filename, quill::Logger *logger)
    : filename(filename), packetCaptureTime(5), bufferSize(1024), logger(logger) {}

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
        std::cerr << "I/O error while reading file." << std::endl;
        return false;
    }
    catch (const libconfig::ParseException &pex)
    {
        LOG_ERROR(logger, "Parse error at {}:{} - {}", pex.getFile(), pex.getLine(), pex.getError());
        std::cerr << "Parse error at " << pex.getFile() << ":" << pex.getLine() << " - " << pex.getError() << std::endl;
        return false;
    }

    // Retrieve settings from the config file
    try
    {
        packetCaptureTime = cfg.lookup("packet_capture_time");
        bufferSize = cfg.lookup("buffer_size");
        logLevel = cfg.lookup("log_level").c_str(); // Cast to string

        // LOG_INFO(logger, "Loaded packet_capture_time: {}, buffer_size: {}", packetCaptureTime, bufferSize);
    }
    catch (const libconfig::SettingNotFoundException &nfex)
    {
        LOG_ERROR(logger, "Setting not found in configuration file: {}", filename);
        std::cerr << "Setting not found in configuration file." << std::endl;
        return false;
    }

    return true;
}

int ConfigManager::getPacketCaptureTime() const
{
    return packetCaptureTime;
}

int ConfigManager::getBufferSize() const
{
    return bufferSize;
}

std::string ConfigManager::getLogLevel() const
{
    return logLevel;
}
