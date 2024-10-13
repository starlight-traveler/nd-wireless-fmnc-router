#ifndef CONFIG_H
#define CONFIG_H

#include <libconfig.h++>
#include <string>
#include <iostream>

#include "logger.h"

class ConfigManager
{
public:
    ConfigManager(const std::string &filename, quill::Logger* logger);
    bool loadConfig();
    int getPacketCaptureTime() const;
    int getBufferSize() const;
    std::string getLogLevel() const;

private:
    std::string filename;
    libconfig::Config cfg;
    int packetCaptureTime;
    int bufferSize;
    quill::Logger *logger;
    std::string logLevel;
};

// // Get custom variables from the config file
// int packetCaptureTime = config.getPacketCaptureTime();
// int bufferSize = config.getBufferSize();

// std::cout << "Packet Capture Time: " << packetCaptureTime << "\n";
// std::cout << "Buffer Size: " << bufferSize << "\n";

#endif // CONFIG_H