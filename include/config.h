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

    // Getter Functions
    std::string getLogLevel() const;
    std::string getLogDirectory() const;
    int getTimeWait() const;
    bool getReorderPackets() const;
    bool getManageSSL() const;

private:
    std::string filename;
    libconfig::Config cfg;
    quill::Logger *logger;

    // Variable Functions
    std::string logLevel;
    std::string logDirectory;
    int timeWait;
    bool reorderPackets;
    bool manageSSL;
};

#endif // CONFIG_H