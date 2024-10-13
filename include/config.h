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

private:
    std::string filename;
    libconfig::Config cfg;
    quill::Logger *logger;

    // Variable Functions
    std::string logLevel;
};

#endif // CONFIG_H