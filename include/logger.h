#ifndef LOGGER_INIT_H
#define LOGGER_INIT_H

#include "quill/LogMacros.h"
#include "quill/Logger.h"
#include "config.h"

class ConfigManager;

quill::Logger *initialize_logger();
void set_log_level(ConfigManager &config, quill::Logger *logger); // Use reference

#endif // LOGGER_INIT_H
