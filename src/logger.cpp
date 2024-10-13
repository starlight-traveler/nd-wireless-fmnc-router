#include "quill/Backend.h"
#include "quill/Frontend.h"
#include "quill/Logger.h"
#include "quill/sinks/ConsoleSink.h"
#include "quill/sinks/FileSink.h"

#include <utility>

#include "config.h"

quill::Logger *initialize_logger()
{
    // Start the backend thread
    quill::BackendOptions backend_options;
    quill::Backend::start(backend_options);

    // Frontend
    quill::ConsoleColours custom_console_colours;
    custom_console_colours.set_default_colours();
    custom_console_colours.set_colour(quill::LogLevel::Info, quill::ConsoleColours::blue);      // overwrite the colour for INFO
    custom_console_colours.set_colour(quill::LogLevel::Warning, quill::ConsoleColours::yellow); // overwrite the colour for WARNING
    custom_console_colours.set_colour(quill::LogLevel::Error, quill::ConsoleColours::red);      // overwrite the colour for ERROR

    // Create the sink
    auto console_sink = quill::Frontend::create_or_get_sink<quill::ConsoleSink>("sink_client", custom_console_colours);

    auto file_sink = quill::Frontend::create_or_get_sink<quill::FileSink>(
        "fmnc_client.log",
        []()
        {
            quill::FileSinkConfig cfg;
            cfg.set_open_mode('w');
            return cfg;
        }(),
        quill::FileEventNotifier{});

    quill::Logger *logger = quill::Frontend::create_or_get_logger("root", {std::move(console_sink), std::move(file_sink)});

    // Change the LogLevel to print everything
    logger->set_log_level(quill::LogLevel::TraceL3);

    return logger;
}

void set_log_level(ConfigManager &config, quill::Logger *logger)
{
    // Retrieve the log level from the configuration
    std::string log_level = config.getLogLevel();

    // Check the log level and set it accordingly
    if (log_level == "TRACE_L1")
    {
        logger->set_log_level(quill::LogLevel::TraceL1);
    }
    else if (log_level == "TRACE_L2")
    {
        logger->set_log_level(quill::LogLevel::TraceL2);
    }
    else if (log_level == "TRACE_L3")
    {
        logger->set_log_level(quill::LogLevel::TraceL3);
    }
    else if (log_level == "DEBUG")
    {
        logger->set_log_level(quill::LogLevel::Debug);
    }
    else if (log_level == "INFO")
    {
        logger->set_log_level(quill::LogLevel::Info);
    }
    else if (log_level == "WARNING")
    {
        logger->set_log_level(quill::LogLevel::Warning);
    }
    else if (log_level == "ERROR")
    {
        logger->set_log_level(quill::LogLevel::Error);
    }
    else if (log_level == "CRITICAL")
    {
        logger->set_log_level(quill::LogLevel::Critical);
    }
    else
    {
        // Default or invalid log level case
        logger->set_log_level(quill::LogLevel::Info); // Set default log level
        // Optionally log a warning for an invalid log level
        LOG_WARNING(logger, "Invalid log level '{}' specified in configuration. Defaulting to INFO.", log_level);
    }
}
