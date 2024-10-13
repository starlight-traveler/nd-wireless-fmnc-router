#include "general.h"
#include "config.h"
#include "client.h"
#include "server.h"
#include "logger.h"

void signalHandler(int signum)
{
    std::cout << "Interrupt signal (" << signum << ") received.\n";

    exit(signum);
}


int main()
{
    
    // Setup logger
    quill::Logger *logger = initialize_logger();

    // Initialize config manager and load the config
    ConfigManager config("../config.cfg", logger);
    if (!config.loadConfig())
    {
        std::cerr << "Failed to load config." << std::endl;
        return -1;
    }

    // Setup raw socket for packet forwarding
    setup_raw_socket();

    // Threaded functions using custom variables from config
    std::thread thread_client_to_server([&]()
                                        { threaded(logger, 5, 3, capture_packets_to, logger); });

    std::thread thread_server_to_client([&]()
                                        { threaded(logger, 5, 3, capture_packets_from, logger); });

    // Just suspend until CTRL-C is called
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Cleanup
    close(raw_socket);

    return 0;
}