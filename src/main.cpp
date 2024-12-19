#include "general.h"
#include "config.h"
#include "client.h"
#include "server.h"
#include "logger.h"
#include "serialization_manager.h"

void signalHandler(int signum)
{
    std::cout << "Interrupt signal (" << signum << ") received.\n";

    exit(signum);
}

// pcap inject would not work, same thing as just immediate send with pcap loop

// options are added to logging on the client side

// 

int main()
{
    
    // Setup logger
    quill::Logger *logger = initialize_logger();

    // Initialize config manager and load the config
    ConfigManager config("../config.cfg", logger);
    if (!config.loadConfig())
    {
        LOG_ERROR(logger, "Failed to load config.");
        return -1;
    }

    // Set log level config
    set_log_level(config, logger);

    // Setup raw socket for packet forwarding
    setup_raw_socket();

    // Allocate shared Server::Data
    std::shared_ptr<Server::Data> internal_server = std::make_shared<Server::Data>();
    internal_server->logger = logger;
    internal_server->prev_timestamp.tv_sec = 0;
    internal_server->prev_timestamp.tv_usec = 0;
    internal_server->total_payload_length = 0;

    // Allocate shared Client::Data
    std::shared_ptr<Client::Data> internal_client = std::make_shared<Client::Data>();
    internal_client->logger = logger;

    // Threaded functions using custom variables from config
    std::thread thread_client_to_server([&]()
                                        { threaded(logger, 5, 3, capture_packets_to, logger); });

    std::thread thread_server_to_client([&]()
                                        { threaded(logger, 5, 3, capture_packets_from, internal_server, logger, config); });

    std::thread thread_serialization_server([&]()
                                            { threaded(logger, 5, 3, serialization_manager, internal_server); });

    std::thread thread_serialization_client([&]()
                                            { threaded(logger, 5, 3, serialization_manager_client, internal_client); });
    // Just suspend until CTRL-C is called
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Cleanup
    close(raw_socket);

    return 0;
}