#include "general.h"

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
    // Setup raw socket for packet forwarding
    setup_raw_socket();

    // Setup logger
    quill::Logger *logger = initialize_logger();

    // Threaded functions
    std::thread thread_client_to_server([&]()
                                        { threaded(logger, 5, 3, capture_packets_to_192_168_2_2, logger); });

    std::thread thread_server_to_client([&]()
                                        { threaded(logger, 5, 3, capture_packets_from_192_168_2_2, logger); });

    // Just suspend until CTRL-C is called
    while (1) {
        sleep(10000);
    }

    // Cleanup
    close(raw_socket);

    return 0;
}