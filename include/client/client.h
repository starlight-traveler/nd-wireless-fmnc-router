#ifndef CLIENT
#define CLIENT

#include "general.h"

#define MAX_PACKET_SIZE 65536

namespace Client
{
    // Configuration
    typedef struct
    {
        quill::Logger *logger;

    } Configuration;

}

    void capture_packets_to(quill::Logger *logger);
    void packet_handler_to(Client::Configuration args[], const struct pcap_pkthdr *header, const u_char *packet);

#endif
