#ifndef SERVER
#define SERVER

#include "general.h"

namespace Server
{

    typedef struct
    {
        quill::Logger *logger;

    } Configuration;

}

void capture_packets_from(quill::Logger *logger);

void packet_handler_from(Server::Configuration args[], const struct pcap_pkthdr *header, const u_char *packet);

// Configuration



#endif
