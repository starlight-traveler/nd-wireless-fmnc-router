#ifndef SERVER
#define SERVER

#include "general.h"

void capture_packets_from_192_168_2_2(quill::Logger *logger);

void packet_handler_from_192_168_2_2(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif
