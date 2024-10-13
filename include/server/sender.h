#ifndef SENDER
#define SENDER

#include "server.h"

void send_queued_packets(Server::Data *internal);
void send_packet(const Server::PacketData &pkt, quill::Logger *logger);

#endif