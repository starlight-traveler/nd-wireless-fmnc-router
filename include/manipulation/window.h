#ifndef WINDOW
#define WINDOW

#include "server.h"

#include <memory>

void window(std::shared_ptr<Server::Data> internal, const Server::PacketData &original_packet);

#endif