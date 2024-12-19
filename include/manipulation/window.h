#ifndef WINDOW_H
#define WINDOW_H

#include <memory>
#include "server.h"

void window(std::shared_ptr<Server::Data> internal, const Server::PacketData &original_packet);

#endif // WINDOW_H
