// serialization_manager.h

#ifndef SERIALIZATION_MANAGER_H
#define SERIALIZATION_MANAGER_H

#include "server.h"
#include "logger.h"
#include <memory>

void serialization_manager(std::shared_ptr<Server::Data> internal);
void dump_tcp_option_counts(std::shared_ptr<Server::Data> internal);
void dump_tcp_flag_counts(std::shared_ptr<Server::Data> internal);

#endif // SERIALIZATION_MANAGER_H
