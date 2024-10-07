#ifndef CLIENT
#define CLIENT

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include "client.h"

const int BUFFER_SIZE = 4096;

void client(int src_fd, int dest_fd);

#endif
