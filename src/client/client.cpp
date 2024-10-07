#include "client.h"

void client(int src_fd, int dest_fd)
{
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    while ((bytes_read = recv(src_fd, buffer, BUFFER_SIZE, 0)) > 0)
    {
        send(dest_fd, buffer, bytes_read, 0);
    }
    shutdown(dest_fd, SHUT_WR);
}