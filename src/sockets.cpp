#include "sockets.h"


void setup_raw_socket()
{
    // Create a raw socket
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket == -1)
    {
        perror("Failed to create raw socket");
        exit(EXIT_FAILURE);
    }

    // Get the interface index
    struct ifreq ifr
    {
    };
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(raw_socket, SIOCGIFINDEX, &ifr) == -1)
    {
        perror("Failed to get interface index");
        close(raw_socket);
        exit(EXIT_FAILURE);
    }
    if_index = ifr.ifr_ifindex;

    // Get the source MAC address
    if (ioctl(raw_socket, SIOCGIFHWADDR, &ifr) == -1)
    {
        perror("Failed to get MAC address");
        close(raw_socket);
        exit(EXIT_FAILURE);
    }
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);
}