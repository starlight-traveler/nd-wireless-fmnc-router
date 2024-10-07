#include <iostream>
#include <thread>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

void handle_connection(int client_sock)
{
    // Connect to the actual server
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0)
    {
        perror("Server socket creation failed");
        close(client_sock);
        return;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8085);                        // Server's port
    inet_pton(AF_INET, "192.168.1.50", &server_addr.sin_addr); // Server's IP

    if (connect(server_sock, (sockaddr *)&server_addr, sizeof(server_addr)) != 0)
    {
        perror("Connection to server failed");
        close(client_sock);
        close(server_sock);
        return;
    }

    // Start threads to forward data between client and server
    std::thread forward_client_to_server([client_sock, server_sock]()
                                         {
        char buffer[4096];
        ssize_t bytes;
        while ((bytes = recv(client_sock, buffer, sizeof(buffer), 0)) > 0) {
            if (send(server_sock, buffer, bytes, 0) < 0) {
                perror("Send to server failed");
                break;
            }
        }
        shutdown(server_sock, SHUT_WR); });

    std::thread forward_server_to_client([client_sock, server_sock]()
                                         {
        char buffer[4096];
        ssize_t bytes;
        while ((bytes = recv(server_sock, buffer, sizeof(buffer), 0)) > 0) {
            if (send(client_sock, buffer, bytes, 0) < 0) {
                perror("Send to client failed");
                break;
            }
        }
        shutdown(client_sock, SHUT_WR); });

    // Wait for threads to finish
    forward_client_to_server.join();
    forward_server_to_client.join();

    close(client_sock);
    close(server_sock);
}

int main()
{
    const int listen_port = 8081; // Port that clients connect to

    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0)
    {
        perror("Listening socket creation failed");
        return 1;
    }

    sockaddr_in listen_addr{};
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(listen_port);
    listen_addr.sin_addr.s_addr = INADDR_ANY;

    // Allow the socket to be reused immediately after program exits
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(listen_sock, (sockaddr *)&listen_addr, sizeof(listen_addr)) != 0)
    {
        perror("Bind failed");
        close(listen_sock);
        return 1;
    }

    if (listen(listen_sock, 5) != 0)
    {
        perror("Listen failed");
        close(listen_sock);
        return 1;
    }

    std::cout << "Proxy server is listening on port " << listen_port << std::endl;

    while (true)
    {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(listen_sock, (sockaddr *)&client_addr, &client_len);
        if (client_sock < 0)
        {
            perror("Accept failed");
            continue;
        }

        // Handle each client connection in a separate thread
        std::thread(handle_connection, client_sock).detach();
    }

    close(listen_sock);
    return 0;
}
