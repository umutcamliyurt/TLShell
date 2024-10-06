#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include <cstdlib>

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    // Use only TLS 1.3
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Disable all other versions to enforce only TLS 1.3
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void handle_client(int client_sock, SSL *ssl) {
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        std::cout << "Client connected!" << std::endl;
        std::string command;
        char buf[1024] = {0};

        while (true) {
            std::cout << "Enter command to send to client (type 'exit' to quit): ";
            std::getline(std::cin, command); // Get command input from the server

            if (command == "exit") {
                std::cout << "Closing connection." << std::endl;
                break; // Exit the loop if 'exit' is typed
            }

            // Send the command to the client
            SSL_write(ssl, command.c_str(), command.length());

            // Receive the output from the client
            int bytes = SSL_read(ssl, buf, sizeof(buf) - 1); // leave space for null terminator
            if (bytes > 0) {
                buf[bytes] = '\0'; // Null-terminate the buffer
                std::cout << "Client output: " << buf << std::endl;
            } else {
                std::cerr << "Error reading from client" << std::endl;
                break; // Break if there is an error
            }
        }
    }

    SSL_free(ssl);
    close(client_sock);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
        return EXIT_FAILURE;
    }

    int port = atoi(argv[1]);  // Convert argument to an integer
    if (port <= 0) {
        std::cerr << "Invalid port number." << std::endl;
        return EXIT_FAILURE;
    }

    initialize_openssl();

    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);  // Use the command-line argument as the port number
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, 1) < 0) {
        perror("Unable to listen");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    std::cout << "Server listening on port " << port << "..." << std::endl;

    while (true) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        int client_sock = accept(sockfd, (struct sockaddr*)&addr, &len);
        if (client_sock < 0) {
            perror("Unable to accept");
            close(sockfd);
            break;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);

        std::thread(handle_client, client_sock, ssl).detach();
    }

    close(sockfd);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
