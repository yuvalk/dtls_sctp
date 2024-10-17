#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>

#define SERVER_PORT 4433
#define BUFFER_SIZE 1024

void init_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_server_context() {
    SSL_CTX* ctx = SSL_CTX_new(DTLS_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set up certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

SSL_CTX* create_client_context() {
    SSL_CTX* ctx = SSL_CTX_new(DTLS_client_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // For demo purposes, don't verify server certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}

int create_sctp_server_socket() {
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(sock, 5) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    return sock;
}

int create_sctp_client_socket(const char* server_ip) {
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connect failed");
        exit(EXIT_FAILURE);
    }

    return sock;
}

void handle_server() {
    init_openssl();
    SSL_CTX* ctx = create_server_context();
    int server_sock = create_sctp_server_socket();

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_sock < 0) {
            perror("Accept failed");
            continue;
        }

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            char buffer[BUFFER_SIZE];
            int bytes = SSL_read(ssl, buffer, sizeof(buffer));
            if (bytes > 0) {
                buffer[bytes] = 0;
                printf("Received: %s\n", buffer);
                SSL_write(ssl, "Hello from server!", strlen("Hello from server!"));
            }
        }

        SSL_free(ssl);
        close(client_sock);
    }

    SSL_CTX_free(ctx);
    cleanup_openssl();
    close(server_sock);
}

void handle_client(const char* server_ip) {
    init_openssl();
    SSL_CTX* ctx = create_client_context();
    int sock = create_sctp_client_socket(server_ip);

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        const char* message = "Hello from client!";
        SSL_write(ssl, message, strlen(message));

        char buffer[BUFFER_SIZE];
        int bytes = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes > 0) {
            buffer[bytes] = 0;
            printf("Received: %s\n", buffer);
        }
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    close(sock);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s [-s|-c] [server_ip]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (strcmp(argv[1], "-s") == 0) {
        handle_server();
    } else if (strcmp(argv[1], "-c") == 0) {
        handle_client(argv[2]);
    } else {
        fprintf(stderr, "Invalid option. Use -s for server or -c for client\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}
