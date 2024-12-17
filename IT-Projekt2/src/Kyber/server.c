#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <time.h>
#include "api.h"
#include "/Users/flrnvsc/Documents/Visual Studio 2015/IT-Projekt2/IT-Projekt2/IT-Projekt2/include/PQClean/crypto_kem/kyber1024/clean/api.h"
#define PORT 8080
#define ITERATIONS 1000
#define CSV_FILE "server_timings.csv"
#define LOG_FILE "server_log.txt"

int main() {
    double total_keygen_time = 0;
    double total_decap_time = 0;
    FILE *csv_file = fopen(CSV_FILE, "w");
    FILE *log_file = fopen(LOG_FILE, "w");

    if (csv_file == NULL || log_file == NULL) {
        printf("Unable to create output files.\n");
        return 1;
    }

    fprintf(csv_file, "Iteration,Key Generation Time (seconds),Decapsulation Time (seconds)\n");
    for (int i = 0; i < ITERATIONS; i++) {
        int server_fd, new_socket;
        struct sockaddr_in address;
        socklen_t addrlen = sizeof(address);
        uint8_t public_key[PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
        uint8_t secret_key[PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES];
        uint8_t ciphertext[PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES];
        uint8_t shared_secret[PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES];
        clock_t start_keygen = clock();

        if (PQCLEAN_KYBER1024_CLEAN_crypto_kem_keypair(public_key, secret_key) != 0) {
            fprintf(log_file, "Key pair generation failed (iteration %d).\n", i+1);
            return 1;
        }
        clock_t end_keygen = clock();
        double keygen_time = (double)(end_keygen - start_keygen) / CLOCKS_PER_SEC;
        total_keygen_time += keygen_time;
        fprintf(log_file, "Key Generation Time (iteration %d): %f seconds\n", i+1, keygen_time);

        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
            perror("Socket failed");
            exit(EXIT_FAILURE);
        }

        int opt = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            perror("setsockopt failed");
            exit(EXIT_FAILURE);
        }

        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(PORT);
        if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
            perror("Bind failed");
            exit(EXIT_FAILURE);
        }

        if (listen(server_fd, 3) < 0) {
            perror("Listen failed");
            exit(EXIT_FAILURE);
        }
        new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen);
        if (new_socket < 0) {
            perror("Accept failed");
            exit(EXIT_FAILURE);
        }

        // Receive request for public key from client
        char client_request[64];
        if (recv(new_socket, client_request, sizeof(client_request), 0) <= 0) {
            fprintf(log_file, "Failed to receive client request (iteration %d).\n", i+1);
            close(new_socket);
            close(server_fd);
            continue;
        }

        send(new_socket, public_key, PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES, 0);
        fprintf(log_file, "Public key sent to client (iteration %d).\n", i+1);
        read(new_socket, ciphertext, PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES);
        fprintf(log_file, "Ciphertext received from client (iteration %d).\n", i+1);
        clock_t start_decap = clock();
        if (PQCLEAN_KYBER1024_CLEAN_crypto_kem_dec(shared_secret, ciphertext, secret_key) != 0) {
            fprintf(log_file, "Decapsulation failed (iteration %d).\n", i+1);
            close(new_socket);
            close(server_fd);
            return 1;
        }
        clock_t end_decap = clock();
        double decap_time = (double)(end_decap - start_decap) / CLOCKS_PER_SEC;
        total_decap_time += decap_time;
        fprintf(log_file, "Decapsulation Time (iteration %d): %f seconds\n", i+1, decap_time);
        fprintf(csv_file, "%d,%f,%f\n", i+1, keygen_time, decap_time);
        unsigned char aes_key[32];
        SHA256(shared_secret, sizeof(shared_secret), aes_key);
        unsigned char iv[16];
        read(new_socket, iv, sizeof(iv));
        unsigned char encrypted_data[4096];
        int encrypted_data_len = read(new_socket, encrypted_data, sizeof(encrypted_data));
        fprintf(log_file, "Encrypted data received from client (iteration %d).\n", i+1);
        unsigned char decrypted_data[4096];
        int decrypted_data_len = aes_decrypt(encrypted_data, encrypted_data_len, aes_key, iv, decrypted_data);
        if (decrypted_data_len >= 0) {
            fprintf(log_file, "Decrypted data (iteration %d): %.100s...\n", i+1, decrypted_data);
        } else {
            fprintf(log_file, "Decryption failed (iteration %d).\n", i+1);
        }
        // Send acknowledgment to the client
        const char *ack = "Received";
        send(new_socket, ack, strlen(ack), 0);
        close(new_socket);
        close(server_fd);
    }

    fprintf(log_file, "Average Key Generation Time: %f seconds\n", total_keygen_time / ITERATIONS);
    fprintf(log_file, "Average Decapsulation Time: %f seconds\n", total_decap_time / ITERATIONS);
    fprintf(csv_file, "Average,%f,%f\n", total_keygen_time / ITERATIONS, total_decap_time / ITERATIONS);
    fclose(csv_file);
    fclose(log_file);
    return 0;
}