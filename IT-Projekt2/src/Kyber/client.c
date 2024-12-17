#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <curl/curl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <time.h>
#include "api.h"
#include "aes_utils.h"
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080
#define URL "https://ogcapi.hft-stuttgart.de/sta/icity_data_security/v1.1"
#define ITERATIONS 1000
#define CSV_FILE "client_timings.csv"
#define LOG_FILE "client_log.txt"
#define RETRY_DELAY 1000000 // 1 second

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t totalSize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + totalSize + 1);
    if (ptr == NULL) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, totalSize);
    mem->size += totalSize;
    mem->memory[mem->size] = 0;
    return totalSize;
}

int main() {
    CURL *curl_handle;
    CURLcode res;
    struct MemoryStruct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;
    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL, URL);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
    res = curl_easy_perform(curl_handle);

    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        return 1;
    }

    curl_easy_cleanup(curl_handle);
    curl_global_cleanup();
    uint8_t public_key[PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t ciphertext[PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t shared_secret[PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES];
    double total_encap_time = 0;
    FILE *csv_file = fopen(CSV_FILE, "w");
    FILE *log_file = fopen(LOG_FILE, "w");

    if (csv_file == NULL || log_file == NULL) {
        printf("Unable to create output files.\n");
        return 1;
    }

    fprintf(csv_file, "Iteration,Encapsulation Time (seconds)\n");
    for (int i = 0; i < ITERATIONS; i++) {
        int sock = 0;
        struct sockaddr_in serv_addr;
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(log_file, "Socket creation error (iteration %d)\n", i+1);
        return 1;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        fprintf(log_file, "Invalid address/Address not supported (iteration %d)\n", i+1);
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(log_file, "Connection Failed (iteration %d)\n", i+1);
        close(sock);
        usleep(RETRY_DELAY);
        continue;
    }

    // Request public key
    const char *request = "Requesting Public Key";
    send(sock, request, strlen(request), 0);
    if (read(sock, public_key, PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES) <= 0) {
        fprintf(log_file, "Failed to receive public key from server (iteration %d).\n", i+1);
        close(sock);
        continue;
    }

    clock_t start_encap = clock();
    if (PQCLEAN_KYBER1024_CLEAN_crypto_kem_enc(ciphertext, shared_secret, public_key) != 0) {
        fprintf(log_file, "Encapsulation failed (iteration %d).\n", i+1);
        close(sock);
        return 1;
    }

    clock_t end_encap = clock();
    double encap_time = (double)(end_encap - start_encap) / CLOCKS_PER_SEC;
    total_encap_time += encap_time;
    fprintf(csv_file, "%d,%f\n", i+1, encap_time);
    fprintf(log_file, "Encapsulation Time (iteration %d): %f seconds\n", i+1, encap_time);
    send(sock, ciphertext, PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES, 0);
    unsigned char aes_key[32];
    SHA256(shared_secret, sizeof(shared_secret), aes_key);
    unsigned char iv[16];

    if (!RAND_bytes(iv, sizeof(iv))) {
        fprintf(log_file, "Failed to generate random IV (iteration %d).\n", i+1);
        close(sock);
        return 1;
    }

    unsigned char encrypted_data[4096];
    int encrypted_data_len = aes_encrypt(chunk.memory, chunk.size, aes_key, iv, encrypted_data);
    send(sock, iv, sizeof(iv), 0);
    send(sock, encrypted_data, encrypted_data_len, 0);
    fprintf(log_file, "Encrypted data sent to server (iteration %d).\n", i+1);
    // Wait for server acknowledgment before proceeding
    char server_ack[16];
    if (recv(sock, server_ack, sizeof(server_ack), 0) <= 0) {
        fprintf(log_file, "Failed to receive server acknowledgment (iteration %d).\n", i+1);
        close(sock);
        usleep(RETRY_DELAY);
        continue;
    } else {
        fprintf(log_file, "Server acknowledged (iteration %d): %s\n", i+1, server_ack);
    }
    
    close(sock); // Close the socket after each iteration
    usleep(RETRY_DELAY); // Delay to ensure the server is ready for the next connection
    }
    fprintf(log_file, "Average Encapsulation Time: %f seconds\n", total_encap_time / ITERATIONS);
    fprintf(csv_file, "Average,%f\n", total_encap_time / ITERATIONS);
    fclose(csv_file);
    fclose(log_file);
    free(chunk.memory);
    return 0;
}