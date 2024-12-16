#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h> // Include for sleep()
#include <curl/curl.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include "api.h"
#include "aes_crypto.h"
#define SHA256_DIGEST_LENGTH 32 // Define SHA-256 hash length
#define NUM_ITERATIONS 1000 // Define the number of iterations
#define CSV_FILE "client_timings_sphincs.csv"
#define LOG_FILE "client_log_sphincs.txt"

// Function to download data from a URL
size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream) {
 size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
 return written;
}

void download_data(const char *url, const char *file_name) {
    CURL *curl;
    FILE *fp;
    CURLcode res;
    curl = curl_easy_init();
    if (curl) {
        fp = fopen(file_name, "wb");
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        fclose(fp);
    }
}

void save_to_file(const char *filename, const uint8_t *data, size_t size) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        fprintf(stderr, "Error: Could not open file %s for writing.\n", filename);
        exit(EXIT_FAILURE);
    }
    fwrite(data, 1, size, file);
    fclose(file);
}

// Function to hash data using the EVP interface (SHA-256)
void hash_data(const unsigned char *data, size_t data_len, unsigned char *output_hash) {
    EVP_MD_CTX *mdctx;
    unsigned int hash_len;
    // Create and initialize the context
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Failed to create hash context.\n");
        exit(EXIT_FAILURE);
    }
    // Initialize the hash function (SHA-256)
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        fprintf(stderr, "Failed to initialize hash function.\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }
    // Update the hash with the data
    if (1 != EVP_DigestUpdate(mdctx, data, data_len)) {
        fprintf(stderr, "Failed to update hash with data.\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }
    // Finalize the hash and retrieve the result
    if (1 != EVP_DigestFinal_ex(mdctx, output_hash, &hash_len)) {
        fprintf(stderr, "Failed to finalize hash.\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }
    // Free the context
    EVP_MD_CTX_free(mdctx);
}

void write_ready_flag() {
    FILE *file = fopen("ready.flag", "w");
    if (!file) {
        fprintf(stderr, "Error: Could not create ready flag.\n");
        exit(EXIT_FAILURE);
    }
    fprintf(file, "ready");
    fclose(file);
}

int main() {
    double total_key_generation_time = 0.0;
    double total_signing_time = 0.0;
    // Open CSV file for writing the results
    FILE *csv_file = fopen(CSV_FILE, "w");
    FILE *log_file = fopen(LOG_FILE, "w");
    if (!csv_file || !log_file) {
        fprintf(stderr, "Error: Could not open output files.\n");
        return 1;
    }

    fprintf(csv_file, "Iteration,Key Generation Time (seconds),Signing Time (seconds)\n");
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        fprintf(log_file, "Iteration: %d\n", i + 1);

        uint8_t public_key[PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
        uint8_t secret_key[PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
        uint8_t signature[PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_BYTES];
        size_t signature_len;
        // AES key and IV
        unsigned char key[32]; // 256-bit key
        unsigned char iv[16]; // 128-bit IV
        memset(key, 0x00, sizeof(key)); // Set key to all 0s (in real scenarios, use a secure key)
        memset(iv, 0x00, sizeof(iv)); // Set IV to all 0s
        // Download data
        const char *url = "https://ogcapi.hft-stuttgart.de/sta/icity_data_security/v1.1";
        const char *file_name = "data.json";
        download_data(url, file_name);
        // Read data from file
        FILE *file = fopen(file_name, "rb");
        if (!file) {
            fprintf(log_file, "Error: Could not open file %s for reading.\n", file_name);
            return 1;
        }

        fseek(file, 0, SEEK_END);
        size_t message_len = ftell(file);
        rewind(file);
        uint8_t *message = malloc(message_len);
        if (!message) {
            fprintf(log_file, "Error: Could not allocate memory for message.\n");
            fclose(file);
            return 1;
        }

        fread(message, 1, message_len, file);
        fclose(file);
        // Encrypt the data before signing
        unsigned char *ciphertext = malloc(message_len + AES_BLOCK_SIZE);
        int ciphertext_len = encrypt(message, message_len, key, iv, ciphertext);
        // Save the ciphertext to a file
        save_to_file("encrypted_data.bin", ciphertext, ciphertext_len);
        // Hash the encrypted data
        unsigned char data_hash[SHA256_DIGEST_LENGTH];
        hash_data(ciphertext, ciphertext_len, data_hash);
        // Timing variables
        clock_t start, end;
        double cpu_time_used;
        // Key pair generation
        start = clock();
        if (PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_keypair(public_key, secret_key) != 0) {
            fprintf(log_file, "Key pair generation failed.\n");
            free(message);
            free(ciphertext);
            return 1;
        }

        end =  clock();
        cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
        fprintf(log_file, "Key Generation Time: %f seconds\n", cpu_time_used);
        total_key_generation_time += cpu_time_used;
        // Save public key
        save_to_file("public_key.bin", public_key, sizeof(public_key));
        // Signing the hash of the encrypted message
        start = clock();

        if (PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_signature(signature, &signature_len,
            data_hash, SHA256_DIGEST_LENGTH, secret_key) != 0) {
            fprintf(log_file, "Signing failed.\n");
            free(message);
            free(ciphertext);
            return 1;
        }

        end = clock();
        cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
        fprintf(log_file, "Signing Time: %f seconds\n", cpu_time_used);
        total_signing_time += cpu_time_used;
        // Save signature
        save_to_file("signature.bin", signature, signature_len);
        // Write results to CSV
         fprintf(csv_file, "%d,%f,%f\n", i + 1, total_key_generation_time / (i + 1), total_signing_time / (i + 1));
        // Free allocated memory
        free(message);
        free(ciphertext);
        // Write ready flag file
        write_ready_flag();
        fprintf(log_file, "Iteration %d complete.\n", i + 1);
    }

    fprintf(csv_file, "Average,%f,%f\n", total_key_generation_time / NUM_ITERATIONS, total_signing_time /
        NUM_ITERATIONS);
    fclose(csv_file);
    fclose(log_file);
    return 0;
}
