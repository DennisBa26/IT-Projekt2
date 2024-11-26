#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h> // Include for sleep()
#include <openssl/aes.h>
#include <openssl/evp.h>
#include "api.h"
#include "aes_crypto.h"
#define SHA256_DIGEST_LENGTH 32 // Define SHA-256 hash length
#define NUM_ITERATIONS 1000 // Define the number of iterations
#define CSV_FILE "server_timings_sphincs.csv"
#define LOG_FILE "server_log_sphincs.txt"

// Function to load data from a file
size_t load_from_file(const char *filename, uint8_t **data) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Could not open file %s for reading.\n", filename);
        exit(EXIT_FAILURE);
    }
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    rewind(file);
    *data = malloc(size);
    if (!*data) {
        fprintf(stderr, "Error: Could not allocate memory for reading data.\n");
        exit(EXIT_FAILURE);
    }
    fread(*data, 1, size, file);
    fclose(file);
    return size;
}

// Function to load a fixed-size array from a file
void load_array_from_file(const char *filename, uint8_t *array, size_t size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Could not open file %s for reading.\n", filename);
        exit(EXIT_FAILURE);
    }
    if (fread(array, 1, size, file) != size) {
        fprintf(stderr, "Error: Could not read the complete array from file %s.\n", filename);
        fclose(file);
        exit(EXIT_FAILURE);
    }
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

void wait_for_ready_flag() {
 while (access("ready.flag", F_OK) == -1) {
    usleep(10000); // sleep for 10ms
 }
 remove("ready.flag"); // clean up the flag file
}
int main() {
    // Open CSV and log files for writing the results
    FILE *csv_file = fopen(CSV_FILE, "w");
    FILE *log_file = fopen(LOG_FILE, "w");
    if (!csv_file || !log_file) {
        fprintf(stderr, "Error: Could not open output files.\n");
        return 1;
    }

    fprintf(csv_file, "Iteration,Verification Time (seconds)\n");
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        fprintf(log_file, "Iteration: %d\n", i + 1);
        // Wait for the client to signal readiness
        wait_for_ready_flag();
        uint8_t public_key[PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
        uint8_t *signature;
        uint8_t *data;
        size_t data_len;
        size_t signature_len = PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_BYTES;
        // Load public key from file
        load_array_from_file("public_key.bin", public_key, sizeof(public_key));
        // Load signature from file
        signature_len = load_from_file("signature.bin", &signature);
        // Load encrypted data from file
        data_len = load_from_file("encrypted_data.bin", &data);
        // Timing variables
        clock_t start, end;
        double cpu_time_used;
        // Hash the encrypted data
        unsigned char data_hash[SHA256_DIGEST_LENGTH];
        hash_data(data, data_len, data_hash);
        // Verify the signature on the hash of the encrypted data
        start = clock();
        int verification_result = PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_verify(signature,
        signature_len, data_hash, SHA256_DIGEST_LENGTH, public_key);
        end = clock();
        cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
        if (verification_result != 0) {
            fprintf(log_file, "Signature verification failed on iteration %d.\n", i + 1);
            free(signature);
            free(data);
            return 1;
        } else {
            fprintf(log_file, "Signature verification successful on iteration %d.\n", i + 1);
        }
        fprintf(log_file, "Verification Time: %f seconds\n", cpu_time_used);
        fprintf(csv_file, "%d,%f\n", i + 1, cpu_time_used);
        // Free allocated memory
        free(signature);
        free(data);
    }
    fclose(csv_file);
    fclose(log_file);
    return 0;
}