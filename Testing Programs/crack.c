#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <sys/time.h>

#define MAX_HASHES 1000
#define MAX_LINE_LEN 256

char *hashes[MAX_HASHES];
int hash_count = 0;

void compute_md5(const char *str, char *output) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Failed to create EVP_MD_CTX\n");
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, str, strlen(str)) != 1 ||
        EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) {
        fprintf(stderr, "MD5 computation failed\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(mdctx);

    for (unsigned int i = 0; i < digest_len; i++) {
        sprintf(&output[i * 2], "%02x", digest[i]);
    }
    output[32] = '\0'; // Null-terminate
}

int load_file(const char *filename, char *array[], int max_lines) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file");
        return -1;
    }

    char line[MAX_LINE_LEN];
    int count = 0;

    while (fgets(line, sizeof(line), file) && count < max_lines) {
        line[strcspn(line, "\r\n")] = '\0'; // Remove newline
        array[count] = strdup(line);
        count++;
    }

    fclose(file);
    return count;
}

int main() {
    hash_count = load_file("hashes.txt", hashes, MAX_HASHES);
    if (hash_count == -1) {
        fprintf(stderr, "Failed to load hashes.\n");
        return EXIT_FAILURE;
    }

    printf("Loaded %d hashes.\n", hash_count);

    // Open the dictionary file (rockyou.txt)
    FILE *dict_file = fopen("rockyou.txt", "r");
    if (!dict_file) {
        perror("Failed to open dictionary file");
        return EXIT_FAILURE;
    }

    struct timeval start, end;
    gettimeofday(&start, NULL);

    // Process the dictionary line-by-line
    char line[MAX_LINE_LEN];
    int match_count = 0;
    while (fgets(line, sizeof(line), dict_file)) {
        line[strcspn(line, "\r\n")] = '\0'; // Strip newline

        char md5_output[33];
        compute_md5(line, md5_output);

        // Check against all hashes
        for (int j = 0; j < hash_count; j++) {
            if (strcmp(md5_output, hashes[j]) == 0) {
                printf("Match %d: %s -> %s\n", ++match_count, line, hashes[j]);
                // If you know each hash is unique and only one match is needed per hash,
                // you could break here. Otherwise, keep checking.
            }
        }
    }

    fclose(dict_file);

    gettimeofday(&end, NULL);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)/1000000.0;

    printf("\nTotal matches found: %d\n", match_count);
    printf("Time taken: %.2f seconds\n", elapsed);

    // Cleanup
    for (int i = 0; i < hash_count; i++) {
        free(hashes[i]);
    }

    return 0;
}
