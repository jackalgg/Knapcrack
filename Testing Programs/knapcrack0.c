#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>
#include <openssl/evp.h>
#include <ctype.h>

#define MAX_HASH_LEN 33 // MD5 hash length (32 chars) + null terminator
#define MAX_LINE_LEN 256
#define MAX_HASHES 100000 // Adjust as needed

// Function to compute the MD5 hash of a string
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
    output[32] = '\0'; // Null-terminate the hash string
}

// Function to read hashes from file
int load_hashes(const char *filename, char hashes[][MAX_HASH_LEN], int max_hashes) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open hashes file");
        return -1;
    }

    char line[MAX_HASH_LEN];
    int count = 0;

    while (fgets(line, sizeof(line), file) && count < max_hashes) {
        line[strcspn(line, "\r\n")] = '\0'; // Remove newline
        strncpy(hashes[count], line, MAX_HASH_LEN);
        count++;
    }

    fclose(file);
    return count;
}

// Count total lines in a file
long count_lines(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file for line counting");
        return -1;
    }

    long lines = 0;
    char buffer[MAX_LINE_LEN];
    while (fgets(buffer, sizeof(buffer), file)) {
        lines++;
    }

    fclose(file);
    return lines;
}

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);
    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    double start_time = MPI_Wtime(); // Start timing

    // Load hashes (only root process)
    char (*hashes)[MAX_HASH_LEN] = malloc(sizeof(char[MAX_HASHES][MAX_HASH_LEN]));
    int hash_count = 0;
    if (rank == 0) {
        hash_count = load_hashes("hashes.txt", hashes, MAX_HASHES);
        if (hash_count == -1) {
            MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
        }
        printf("Loaded %d hashes.\n", hash_count);
    }

    // Broadcast the number of hashes and the hashes themselves
    MPI_Bcast(&hash_count, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(hashes, hash_count * MAX_HASH_LEN, MPI_CHAR, 0, MPI_COMM_WORLD);

    // Count total lines in the dictionary (only rank 0)
    long total_lines = 0;
    if (rank == 0) {
        total_lines = count_lines("rockyou.txt");
        if (total_lines == -1) {
            MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
        }
        printf("Total dictionary lines: %ld\n", total_lines);
    }

    // Broadcast total_lines
    MPI_Bcast(&total_lines, 1, MPI_LONG, 0, MPI_COMM_WORLD);

    // Calculate per-process line range
    long lines_per_proc = total_lines / size;
    long start_line = rank * lines_per_proc;
    long end_line = (rank == size - 1) ? total_lines : start_line + lines_per_proc;

    // Open rockyou.txt again and move to the start_line
    FILE *dict_file = fopen("rockyou.txt", "r");
    if (!dict_file) {
        perror("Failed to open rockyou.txt");
        MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
    }

    // Skip lines up to start_line
    for (long i = 0; i < start_line; i++) {
        if (fgets((char[2]){}, 2, dict_file) == NULL) {
            // In case file is shorter than expected
            break;
        }
    }

    // Process lines from start_line to end_line
    char line[MAX_LINE_LEN];
    char md5_output[MAX_HASH_LEN];
    int local_matches = 0;

    for (long current_line = start_line; current_line < end_line; current_line++) {
        if (!fgets(line, sizeof(line), dict_file)) {
            // If no more lines are available, break early
            break;
        }
        line[strcspn(line, "\r\n")] = '\0'; // Remove newline

        // Compute MD5
        compute_md5(line, md5_output);

        // Compare with hashes
        for (int i = 0; i < hash_count; i++) {
            if (strcmp(md5_output, hashes[i]) == 0) {
                printf("Match found: %s -> %s (Rank %d)\n", line, hashes[i], rank);
                local_matches++;
                break; // Stop after first match to save time
            }
        }
    }

    fclose(dict_file);

    // Gather match counts
    int total_matches = 0;
    MPI_Reduce(&local_matches, &total_matches, 1, MPI_INT, MPI_SUM, 0, MPI_COMM_WORLD);

    double end_time = MPI_Wtime(); // End timing
    double elapsed = end_time - start_time;

    if (rank == 0) {
        printf("Total matches found: %d\n", total_matches);
        printf("Total time taken: %f seconds\n", elapsed);
    }

    free(hashes);
    MPI_Finalize();
    return 0;
}
