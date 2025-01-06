#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>
#include <openssl/evp.h>
#include <omp.h>

#define MAX_HASH_LEN 33
#define MAX_LINE_LEN 256

// Global pointer to weights for the comparator in qsort
static int *g_weights = NULL;

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
    output[32] = '\0';
}

// Dynamically load hashes from file into a char**. Returns count of hashes.
int load_hashes(const char *filename, char ***hashes_out) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open hashes file");
        return -1;
    }

    int capacity = 10000; // Initial guess, can be larger if needed
    char **hashes = (char **)malloc(capacity * sizeof(char *));
    if (!hashes) {
        perror("malloc failed for hashes");
        fclose(file);
        return -1;
    }

    int count = 0;
    char line[MAX_HASH_LEN];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (count == capacity) {
            capacity *= 2;
            char **new_hashes = (char **)realloc(hashes, capacity * sizeof(char *));
            if (!new_hashes) {
                perror("realloc failed for hashes");
                // cleanup
                for (int i = 0; i < count; i++) free(hashes[i]);
                free(hashes);
                fclose(file);
                return -1;
            }
            hashes = new_hashes;
        }
        hashes[count] = strdup(line);
        if (!hashes[count]) {
            perror("strdup failed for a hash");
            // cleanup
            for (int i = 0; i < count; i++) free(hashes[i]);
            free(hashes);
            fclose(file);
            return -1;
        }
        count++;
    }
    fclose(file);
    *hashes_out = hashes;
    return count;
}

// Comparator for sorting indices by descending weight
int compare_weights_desc(const void *a, const void *b) {
    int idx_a = *(int *)a;
    int idx_b = *(int *)b;
    if (g_weights[idx_a] > g_weights[idx_b]) return -1;
    if (g_weights[idx_a] < g_weights[idx_b]) return 1;
    return 0;
}

// Simple integer compare for qsort
static int int_compare(const void *a, const void *b) {
    int x = *(int*)a;
    int y = *(int*)b;
    return (x < y) ? -1 : (x > y);
}

// Dynamically read line lengths from rockyou.txt (only on rank 0)
// Returns arrays by reference: weights_out and password_count_out
int load_dictionary_weights(const char *filename, int **weights_out, int *password_count_out) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("Failed to open rockyou.txt");
        return -1;
    }

    int capacity = 100000; // initial guess
    int *weights = (int *)malloc(capacity * sizeof(int));
    if (!weights) {
        perror("malloc failed for weights");
        fclose(f);
        return -1;
    }

    int count = 0;
    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (count == capacity) {
            capacity *= 2;
            int *new_weights = (int *)realloc(weights, capacity * sizeof(int));
            if (!new_weights) {
                perror("realloc failed for weights");
                free(weights);
                fclose(f);
                return -1;
            }
            weights = new_weights;
        }
        weights[count] = (int)strlen(line);
        count++;
    }
    fclose(f);

    *weights_out = weights;
    *password_count_out = count;
    return 0;
}

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);
    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    double start_time = MPI_Wtime();

    // Load hashes on rank 0
    char **hashes = NULL;
    int hash_count = 0;
    if (rank == 0) {
        hash_count = load_hashes("hashes.txt", &hashes);
        if (hash_count == -1) {
            MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
        }
        printf("Loaded %d hashes.\n", hash_count);
    }

    // Broadcast hash_count
    MPI_Bcast(&hash_count, 1, MPI_INT, 0, MPI_COMM_WORLD);

    // Broadcast all hashes
    // First, we need to broadcast the total length of all hashes combined.
    // Pack hashes into a contiguous buffer for broadcasting.
    int total_hash_chars = 0;
    if (rank == 0) {
        for (int i = 0; i < hash_count; i++) {
            // +1 for null terminator
            total_hash_chars += (int)(strlen(hashes[i]) + 1);
        }
    }
    MPI_Bcast(&total_hash_chars, 1, MPI_INT, 0, MPI_COMM_WORLD);

    char *hash_buffer = NULL;
    int *hash_lengths = NULL; 
    if (rank == 0) {
        hash_buffer = (char *)malloc(total_hash_chars * sizeof(char));
        hash_lengths = (int *)malloc(hash_count * sizeof(int));
        if (!hash_buffer || !hash_lengths) {
            perror("malloc failed for hash_buffer/hash_lengths");
            MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
        }

        // Copy hashes into buffer
        int pos = 0;
        for (int i = 0; i < hash_count; i++) {
            int len = (int)strlen(hashes[i]) + 1;
            memcpy(hash_buffer + pos, hashes[i], len);
            hash_lengths[i] = len;
            pos += len;
        }
    } else {
        // Non-root ranks allocate buffer after receiving lengths
        hash_lengths = (int *)malloc(hash_count * sizeof(int));
        if (!hash_lengths) {
            perror("malloc failed for hash_lengths on non-root");
            MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
        }
    }

    // Broadcast individual hash lengths
    MPI_Bcast(hash_lengths, hash_count, MPI_INT, 0, MPI_COMM_WORLD);

    if (rank != 0) {
        hash_buffer = (char *)malloc(total_hash_chars * sizeof(char));
        if (!hash_buffer) {
            perror("malloc failed for hash_buffer on non-root");
            MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
        }
    }

    // Broadcast the buffer
    MPI_Bcast(hash_buffer, total_hash_chars, MPI_CHAR, 0, MPI_COMM_WORLD);

    // Rebuild hashes array on non-root processes
    if (rank != 0) {
        hashes = (char **)malloc(hash_count * sizeof(char *));
        if (!hashes) {
            perror("malloc failed for hashes on non-root");
            MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
        }
        int pos = 0;
        for (int i = 0; i < hash_count; i++) {
            hashes[i] = hash_buffer + pos;
            pos += hash_lengths[i];
        }
    }

    int password_count = 0;
    int *weights = NULL;
    int *partition_assignments = NULL;
    int *partition_sizes = NULL;

    if (rank == 0) {
        // Load dictionary line lengths
        if (load_dictionary_weights("rockyou.txt", &weights, &password_count) == -1) {
            MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
        }

        printf("Loaded %d dictionary lines.\n", password_count);

        // Prepare indices and sort by descending weight
        int *indices = (int *)malloc(password_count * sizeof(int));
        if (!indices) {
            perror("malloc failed for indices");
            MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
        }
        for (int i = 0; i < password_count; i++) {
            indices[i] = i;
        }

        g_weights = weights;
        qsort(indices, password_count, sizeof(int), compare_weights_desc);

        partition_assignments = (int *)malloc(password_count * sizeof(int));
        partition_sizes = (int *)calloc(size, sizeof(int));
        if (!partition_assignments || !partition_sizes) {
            perror("malloc failed for partition arrays");
            MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
        }

        int *current_weights = (int *)calloc(size, sizeof(int));
        if (!current_weights) {
            perror("malloc failed for current_weights");
            MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
        }

        // First-fit decreasing bin packing to assign passwords to ranks
        for (int i = 0; i < password_count; i++) {
            int pwd_idx = indices[i];
            int min_proc = 0;
            for (int j = 1; j < size; j++) {
                if (current_weights[j] < current_weights[min_proc]) {
                    min_proc = j;
                }
            }
            partition_assignments[pwd_idx] = min_proc;
            partition_sizes[min_proc]++;
            current_weights[min_proc] += weights[pwd_idx];
        }

        free(current_weights);
        free(indices);
    }

    // Broadcast password_count so others can allocate arrays
    MPI_Bcast(&password_count, 1, MPI_INT, 0, MPI_COMM_WORLD);

    if (rank != 0) {
        weights = (int *)malloc(password_count * sizeof(int));
        partition_assignments = (int *)malloc(password_count * sizeof(int));
        partition_sizes = (int *)malloc(size * sizeof(int));
        if (!weights || !partition_assignments || !partition_sizes) {
            perror("malloc failed for arrays on non-root");
            MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
        }
    }

    MPI_Bcast(weights, password_count, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(partition_assignments, password_count, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(partition_sizes, size, MPI_INT, 0, MPI_COMM_WORLD);

    int local_size = partition_sizes[rank];
    int *local_indexes = (int *)malloc(local_size * sizeof(int));
    if (!local_indexes) {
        perror("malloc failed for local_indexes");
        MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
    }

    // Collect indexes for this rank
    {
        int pos = 0;
        for (int i = 0; i < password_count; i++) {
            if (partition_assignments[i] == rank) {
                local_indexes[pos++] = i;
            }
        }
    }

    // Sort indexes for sequential reading
    qsort(local_indexes, local_size, sizeof(int), int_compare);

    // Now read only the assigned lines from rockyou.txt
    FILE *f = fopen("rockyou.txt", "r");
    if (!f) {
        perror("Failed to open rockyou.txt on all ranks");
        MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
    }

    char **local_lines = (char **)malloc(local_size * sizeof(char *));
    if (!local_lines) {
        perror("malloc failed for local_lines");
        MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
    }

    int current_line = 0;
    int next_index_pos = 0;
    int target_index = (local_size > 0) ? local_indexes[next_index_pos] : -1;
    char line[MAX_LINE_LEN];

    while (fgets(line, sizeof(line), f) && next_index_pos < local_size) {
        if (current_line == target_index) {
            line[strcspn(line, "\r\n")] = '\0';
            local_lines[next_index_pos] = strdup(line);
            if (!local_lines[next_index_pos]) {
                perror("strdup failed for local line");
                MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
            }
            next_index_pos++;
            if (next_index_pos < local_size)
                target_index = local_indexes[next_index_pos];
        }
        current_line++;
    }
    fclose(f);

    int local_matches = 0;

    // Use OpenMP to parallelize the MD5 and comparison steps
    #pragma omp parallel
    {
        char md5_output[MAX_HASH_LEN];
        int thread_local_matches = 0;

        #pragma omp for
        for (int i = 0; i < local_size; i++) {
            compute_md5(local_lines[i], md5_output);
            // Check against all hashes
            for (int j = 0; j < hash_count; j++) {
                if (strcmp(md5_output, hashes[j]) == 0) {
                    #pragma omp critical
                    {
                        printf("Match found: %s -> %s (Rank %d)\n", local_lines[i], hashes[j], rank);
                    }
                    thread_local_matches++;
                    break;
                }
            }
        }

        #pragma omp atomic
        local_matches += thread_local_matches;
    }

    int total_matches = 0;
    MPI_Reduce(&local_matches, &total_matches, 1, MPI_INT, MPI_SUM, 0, MPI_COMM_WORLD);

    if (rank == 0) {
        printf("Total matches found: %d\n", total_matches);
    }

    double end_time = MPI_Wtime();
    if (rank == 0) {
        printf("Computation Time: %f seconds\n", end_time - start_time);
    }

    // Cleanup
    for (int i = 0; i < local_size; i++) {
        free(local_lines[i]);
    }
    free(local_lines);
    free(local_indexes);
    free(weights);
    free(partition_assignments);
    free(partition_sizes);

    if (rank == 0) {
        for (int i = 0; i < hash_count; i++) {
            // On rank 0 we allocated and duplicated them
            free(hashes[i]);
        }
        free(hashes);
        free(hash_buffer);
        free(hash_lengths);
    } else {
        // On non-root ranks, we just allocated hashes array pointing into hash_buffer
        free(hashes); 
        free(hash_buffer);
        free(hash_lengths);
    }

    MPI_Finalize();
    return 0;
}
