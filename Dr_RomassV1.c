#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/sha.h>

#define MAX_PATH_LEN 256

// Function to calculate the SHA256 checksum of a file
int calculate_sha256_checksum(const char *file_path, unsigned char *checksum) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("Error opening file");
        return -1;
    }

    SHA256_CTX sha256_context;
    SHA256_Init(&sha256_context);

    unsigned char buffer[1024];
    size_t bytes;

    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        SHA256_Update(&sha256_context, buffer, bytes);
    }

    SHA256_Final(checksum, &sha256_context);

    fclose(file);
    return 0;
}

// Function to recursively monitor a directory for file changes
void monitor_directory(const char *dir_path, unsigned char *prev_checksum) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        perror("Error opening directory");
        return;
    }

    struct dirent *entry;
    char file_path[MAX_PATH_LEN];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue; // Skip "." and ".." entries
        }

        snprintf(file_path, MAX_PATH_LEN, "%s/%s", dir_path, entry->d_name);

        if (entry->d_type == DT_DIR) {
            monitor_directory(file_path, prev_checksum); // Recursively monitor subdirectories
        } else if (entry->d_type == DT_REG) {
            unsigned char checksum[SHA256_DIGEST_LENGTH];

            if (calculate_sha256_checksum(file_path, checksum) == 0) {
                if (memcmp(checksum, prev_checksum, SHA256_DIGEST_LENGTH) != 0) {
                    printf("File changed: %s\n", file_path);
                    memcpy(prev_checksum, checksum, SHA256_DIGEST_LENGTH);
                }
            }
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <directory_path>\n", argv[0]);
        return 1;
    }

    unsigned char prev_checksum[SHA256_DIGEST_LENGTH];
    memset(prev_checksum, 0, SHA256_DIGEST_LENGTH);

    monitor_directory(argv[1], prev_checksum);

    return 0;
}
