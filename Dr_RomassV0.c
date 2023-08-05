#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/md5.h>

#define MAX_PATH_LEN 256
#define MAX_FILE_LEN 256

// Function to calculate the MD5 checksum of a file
int calculate_md5_checksum(const char *file_path, unsigned char *checksum) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("Error opening file");
        return -1;
    }

    MD5_CTX md5_context;
    MD5_Init(&md5_context);

    unsigned char buffer[1024];
    size_t bytes;

    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        MD5_Update(&md5_context, buffer, bytes);
    }

    MD5_Final(checksum, &md5_context);

    fclose(file);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <directory_path>\n", argv[0]);
        return 1;
    }

    DIR *dir = opendir(argv[1]);
    if (!dir) {
        perror("Error opening directory");
        return 1;
    }

    struct dirent *entry;
    char file_path[MAX_PATH_LEN];
    unsigned char prev_checksum[MD5_DIGEST_LENGTH];

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            snprintf(file_path, MAX_PATH_LEN, "%s/%s", argv[1], entry->d_name);
            unsigned char checksum[MD5_DIGEST_LENGTH];

            if (calculate_md5_checksum(file_path, checksum) == 0) {
                if (memcmp(checksum, prev_checksum, MD5_DIGEST_LENGTH) != 0) {
                    printf("File changed: %s\n", file_path);
                }
                memcpy(prev_checksum, checksum, MD5_DIGEST_LENGTH);
            }
        }
    }

    closedir(dir);
    return 0;
}
