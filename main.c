#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "xor.h"
#include "brute_force.h"
#include "config.h"

int read_file(const char* filename, unsigned char* buffer, size_t* length) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("fopen");
        return 0;
    }

    *length = fread(buffer, 1, MAX_FILE_SIZE, file);
    fclose(file);
    return 1;
}

int write_file(const char* filename, const unsigned char* data, size_t length) {
    FILE* file = fopen(filename, "wb");
    if (!file) {
        perror("fopen");
        return 0;
    }

    fwrite(data, 1, length, file);
    fclose(file);
    return 1;
}

int main() {
    char file_name[256];
    unsigned char buffer[MAX_FILE_SIZE];
    size_t file_len = 0;

    char key[MAX_KEY_LENGTH + 1];
    char known_phrase[256];
    unsigned char encrypted[MAX_FILE_SIZE];
    unsigned char found_key[MAX_KEY_LENGTH + 1];

    printf("Enter path to file to encrypt:\n> ");
    fgets(file_name, sizeof(file_name), stdin);
    file_name[strcspn(file_name, "\n")] = '\0';

    printf("Enter encryption key (max %d characters):\n> ", MAX_KEY_LENGTH);
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = '\0';
    size_t key_len = strlen(key);

    printf("Enter known phrase to search for in decrypted text:\n> ");
    fgets(known_phrase, sizeof(known_phrase), stdin);
    known_phrase[strcspn(known_phrase, "\n")] = '\0';

    if (!read_file(file_name, buffer, &file_len)) {
        fprintf(stderr, "Failed to read file: %s\n", file_name);
        return 1;
    }

    xor_encrypt(buffer, encrypted, file_len, (unsigned char*)key, key_len);
    write_file("encrypted.bin", encrypted, file_len);
    printf("File encrypted to 'encrypted.bin'\n");

    clock_t start = clock();
    size_t attempts = brute_force_attack(encrypted, file_len, found_key, 3, MAX_KEY_LENGTH, known_phrase, key_len);
    clock_t end = clock();
    double duration = (double)(end - start) / CLOCKS_PER_SEC;

    if (attempts > 0) {
        printf("Key found: '%s'\n", found_key);
        printf("Found after %zu attempts.\n", attempts);

        unsigned char decrypted[MAX_FILE_SIZE];
        xor_encrypt(encrypted, decrypted, file_len, found_key, strlen((char*)found_key));
        write_file("decrypted.txt", decrypted, file_len);
        printf("Decrypted output saved to 'decrypted.txt'\n");
    }
    else {
        printf("Key not found.\n");
    }

    printf("Brute-force took %.3f seconds.\n", duration);
    return 0;
}
