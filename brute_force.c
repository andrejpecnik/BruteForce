#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "brute_force.h"
#include "xor.h"
#include "config.h"

int brute_force_attack(const unsigned char* data, size_t data_len, unsigned char* found_key,
    int min_len, int max_len, const char* known_phrase, size_t expected_key_len) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    size_t charset_len = strlen(charset);

    unsigned char* decrypted = malloc(MAX_FILE_SIZE);
    if (!decrypted) {
        perror("malloc failed");
        return 0;
    }

    for (int key_len = min_len; key_len <= max_len; key_len++) {
        size_t total = 1;
        for (int i = 0; i < key_len; i++) total *= charset_len;

        char* current_key = malloc(key_len + 1);
        if (!current_key) {
            perror("malloc failed");
            free(decrypted);
            return 0;
        }

        for (size_t i = 0; i < total; i++) {
            size_t idx = i;
            for (int j = 0; j < key_len; j++) {
                current_key[j] = charset[idx % charset_len];
                idx /= charset_len;
            }
            current_key[key_len] = '\0';

            xor_encrypt(data, decrypted, data_len, (unsigned char*)current_key, key_len);
            decrypted[data_len < MAX_FILE_SIZE ? data_len : MAX_FILE_SIZE - 1] = '\0';

            // Kontrola: zaèína "HEADER:" a obsahuje known_phrase
            if (key_len == expected_key_len &&
                memcmp(decrypted, "HEADER:", 7) == 0 &&
                strstr((char*)decrypted, known_phrase)) {
                strcpy_s((char*)found_key, MAX_KEY_LENGTH + 1, current_key);
                free(current_key);
                free(decrypted);
                return 1;
            }
        }

        free(current_key);
    }

    free(decrypted);
    return 0;
}
