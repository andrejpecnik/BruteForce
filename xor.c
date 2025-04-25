#include "xor.h"

#include "config.h"


void xor_encrypt(const unsigned char* input, unsigned char* output, size_t len, const unsigned char* key, size_t key_len) {
    for (size_t i = 0; i < len; ++i) {
        output[i] = input[i] ^ key[i % key_len];
    }
}

void xor_decrypt(const unsigned char* input, unsigned char* output, size_t len, const unsigned char* key, size_t key_len) {
    xor_encrypt(input, output, len, key, key_len);
}
