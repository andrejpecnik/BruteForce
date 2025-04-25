#ifndef BRUTE_FORCE_H
#define BRUTE_FORCE_H

#include <stddef.h>

int brute_force_attack(const unsigned char* data, size_t data_len, unsigned char* found_key,
    int min_len, int max_len, const char* known_phrase, size_t expected_key_len);

#endif
