#pragma once
#ifndef XOR_H
#define XOR_H

#include <stddef.h>  // pre size_t

// Funkcia na šifrovanie (XOR)
void xor_encrypt(const unsigned char* input, unsigned char* output, size_t len, const unsigned char* key, size_t key_len);

// XOR je symetrický, dešifrovanie je rovnaké
void xor_decrypt(const unsigned char* input, unsigned char* output, size_t len, const unsigned char* key, size_t key_len);

#endif
