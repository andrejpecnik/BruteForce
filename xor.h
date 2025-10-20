#pragma once
#ifndef XOR_H
#define XOR_H

#include <stddef.h>  // pre size_t


/**
 * Zašifruje vstupné dáta pomocou XOR algoritmu s daným kľúčom.
 *
 * @param input Ukazovateľ na vstupné dáta.
 * @param output Ukazovateľ na výstupné (zašifrované) dáta.
 * @param len Dĺžka vstupných dát.
 * @param key Ukazovateľ na šifrovací kľúč.
 * @param key_len Dĺžka šifrovacieho kľúča.
 */

void xor_encrypt(const unsigned char* input, unsigned char* output, size_t len, const unsigned char* key, size_t key_len);

/**
 * Dešifruje vstupné dáta pomocou XOR algoritmu.
 * Dešifrovanie je rovnaká operácia ako šifrovanie.
 *
 * @param input Ukazovateľ na zašifrované dáta.
 * @param output Ukazovateľ na výstupné (dešifrované) dáta.
 * @param len Dĺžka zašifrovaných dát.
 * @param key Ukazovateľ na dešifrovací kľúč.
 * @param key_len Dĺžka dešifrovacieho kľúča.
 */

void xor_decrypt(const unsigned char* input, unsigned char* output, size_t len, const unsigned char* key, size_t key_len);

#endif
