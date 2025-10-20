#ifndef BRUTE_FORCE_H
#define BRUTE_FORCE_H

#include <stddef.h>

/**
 * Pokúsi sa nájsť správny šifrovací kľúč brute-force útokom.
 * Pre každý možný kľúč vygeneruje dešifrovaný text a hľadá známu frázu.
 *
 * @param data Ukazovateľ na zašifrované dáta.
 * @param data_len Dĺžka zašifrovaných dát.
 * @param found_key Buffer, kam sa uloží nájdený kľúč.
 * @param min_len Minimálna dĺžka generovaných kľúčov.
 * @param max_len Maximálna dĺžka generovaných kľúčov.
 * @param known_phrase Známá fráza, ktorú hľadáme v dešifrovanom texte.
 * @param expected_key_len Očakávaná dĺžka správneho kľúča.
 *
 * @return Počet pokusov potrebných na nájdenie kľúča, alebo 0 ak sa kľúč nepodarilo nájsť.
 */

size_t brute_force_attack(const unsigned char* data, size_t data_len, unsigned char* found_key,
    int min_len, int max_len, const char* known_phrase, size_t expected_key_len);

#endif