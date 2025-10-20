// Testovací súbor pre funkcie šifrovania XOR a brute-force útoku
// Obsahuje jednotkové testy na overenie správnosti šifrovania, dešifrovania a nájdenia kľúča hrubou silou.

#define _CRT_SECURE_NO_WARNINGS

#ifdef snprintf
#undef snprintf
#endif

#include <stdio.h>
#include <string.h>
#include "config.h"
#include "xor.h"
#include "brute_force.h"

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


/**
 * Test: Overí, že po zašifrovaní a následnom dešifrovaní sa dostaneme späť k pôvodným dátam.
 */

void test_xor_encrypt_decrypt() {
    unsigned char input[] = "HEADER: tajne data";
    unsigned char key[] = "abc";
    unsigned char encrypted[MAX_FILE_SIZE];
    unsigned char decrypted[MAX_FILE_SIZE];
    size_t input_len = strlen((char*)input);
    size_t key_len = strlen((char*)key);

    xor_encrypt(input, encrypted, input_len, key, key_len);
    xor_encrypt(encrypted, decrypted, input_len, key, key_len);

    CU_ASSERT_NSTRING_EQUAL(input, decrypted, input_len);
}

/**
 * Test: Overí, že brute-force útok dokáže nájsť správny šifrovací kľúč.
 */

void test_brute_force_attack_success() {
    unsigned char input[] = "HEADER: tajne data";
    unsigned char key[] = "abc";
    unsigned char encrypted[MAX_FILE_SIZE];
    unsigned char found_key[MAX_KEY_LENGTH + 1];
    size_t input_len = strlen((char*)input);
    size_t key_len = strlen((char*)key);

    xor_encrypt(input, encrypted, input_len, key, key_len);

    size_t attempts = brute_force_attack(encrypted, input_len, found_key, 3, 3, "tajne", key_len);

    CU_ASSERT_TRUE(attempts > 0);
    CU_ASSERT_STRING_EQUAL((char*)found_key, "abc");
}

/**
 * Hlavná funkcia: Inicializuje CUnit, pridá testovaciu sadu a jednotlivé testy, spustí testy a uprace po teste.
 */

int main() {
    if (CUE_SUCCESS != CU_initialize_registry()) return CU_get_error();

    CU_pSuite suite = CU_add_suite("Basic Tests", NULL, NULL);
    if (suite == NULL) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    CU_add_test(suite, "XOR Encrypt/Decrypt Test", test_xor_encrypt_decrypt);
    CU_add_test(suite, "Brute Force Attack Success Test", test_brute_force_attack_success);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return CU_get_error();
}