/**
 * @file key_derivation.c
 * @brief High-level key derivation interface.
 */

#include "stego/crypto.h"

StegoResult crypto_derive_encryption_key(const char *pw, const uint8_t *salt, size_t s_len, uint8_t *key, size_t k_len) {
    return stego_derive_key(pw, salt, s_len, key, k_len);
}

