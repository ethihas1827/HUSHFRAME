/**
 * @file argon2id.c
 * @brief Argon2id key derivation stub (Phase 3).
 */

#include "stego/crypto.h"

StegoResult crypto_argon2id_kdf(const char *pw, const uint8_t *salt, size_t salt_len, uint8_t *key, size_t key_len) {
    return stego_derive_key(pw, salt, salt_len, key, key_len);
}

