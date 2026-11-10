/**
 * @file aes_gcm.c
 * @brief AES-256-GCM authenticated encryption and decryption (Phase 3).
 */

#include "stego/crypto.h"

StegoResult crypto_aes_gcm_encrypt(const uint8_t *k, const uint8_t *iv, size_t iv_len,
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *in, size_t len,
                                   uint8_t *out, uint8_t *tag) {
    return stego_encrypt_aes_gcm(k, iv, iv_len, aad, aad_len, in, len, out, tag);
}

StegoResult crypto_aes_gcm_decrypt(const uint8_t *k, const uint8_t *iv, size_t iv_len,
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *in, size_t len,
                                   const uint8_t *tag, uint8_t *out) {
    return stego_decrypt_aes_gcm(k, iv, iv_len, aad, aad_len, in, len, tag, out);
}
