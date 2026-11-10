/**
 * @file crypto.h
 * @brief Cryptographic utilities: Argon2id KDF, AES-256-GCM AEAD, and memory hygiene.
 */

#ifndef STEGO_CRYPTO_H
#define STEGO_CRYPTO_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "stego/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Compute standard ISO 3309 / ITU-T V.42 CRC-32 checksum.
 */
uint32_t stego_crc32(uint32_t crc, const uint8_t *buf, size_t len);

/**
 * @brief Securely zero out sensitive memory to prevent residual secret leakage.
 */
void stego_secure_zero(void *ptr, size_t len);

/**
 * @brief Constant-time memory comparison to protect against timing attacks.
 * @return 0 if equal, non-zero if different.
 */
int stego_const_time_memcmp(const void *a, const void *b, size_t len);

/**
 * @brief Derive a cryptographic key using Argon2id (RFC 9106).
 *
 * @param passphrase Secret user passphrase
 * @param salt Cryptographic salt (typically 16 bytes)
 * @param salt_len Salt length in bytes
 * @param out_key Buffer to receive derived key
 * @param key_len Requested key length in bytes (32 for AES-256)
 * @return STEGO_OK on success, or error code
 */
StegoResult stego_derive_key(const char *passphrase, const uint8_t *salt, size_t salt_len, uint8_t *out_key, size_t key_len);

/**
 * @brief Authenticated encryption using AES-256-GCM with Associated Data (NIST SP 800-38D).
 *
 * @param key 256-bit (32-byte) secret key
 * @param iv 96-bit (12-byte) initialization vector
 * @param iv_len Length of IV (must be 12)
 * @param aad Additional authenticated data (can be NULL if aad_len == 0)
 * @param aad_len Length of AAD
 * @param plaintext Plaintext data to encrypt
 * @param plaintext_len Length of plaintext
 * @param ciphertext Buffer to receive ciphertext (same length as plaintext)
 * @param tag 16-byte buffer to receive 128-bit authentication tag
 * @return STEGO_OK on success, or error code
 */
StegoResult stego_encrypt_aes_gcm(const uint8_t *key,
                                  const uint8_t *iv, size_t iv_len,
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *plaintext, size_t plaintext_len,
                                  uint8_t *ciphertext, uint8_t *tag);

/**
 * @brief Authenticated decryption using AES-256-GCM with Associated Data (NIST SP 800-38D).
 *
 * Verifies the 128-bit authentication tag before releasing decrypted plaintext.
 * If authentication fails, the plaintext buffer is zeroed and STEGO_ERR_AUTH_FAILED is returned.
 *
 * @param key 256-bit (32-byte) secret key
 * @param iv 96-bit (12-byte) initialization vector
 * @param iv_len Length of IV (must be 12)
 * @param aad Additional authenticated data (can be NULL if aad_len == 0)
 * @param aad_len Length of AAD
 * @param ciphertext Ciphertext data to decrypt
 * @param ciphertext_len Length of ciphertext
 * @param tag 16-byte authentication tag to verify
 * @param plaintext Buffer to receive decrypted plaintext (must be at least ciphertext_len bytes)
 * @return STEGO_OK on success, or STEGO_ERR_AUTH_FAILED
 */
StegoResult stego_decrypt_aes_gcm(const uint8_t *key,
                                  const uint8_t *iv, size_t iv_len,
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *ciphertext, size_t ciphertext_len,
                                  const uint8_t *tag, uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_CRYPTO_H */
