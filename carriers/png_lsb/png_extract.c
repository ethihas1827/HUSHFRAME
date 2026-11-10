/**
 * @file png_extract.c
 * @brief PNG adaptive, standard, multi-bit, and password-authenticated AES-256-GCM LSB extraction.
 */

#include "stego/png_carrier.h"
#include "stego/payload.h"
#include "stego/crypto.h"
#include "stego/compress.h"
#include <stdlib.h>
#include <string.h>

#define ADAPTIVE_THRESHOLD 12

StegoResult png_extract_raw_bits(const StegoImage *image, uint8_t *stream, size_t stream_len, bool adaptive, int bits_per_channel) {
    if (!image || !image->pixels || !stream) return STEGO_ERR_INVALID_ARG;
    if (stream_len == 0) return STEGO_OK;
    if (bits_per_channel < 1) bits_per_channel = 1;
    if (bits_per_channel > 3) bits_per_channel = 3;

    size_t raw_cap = png_raw_capacity_bits(image, adaptive, bits_per_channel);
    if (stream_len > raw_cap) return STEGO_ERR_CORRUPT_PAYLOAD;

    memset(stream, 0, stream_len);
    size_t total_bits = stream_len * 8;
    size_t bit_idx = 0;
    uint8_t mask = (uint8_t)((1 << bits_per_channel) - 1);

    for (uint32_t y = 0; y < image->height && bit_idx < total_bits; y++) {
        for (uint32_t x = 0; x < image->width && bit_idx < total_bits; x++) {
            if (adaptive && png_pixel_texture_complexity(image, x, y) < ADAPTIVE_THRESHOLD) {
                continue;
            }

            const uint8_t *pixel = image->pixels + (y * image->stride) + (x * image->channels);
            for (int c = 0; c < 3 && bit_idx < total_bits; c++) {
                int bits_to_read = bits_per_channel;
                if (bit_idx + bits_to_read > total_bits) {
                    bits_to_read = (int)(total_bits - bit_idx);
                }

                uint8_t val = (uint8_t)(pixel[c] & mask);
                val >>= (bits_per_channel - bits_to_read);

                for (int b = 0; b < bits_to_read; b++) {
                    size_t b_pos = bit_idx + b;
                    size_t byte_pos = b_pos / 8;
                    size_t bit_pos = 7 - (b_pos % 8);
                    uint8_t bit = (uint8_t)((val >> (bits_to_read - 1 - b)) & 1);
                    if (bit) {
                        stream[byte_pos] |= (uint8_t)(1 << bit_pos);
                    }
                }
                bit_idx += bits_to_read;
            }
        }
    }

    if (bit_idx < total_bits) return STEGO_ERR_CORRUPT_PAYLOAD;
    return STEGO_OK;
}

StegoResult png_extract_raw(const StegoImage *image, uint8_t *stream, size_t stream_len, bool adaptive) {
    return png_extract_raw_bits(image, stream, stream_len, adaptive, 1);
}

StegoEnvelopeType png_detect_envelope_detailed(const StegoImage *image, bool *out_adaptive, int *out_bits_per_channel, uint32_t *out_payload_len) {
    if (!image || !image->pixels) return STEGO_ENVELOPE_NONE;
    if (out_adaptive) *out_adaptive = false;
    if (out_bits_per_channel) *out_bits_per_channel = 1;
    if (out_payload_len) *out_payload_len = 0;

    int test_bits[] = {1, 2, 3};
    bool test_adapt[] = {false, true};

    for (int b_idx = 0; b_idx < 3; b_idx++) {
        int bpc = test_bits[b_idx];
        for (int a_idx = 0; a_idx < 2; a_idx++) {
            bool adapt = test_adapt[a_idx];
            size_t raw_cap = png_raw_capacity_bits(image, adapt, bpc);
            if (raw_cap < STEGO_CMC1_HEADER_SIZE) continue;

            size_t bytes_to_read = (raw_cap >= STEGO_CMC4_HEADER_SIZE) ? STEGO_CMC4_HEADER_SIZE :
                                   (raw_cap >= STEGO_CMC3_HEADER_SIZE) ? STEGO_CMC3_HEADER_SIZE :
                                   (raw_cap >= STEGO_CMC2_HEADER_SIZE) ? STEGO_CMC2_HEADER_SIZE : STEGO_CMC1_HEADER_SIZE;
            uint8_t header[STEGO_CMC4_HEADER_SIZE] = { 0 };

            if (png_extract_raw_bits(image, header, bytes_to_read, adapt, bpc) == STEGO_OK) {
                uint32_t plen = 0;
                StegoEnvelopeType env = stego_payload_detect_envelope(header, bytes_to_read, &plen);
                if (env != STEGO_ENVELOPE_NONE) {
                    if (out_adaptive) *out_adaptive = adapt;
                    if (out_bits_per_channel) *out_bits_per_channel = bpc;
                    if (out_payload_len) *out_payload_len = plen;
                    return env;
                }
            }
        }
    }
    return STEGO_ENVELOPE_NONE;
}

StegoEnvelopeType png_detect_envelope(const StegoImage *image, bool adaptive, uint32_t *out_payload_len) {
    bool detected_adaptive = adaptive;
    int bpc = 1;
    return png_detect_envelope_detailed(image, &detected_adaptive, &bpc, out_payload_len);
}

bool png_has_payload(const StegoImage *image, bool adaptive, size_t *out_payload_size) {
    uint32_t len = 0;
    bool detected_adaptive = adaptive;
    int bpc = 1;
    StegoEnvelopeType env = png_detect_envelope_detailed(image, &detected_adaptive, &bpc, &len);
    if (env != STEGO_ENVELOPE_NONE) {
        if (out_payload_size) *out_payload_size = (size_t)len;
        return true;
    }
    if (out_payload_size) *out_payload_size = 0;
    return false;
}

StegoResult png_decode(const StegoImage *image, uint8_t **out_payload, size_t *out_len, bool adaptive) {
    return png_decode_secure(image, NULL, out_payload, out_len, adaptive);
}

StegoResult png_decode_secure_ex(const StegoImage *image, const char *passphrase, uint8_t **out_payload, size_t *out_len, bool *out_adaptive, int *out_bits_per_channel) {
    if (!image || !image->pixels || !out_payload || !out_len) {
        return STEGO_ERR_INVALID_ARG;
    }
    *out_payload = NULL;
    *out_len = 0;

    bool detected_adaptive = false;
    int detected_bpc = 1;
    uint32_t payload_len = 0;

    StegoEnvelopeType env = png_detect_envelope_detailed(image, &detected_adaptive, &detected_bpc, &payload_len);
    if (env == STEGO_ENVELOPE_NONE) {
        return STEGO_ERR_NO_PAYLOAD;
    }

    if (out_adaptive) *out_adaptive = detected_adaptive;
    if (out_bits_per_channel) *out_bits_per_channel = detected_bpc;

    size_t raw_cap = png_raw_capacity_bits(image, detected_adaptive, detected_bpc);

    if (env == STEGO_ENVELOPE_CMC1) {
        /* If a passphrase was specified, reject unauthenticated extraction of unencrypted payload */
        if (passphrase && passphrase[0] != '\0') {
            return STEGO_ERR_AUTH_FAILED;
        }

        size_t total_cmc1 = STEGO_CMC1_HEADER_SIZE + (size_t)payload_len;
        if (total_cmc1 > raw_cap) {
            return STEGO_ERR_CORRUPT_PAYLOAD;
        }

        uint8_t *stream = (uint8_t *)malloc(total_cmc1);
        if (!stream) return STEGO_ERR_MEMORY;

        StegoResult res = png_extract_raw_bits(image, stream, total_cmc1, detected_adaptive, detected_bpc);
        if (res != STEGO_OK) {
            free(stream);
            return res;
        }

        uint8_t *raw_extracted = (uint8_t *)malloc(payload_len + 1);
        if (!raw_extracted) {
            free(stream);
            return STEGO_ERR_MEMORY;
        }
        if (payload_len > 0) {
            memcpy(raw_extracted, stream + STEGO_CMC1_HEADER_SIZE, payload_len);
        }
        raw_extracted[payload_len] = '\0';
        free(stream);

        /* Automatic decompression check (CMP1) */
        uint8_t *final_payload = NULL;
        size_t final_len = 0;
        bool was_decomp = false;
        res = stego_decompress_payload_if_packed(raw_extracted, payload_len, &final_payload, &final_len, &was_decomp);
        free(raw_extracted);

        if (res != STEGO_OK) return res;

        *out_payload = final_payload;
        *out_len = final_len;
        return STEGO_OK;

    } else if (env == STEGO_ENVELOPE_CMC2) {
        /* Reject if no passphrase was provided */
        if (!passphrase || passphrase[0] == '\0') {
            return STEGO_ERR_AUTH_FAILED;
        }

        size_t total_cmc2 = STEGO_CMC2_HEADER_SIZE + (size_t)payload_len;
        if (total_cmc2 > raw_cap) {
            return STEGO_ERR_CORRUPT_PAYLOAD;
        }

        uint8_t *stream = (uint8_t *)malloc(total_cmc2);
        if (!stream) return STEGO_ERR_MEMORY;

        StegoResult res = png_extract_raw_bits(image, stream, total_cmc2, detected_adaptive, detected_bpc);
        if (res != STEGO_OK) {
            stego_secure_zero(stream, total_cmc2);
            free(stream);
            return res;
        }

        /* 1. Unpack CMC2 header */
        uint32_t unpacked_len = 0;
        uint8_t salt[STEGO_CMC2_SALT_SIZE];
        uint8_t nonce[STEGO_CMC2_NONCE_SIZE];
        uint8_t tag[STEGO_CMC2_TAG_SIZE];
        if (!stego_payload_unpack_cmc2(stream, &unpacked_len, salt, nonce, tag) || unpacked_len != payload_len) {
            stego_secure_zero(stream, total_cmc2);
            free(stream);
            return STEGO_ERR_CORRUPT_PAYLOAD;
        }

        /* 2. Re-derive 256-bit encryption key with Argon2id */
        uint8_t key[32];
        res = stego_derive_key(passphrase, salt, sizeof(salt), key, sizeof(key));
        if (res != STEGO_OK) {
            stego_secure_zero(key, sizeof(key));
            stego_secure_zero(salt, sizeof(salt));
            stego_secure_zero(nonce, sizeof(nonce));
            stego_secure_zero(tag, sizeof(tag));
            stego_secure_zero(stream, total_cmc2);
            free(stream);
            return res;
        }

        /* 3. Reconstruct 36-byte AAD */
        uint8_t aad[STEGO_CMC2_AAD_SIZE];
        aad[0] = STEGO_MAGIC_CMC2_BYTE0;
        aad[1] = STEGO_MAGIC_CMC2_BYTE1;
        aad[2] = STEGO_MAGIC_CMC2_BYTE2;
        aad[3] = STEGO_MAGIC_CMC2_BYTE3;
        aad[4] = (uint8_t)((payload_len >> 24) & 0xFF);
        aad[5] = (uint8_t)((payload_len >> 16) & 0xFF);
        aad[6] = (uint8_t)((payload_len >> 8)  & 0xFF);
        aad[7] = (uint8_t)(payload_len         & 0xFF);
        memcpy(aad + 8, salt, STEGO_CMC2_SALT_SIZE);
        memcpy(aad + 24, nonce, STEGO_CMC2_NONCE_SIZE);

        /* 4. Authenticate and decrypt with AES-256-GCM */
        uint8_t *plaintext = NULL;
        if (payload_len > 0) {
            plaintext = (uint8_t *)malloc(payload_len + 1);
            if (!plaintext) {
                stego_secure_zero(key, sizeof(key));
                stego_secure_zero(salt, sizeof(salt));
                stego_secure_zero(nonce, sizeof(nonce));
                stego_secure_zero(aad, sizeof(aad));
                stego_secure_zero(tag, sizeof(tag));
                stego_secure_zero(stream, total_cmc2);
                free(stream);
                return STEGO_ERR_MEMORY;
            }
        }

        const uint8_t *ciphertext = stream + STEGO_CMC2_HEADER_SIZE;
        res = stego_decrypt_aes_gcm(key, nonce, sizeof(nonce), aad, sizeof(aad),
                                    ciphertext, payload_len, tag, plaintext);

        /* Scrub key, nonce, salt, aad, and tag immediately */
        stego_secure_zero(key, sizeof(key));
        stego_secure_zero(salt, sizeof(salt));
        stego_secure_zero(nonce, sizeof(nonce));
        stego_secure_zero(aad, sizeof(aad));
        stego_secure_zero(tag, sizeof(tag));
        stego_secure_zero(stream, total_cmc2);
        free(stream);

        if (res != STEGO_OK) {
            if (plaintext) {
                stego_secure_zero(plaintext, payload_len);
                free(plaintext);
            }
            return res;
        }

        if (plaintext) plaintext[payload_len] = '\0';

        /* Automatic decompression check (CMP1) */
        uint8_t *final_payload = NULL;
        size_t final_len = 0;
        bool was_decomp = false;
        res = stego_decompress_payload_if_packed(plaintext, payload_len, &final_payload, &final_len, &was_decomp);
        if (plaintext) {
            stego_secure_zero(plaintext, payload_len);
            free(plaintext);
        }

        if (res != STEGO_OK) return res;

        *out_payload = final_payload;
        *out_len = final_len;
        return STEGO_OK;
    }

    return STEGO_ERR_NO_PAYLOAD;
}

StegoResult png_decode_secure(const StegoImage *image, const char *passphrase, uint8_t **out_payload, size_t *out_len, bool adaptive) {
    (void)adaptive;
    bool det_adapt = false;
    int det_bpc = 1;
    return png_decode_secure_ex(image, passphrase, out_payload, out_len, &det_adapt, &det_bpc);
}
