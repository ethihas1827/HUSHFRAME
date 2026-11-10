/**
 * @file png_carrier.h
 * @brief PNG steganography carrier with standard, adaptive, multi-bit, and password-authenticated LSB embedding.
 */

#ifndef STEGO_PNG_CARRIER_H
#define STEGO_PNG_CARRIER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "stego/error.h"
#include "stego/carrier.h"
#include "stego/payload.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Compute adaptive complexity score for a pixel based on high-order bits (bits 7..2).
 *
 * Using high-order bits guarantees that 1-bit LSB modifications do not change
 * the edge classification, ensuring exact synchronization between encoder and decoder.
 */
uint32_t png_pixel_texture_complexity(const StegoImage *img, uint32_t x, uint32_t y);

/**
 * @brief Calculate total raw capacity in bytes for a carrier image at specified bit depth.
 */
size_t png_raw_capacity_bits(const StegoImage *image, bool adaptive, int bits_per_channel);

/**
 * @brief Calculate total raw capacity in bytes for a carrier image (1-bit LSB).
 */
size_t png_raw_capacity(const StegoImage *image, bool adaptive);

/**
 * @brief Calculate maximum payload capacity in bytes for CMC1 unencrypted payload.
 */
size_t png_max_payload_size(const StegoImage *image, bool adaptive);

/**
 * @brief Calculate maximum payload capacity in bytes for CMC2 authenticated encrypted payload.
 */
size_t png_max_payload_size_cmc2(const StegoImage *image, bool adaptive);

/**
 * @brief Embed a raw byte stream into image LSBs with specified bits per channel (1, 2, or 3).
 */
StegoResult png_embed_raw_bits(StegoImage *image, const uint8_t *stream, size_t stream_len, bool adaptive, int bits_per_channel);

/**
 * @brief Embed a raw byte stream into image LSBs (1-bit default).
 */
StegoResult png_embed_raw(StegoImage *image, const uint8_t *stream, size_t stream_len, bool adaptive);

/**
 * @brief Extract a raw byte stream from image LSBs with specified bits per channel.
 */
StegoResult png_extract_raw_bits(const StegoImage *image, uint8_t *stream, size_t stream_len, bool adaptive, int bits_per_channel);

/**
 * @brief Extract a raw byte stream from image LSBs (1-bit default).
 */
StegoResult png_extract_raw(const StegoImage *image, uint8_t *stream, size_t stream_len, bool adaptive);

/**
 * @brief Detect whether image contains a CMC1, CMC2, CMC3, or CMC4 envelope, determining bit depth and adaptive mode.
 */
StegoEnvelopeType png_detect_envelope_detailed(const StegoImage *image, bool *out_adaptive, int *out_bits_per_channel, uint32_t *out_payload_len);

/**
 * @brief Detect whether image contains a CMC1 or CMC2 envelope.
 */
StegoEnvelopeType png_detect_envelope(const StegoImage *image, bool adaptive, uint32_t *out_payload_len);

/**
 * @brief Check if PNG image contains a valid steganographic envelope (CMC1, CMC2, CMC3, or CMC4).
 */
bool png_has_payload(const StegoImage *image, bool adaptive, size_t *out_payload_size);

/**
 * @brief Embed payload into PNG raw pixel buffer using CMC1 unencrypted framing.
 */
StegoResult png_encode(StegoImage *image, const uint8_t *payload, size_t payload_len, bool adaptive);

/**
 * @brief Extract payload from PNG raw pixel buffer using CMC1 unencrypted framing.
 */
StegoResult png_decode(const StegoImage *image, uint8_t **out_payload, size_t *out_len, bool adaptive);

/**
 * @brief Embed payload into PNG with optional Argon2id + AES-256-GCM encryption and custom bit depth.
 */
StegoResult png_encode_secure_ex(StegoImage *image, const uint8_t *payload, size_t payload_len, const char *passphrase, bool adaptive, int bits_per_channel);

/**
 * @brief Embed payload into PNG with optional Argon2id + AES-256-GCM encryption (1-bit LSB default).
 */
StegoResult png_encode_secure(StegoImage *image, const uint8_t *payload, size_t payload_len, const char *passphrase, bool adaptive);

/**
 * @brief Extract payload from PNG, automatically discovering bit depth and adaptive settings.
 */
StegoResult png_decode_secure_ex(const StegoImage *image, const char *passphrase, uint8_t **out_payload, size_t *out_len, bool *out_adaptive, int *out_bits_per_channel);

/**
 * @brief Extract payload from PNG, verifying AES-256-GCM authentication if encrypted (CMC2).
 */
StegoResult png_decode_secure(const StegoImage *image, const char *passphrase, uint8_t **out_payload, size_t *out_len, bool adaptive);

/**
 * @brief Wrap StegoImage in a polymorphic StegoCarrier interface.
 */
StegoResult stego_png_carrier_create(StegoImage *image, bool adaptive, StegoCarrier **out_carrier);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_PNG_CARRIER_H */
