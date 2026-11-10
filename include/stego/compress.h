/**
 * @file compress.h
 * @brief Lossless compression (DEFLATE / zlib) for steganographic payloads.
 *
 * Implements pre-encryption compression to reduce payload size before hiding.
 * Clearly documents that already-compressed formats (ZIP, JPEG, MP3, MP4, WEBP)
 * cannot be further compressed.
 */

#ifndef STEGO_COMPRESS_H
#define STEGO_COMPRESS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "stego/error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STEGO_COMPRESS_MAGIC_BYTE0 'C'
#define STEGO_COMPRESS_MAGIC_BYTE1 'M'
#define STEGO_COMPRESS_MAGIC_BYTE2 'P'
#define STEGO_COMPRESS_MAGIC_BYTE3 '1'
#define STEGO_COMPRESS_HEADER_SIZE 8 /* 4 magic + 4 orig_len */

/**
 * @brief Checks if a file extension represents an already-compressed format.
 */
bool stego_is_already_compressed_format(const char *filename);

/**
 * @brief Compress uncompressed payload bytes using DEFLATE.
 *
 * @param in Input plaintext buffer.
 * @param in_len Input length in bytes.
 * @param out Pointer to output allocated buffer.
 * @param out_len Pointer to output length in bytes.
 * @return STEGO_OK on success, error code otherwise.
 */
StegoResult stego_compress(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len);

/**
 * @brief Decompress DEFLATE-compressed bytes.
 *
 * @param in Compressed buffer.
 * @param in_len Compressed length in bytes.
 * @param out Pointer to output allocated buffer.
 * @param out_len Pointer to output length in bytes.
 * @return STEGO_OK on success, error code otherwise.
 */
StegoResult stego_decompress(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len);

/**
 * @brief Pack payload with CMP1 compression framing if compression is beneficial.
 *
 * If compression reduces size, outputs [CMP1][orig_len_4b][deflate_data].
 * If compression does NOT reduce size or input is already compressed,
 * leaves payload unchanged and sets *out_was_compressed = false.
 */
StegoResult stego_compress_payload_if_beneficial(const uint8_t *in, size_t in_len,
                                                uint8_t **out, size_t *out_len,
                                                bool *out_was_compressed);

/**
 * @brief Unpack CMP1-compressed payload if CMP1 magic is present, or returns copy.
 */
StegoResult stego_decompress_payload_if_packed(const uint8_t *in, size_t in_len,
                                              uint8_t **out, size_t *out_len,
                                              bool *out_was_decompressed);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_COMPRESS_H */
