/**
 * @file split.h
 * @brief Multi-image payload splitting, authenticated chunking, and recombination.
 */

#ifndef STEGO_SPLIT_H
#define STEGO_SPLIT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "stego/error.h"
#include "stego/payload.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STEGO_MAX_SPLIT_PARTS 64

typedef struct {
    char original_filename[256];
    size_t original_size;
    uint8_t sha256[32];
    char sha256_hex[65];
    uint16_t total_parts;
    bool is_encrypted;
    bool is_compressed;

    struct {
        uint16_t part_num;
        char part_path[512];
        size_t chunk_size;
    } parts[STEGO_MAX_SPLIT_PARTS];
} StegoManifest;

/**
 * @brief Compute SHA-256 hash over data buffer.
 */
void stego_sha256(const uint8_t *data, size_t len, uint8_t out_hash[32]);

/**
 * @brief Compute SHA-256 hexadecimal string over data buffer.
 */
void stego_sha256_hex(const uint8_t *data, size_t len, char out_hex[65]);

/**
 * @brief Split and embed a secret payload across multiple cover images.
 *
 * @param secret_path Path to secret file.
 * @param cover_paths Array of cover image file paths.
 * @param num_covers Number of cover images supplied.
 * @param output_prefix Output prefix (e.g. "secret" -> "secret_part1_of_4.png").
 * @param passphrase Optional passphrase for AES-256-GCM authentication.
 * @param compress Whether to compress payload before encryption.
 * @param bits_per_channel Bit depth (1, 2, or 3).
 * @param out_manifest Pointer to store generated manifest details.
 * @param out_error_msg Buffer to receive error message on failure.
 * @param error_msg_len Size of error message buffer.
 * @return STEGO_OK on success, error code on failure.
 */
StegoResult stego_split_embed(const char *secret_path,
                             const char **cover_paths,
                             uint16_t num_covers,
                             const char *output_prefix,
                             const char *passphrase,
                             bool compress,
                             int bits_per_channel,
                             StegoManifest *out_manifest,
                             char *out_error_msg,
                             size_t error_msg_len);

/**
 * @brief Extract and recombine multiple stego parts into the original secret.
 *
 * Checks for missing, duplicate, reordered, corrupted, or tampered parts.
 * Verifies SHA-256 cryptographic integrity before writing output.
 *
 * @param stego_paths Array of part image paths.
 * @param num_stego_images Number of image paths supplied.
 * @param output_path Target output file path.
 * @param passphrase Passphrase if encrypted.
 * @param out_error_msg Buffer to receive error message on failure.
 * @param error_msg_len Size of error message buffer.
 * @return STEGO_OK on success, error code on failure.
 */
StegoResult stego_split_extract(const char **stego_paths,
                               uint16_t num_stego_images,
                               const char *output_path,
                               const char *passphrase,
                               char *out_error_msg,
                               size_t error_msg_len);

/**
 * @brief Save manifest as human-readable JSON file.
 */
StegoResult stego_save_manifest_json(const char *json_path, const StegoManifest *manifest);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_SPLIT_H */
