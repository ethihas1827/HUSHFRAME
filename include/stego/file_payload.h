/**
 * @file file_payload.h
 * @brief Authenticated file container (FIL1) with metadata preservation and SHA-256 integrity verification.
 *
 * Preserves original secret filename, extension, MIME type, file size,
 * and cryptographic SHA-256 hash inside authenticated envelope payloads.
 */

#ifndef STEGO_FILE_PAYLOAD_H
#define STEGO_FILE_PAYLOAD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "stego/error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STEGO_FIL1_MAGIC_BYTE0 'F'
#define STEGO_FIL1_MAGIC_BYTE1 'I'
#define STEGO_FIL1_MAGIC_BYTE2 'L'
#define STEGO_FIL1_MAGIC_BYTE3 '1'

#define STEGO_FIL1_MIN_HEADER_SIZE 48 /* 4 magic + 2 fn_len + 2 mime_len + 8 sz + 32 sha */

typedef struct {
    char filename[256];      /* Base original filename e.g. "report.pdf" */
    char extension[32];      /* Extension e.g. ".pdf" */
    char mime_type[64];      /* MIME type e.g. "application/pdf" */
    uint64_t file_size;      /* Original file content size in bytes */
    uint8_t sha256[32];      /* Original file SHA-256 hash */
    char sha256_hex[65];     /* Hex-encoded SHA-256 string */
    bool is_verified;        /* True if SHA-256 matched upon extraction */
} StegoFileMetadata;

/**
 * @brief Detect standard MIME type string from a filename extension.
 */
const char *stego_detect_mime_type(const char *filename);

/**
 * @brief Check if a payload stream begins with the FIL1 container magic.
 */
bool stego_file_payload_is_fil1(const uint8_t *payload, size_t payload_len);

/**
 * @brief Pack raw secret file content into an authenticated FIL1 container.
 *
 * @param filename Original filename or path (basename and extension will be extracted).
 * @param file_data Raw file content.
 * @param file_len Length of raw file content in bytes.
 * @param out_packed Pointer to allocated output buffer containing FIL1 stream.
 * @param out_packed_len Pointer to output length.
 * @return STEGO_OK on success, or error code.
 */
StegoResult stego_file_payload_pack(const char *filename,
                                    const uint8_t *file_data,
                                    size_t file_len,
                                    uint8_t **out_packed,
                                    size_t *out_packed_len);

/**
 * @brief Unpack an authenticated FIL1 container, verifying size and SHA-256.
 *
 * If the payload is incomplete, corrupted, or tampered, returns STEGO_ERR_CORRUPT_PAYLOAD
 * and zeroes all temporary memory immediately without exposing decrypted data.
 *
 * @param packed_data Packed payload stream.
 * @param packed_len Length of packed payload stream.
 * @param out_meta Optional metadata struct to receive extracted file metadata.
 * @param out_file_data Pointer to allocated output buffer with restored file data.
 * @param out_file_len Pointer to restored file length.
 * @return STEGO_OK on success, STEGO_ERR_CORRUPT_PAYLOAD on hash mismatch or truncation.
 */
StegoResult stego_file_payload_unpack(const uint8_t *packed_data,
                                      size_t packed_len,
                                      StegoFileMetadata *out_meta,
                                      uint8_t **out_file_data,
                                      size_t *out_file_len);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_FILE_PAYLOAD_H */

