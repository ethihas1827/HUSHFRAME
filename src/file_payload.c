/**
 * @file file_payload.c
 * @brief Implementation of authenticated FIL1 file container with SHA-256 integrity verification.
 */

#include "stego/file_payload.h"
#include "stego/crypto.h"
#include "stego/split.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *stego_detect_mime_type(const char *filename) {
    if (!filename) return "application/octet-stream";
    const char *dot = strrchr(filename, '.');
    if (!dot) return "application/octet-stream";

    if (_stricmp(dot, ".png") == 0) return "image/png";
    if (_stricmp(dot, ".jpg") == 0 || _stricmp(dot, ".jpeg") == 0) return "image/jpeg";
    if (_stricmp(dot, ".bmp") == 0) return "image/bmp";
    if (_stricmp(dot, ".webp") == 0) return "image/webp";
    if (_stricmp(dot, ".gif") == 0) return "image/gif";
    if (_stricmp(dot, ".txt") == 0) return "text/plain";
    if (_stricmp(dot, ".md") == 0) return "text/markdown";
    if (_stricmp(dot, ".json") == 0) return "application/json";
    if (_stricmp(dot, ".pdf") == 0) return "application/pdf";
    if (_stricmp(dot, ".zip") == 0) return "application/zip";
    if (_stricmp(dot, ".csv") == 0) return "text/csv";
    if (_stricmp(dot, ".docx") == 0) return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    if (_stricmp(dot, ".xlsx") == 0) return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    if (_stricmp(dot, ".mp3") == 0) return "audio/mpeg";
    if (_stricmp(dot, ".mp4") == 0) return "video/mp4";

    return "application/octet-stream";
}

bool stego_file_payload_is_fil1(const uint8_t *payload, size_t payload_len) {
    if (!payload || payload_len < STEGO_FIL1_MIN_HEADER_SIZE) return false;
    return (payload[0] == STEGO_FIL1_MAGIC_BYTE0 &&
            payload[1] == STEGO_FIL1_MAGIC_BYTE1 &&
            payload[2] == STEGO_FIL1_MAGIC_BYTE2 &&
            payload[3] == STEGO_FIL1_MAGIC_BYTE3);
}

StegoResult stego_file_payload_pack(const char *filename,
                                    const uint8_t *file_data,
                                    size_t file_len,
                                    uint8_t **out_packed,
                                    size_t *out_packed_len) {
    if (!out_packed || !out_packed_len) return STEGO_ERR_INVALID_ARG;
    *out_packed = NULL;
    *out_packed_len = 0;

    /* Extract base filename */
    const char *base = filename ? strrchr(filename, '/') : NULL;
    if (!base && filename) base = strrchr(filename, '\\');
    base = base ? base + 1 : (filename ? filename : "secret.dat");

    size_t fn_len = strlen(base);
    if (fn_len > 255) fn_len = 255;

    const char *mime = stego_detect_mime_type(base);
    size_t mime_len = strlen(mime);
    if (mime_len > 63) mime_len = 63;

    /* Compute SHA-256 of file content */
    uint8_t sha[32];
    stego_sha256(file_data, file_len, sha);

    size_t header_len = 4 + 2 + fn_len + 2 + mime_len + 8 + 32;
    size_t total_len = header_len + file_len;

    uint8_t *packed = (uint8_t *)malloc(total_len > 0 ? total_len : 1);
    if (!packed) return STEGO_ERR_MEMORY;

    /* Magic */
    packed[0] = STEGO_FIL1_MAGIC_BYTE0;
    packed[1] = STEGO_FIL1_MAGIC_BYTE1;
    packed[2] = STEGO_FIL1_MAGIC_BYTE2;
    packed[3] = STEGO_FIL1_MAGIC_BYTE3;

    /* Filename */
    packed[4] = (uint8_t)((fn_len >> 8) & 0xFF);
    packed[5] = (uint8_t)(fn_len & 0xFF);
    memcpy(packed + 6, base, fn_len);
    size_t pos = 6 + fn_len;

    /* MIME */
    packed[pos] = (uint8_t)((mime_len >> 8) & 0xFF);
    packed[pos + 1] = (uint8_t)(mime_len & 0xFF);
    memcpy(packed + pos + 2, mime, mime_len);
    pos += 2 + mime_len;

    /* File Size (uint64 big-endian) */
    uint64_t sz = (uint64_t)file_len;
    for (int i = 0; i < 8; i++) {
        packed[pos + i] = (uint8_t)((sz >> (56 - i * 8)) & 0xFF);
    }
    pos += 8;

    /* SHA-256 */
    memcpy(packed + pos, sha, 32);
    pos += 32;

    /* File Data */
    if (file_len > 0 && file_data) {
        memcpy(packed + pos, file_data, file_len);
    }

    *out_packed = packed;
    *out_packed_len = total_len;
    return STEGO_OK;
}

StegoResult stego_file_payload_unpack(const uint8_t *packed_data,
                                      size_t packed_len,
                                      StegoFileMetadata *out_meta,
                                      uint8_t **out_file_data,
                                      size_t *out_file_len) {
    if (!packed_data || packed_len < STEGO_FIL1_MIN_HEADER_SIZE) return STEGO_ERR_INVALID_FORMAT;
    if (!stego_file_payload_is_fil1(packed_data, packed_len)) return STEGO_ERR_INVALID_FORMAT;

    if (out_meta) memset(out_meta, 0, sizeof(StegoFileMetadata));
    if (out_file_data) *out_file_data = NULL;
    if (out_file_len) *out_file_len = 0;

    /* Read filename */
    uint16_t fn_len = ((uint16_t)packed_data[4] << 8) | (uint16_t)packed_data[5];
    if (6 + fn_len > packed_len) return STEGO_ERR_CORRUPT_PAYLOAD;

    char fn[256] = {0};
    size_t copy_fn = (fn_len < 255) ? fn_len : 255;
    memcpy(fn, packed_data + 6, copy_fn);
    fn[copy_fn] = '\0';
    size_t pos = 6 + fn_len;

    if (pos + 2 > packed_len) return STEGO_ERR_CORRUPT_PAYLOAD;

    /* Read MIME */
    uint16_t mime_len = ((uint16_t)packed_data[pos] << 8) | (uint16_t)packed_data[pos + 1];
    pos += 2;
    if (pos + mime_len > packed_len) return STEGO_ERR_CORRUPT_PAYLOAD;

    char mime[64] = {0};
    size_t copy_mime = (mime_len < 63) ? mime_len : 63;
    memcpy(mime, packed_data + pos, copy_mime);
    mime[copy_mime] = '\0';
    pos += mime_len;

    /* Read File Size */
    if (pos + 8 + 32 > packed_len) return STEGO_ERR_CORRUPT_PAYLOAD;
    uint64_t file_size = 0;
    for (int i = 0; i < 8; i++) {
        file_size = (file_size << 8) | (uint64_t)packed_data[pos + i];
    }
    pos += 8;

    /* Read SHA-256 */
    uint8_t expected_sha[32];
    memcpy(expected_sha, packed_data + pos, 32);
    pos += 32;

    /* Verify payload length */
    size_t remaining = packed_len - pos;
    if (remaining != (size_t)file_size) {
        return STEGO_ERR_CORRUPT_PAYLOAD;
    }

    /* Allocate and copy restored file data */
    uint8_t *restored = (uint8_t *)malloc(file_size > 0 ? (size_t)file_size : 1);
    if (!restored) return STEGO_ERR_MEMORY;

    if (file_size > 0) {
        memcpy(restored, packed_data + pos, (size_t)file_size);
    }

    /* Cryptographic SHA-256 Checksum Verification */
    uint8_t computed_sha[32];
    stego_sha256(restored, (size_t)file_size, computed_sha);

    if (stego_const_time_memcmp(computed_sha, expected_sha, 32) != 0) {
        stego_secure_zero(restored, (size_t)file_size);
        free(restored);
        return STEGO_ERR_CORRUPT_PAYLOAD;
    }

    if (out_meta) {
        snprintf(out_meta->filename, sizeof(out_meta->filename), "%s", fn);
        const char *dot = strrchr(fn, '.');
        if (dot) snprintf(out_meta->extension, sizeof(out_meta->extension), "%s", dot);
        snprintf(out_meta->mime_type, sizeof(out_meta->mime_type), "%s", mime);
        out_meta->file_size = file_size;
        memcpy(out_meta->sha256, expected_sha, 32);
        for (int i = 0; i < 32; i++) {
            snprintf(out_meta->sha256_hex + (i * 2), 3, "%02x", expected_sha[i]);
        }
        out_meta->sha256_hex[64] = '\0';
        out_meta->is_verified = true;
    }

    if (out_file_data) *out_file_data = restored;
    else {
        stego_secure_zero(restored, (size_t)file_size);
        free(restored);
    }
    if (out_file_len) *out_file_len = (size_t)file_size;

    return STEGO_OK;
}

