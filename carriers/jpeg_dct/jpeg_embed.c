/**
 * @file jpeg_embed.c
 * @brief JPEG DCT frequency coefficient embedding stub (Phase 2).
 */

#include "stego/error.h"

StegoResult stego_jpeg_embed_dct(const char *cover_path, const char *stego_path, const uint8_t *payload, size_t len) {
    (void)cover_path; (void)stego_path; (void)payload; (void)len;
    return STEGO_ERR_NOT_IMPLEMENTED;
}

