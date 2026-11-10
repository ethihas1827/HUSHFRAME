/**
 * @file heic_metadata_embed.c
 * @brief HEIC container/metadata embedding stub (Phase 3).
 */

#include "stego/error.h"

StegoResult stego_heic_embed_meta(const char *cover_path, const char *stego_path, const uint8_t *payload, size_t len) {
    (void)cover_path; (void)stego_path; (void)payload; (void)len;
    return STEGO_ERR_NOT_IMPLEMENTED;
}

