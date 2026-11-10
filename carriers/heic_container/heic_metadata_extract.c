/**
 * @file heic_metadata_extract.c
 * @brief HEIC container/metadata extraction stub (Phase 3).
 */

#include "stego/error.h"

StegoResult stego_heic_extract_meta(const char *stego_path, uint8_t **out_payload, size_t *out_len) {
    (void)stego_path;
    if (out_payload) *out_payload = NULL;
    if (out_len) *out_len = 0;
    return STEGO_ERR_NOT_IMPLEMENTED;
}

