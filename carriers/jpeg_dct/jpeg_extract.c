/**
 * @file jpeg_extract.c
 * @brief JPEG DCT frequency coefficient extraction stub (Phase 2).
 */

#include "stego/error.h"

StegoResult stego_jpeg_extract_dct(const char *stego_path, uint8_t **out_payload, size_t *out_len) {
    (void)stego_path;
    if (out_payload) *out_payload = NULL;
    if (out_len) *out_len = 0;
    return STEGO_ERR_NOT_IMPLEMENTED;
}

