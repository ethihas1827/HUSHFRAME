/**
 * @file fec.c
 * @brief Forward Error Correction stub (Phase 6).
 */

#include "stego/fec.h"

StegoResult stego_fec_encode(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len, size_t parity_bytes) {
    (void)in; (void)in_len; (void)out; (void)out_len; (void)parity_bytes;
    return STEGO_ERR_NOT_IMPLEMENTED;
}

StegoResult stego_fec_decode(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len, size_t parity_bytes) {
    (void)in; (void)in_len; (void)out; (void)out_len; (void)parity_bytes;
    return STEGO_ERR_NOT_IMPLEMENTED;
}

