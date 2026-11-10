/**
 * @file reed_solomon.c
 * @brief Reed-Solomon codec stub (Phase 6).
 */

#include "stego/fec.h"

StegoResult codec_rs_encode(const uint8_t *in, size_t len, uint8_t **out, size_t *out_len, size_t parity) {
    return stego_fec_encode(in, len, out, out_len, parity);
}

