/**
 * @file dct_utils.c
 * @brief Discrete Cosine Transform utilities for JPEG carrier (Phase 2).
 */

#include "stego/error.h"
#include <stdint.h>
#include <stddef.h>

void stego_dct_fdct(const float *block, float *coeff) {
    (void)block; (void)coeff;
}

void stego_dct_idct(const float *coeff, float *block) {
    (void)coeff; (void)block;
}

