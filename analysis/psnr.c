/**
 * @file psnr.c
 * @brief PSNR metric computation wrapper.
 */

#include "stego/analysis.h"

double analysis_calc_psnr(const StegoImage *a, const StegoImage *b) {
    return stego_compute_psnr(a, b);
}

