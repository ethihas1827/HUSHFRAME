/**
 * @file ssim.c
 * @brief SSIM metric computation wrapper.
 */

#include "stego/analysis.h"

double analysis_calc_ssim(const StegoImage *a, const StegoImage *b) {
    return stego_compute_ssim(a, b);
}

