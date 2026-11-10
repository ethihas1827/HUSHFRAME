/**
 * @file analysis.h
 * @brief Distortion analysis (PSNR, SSIM) and steganalysis metrics.
 */

#ifndef STEGO_ANALYSIS_H
#define STEGO_ANALYSIS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "stego/error.h"
#include "stego/image_loader.h"

#ifdef __cplusplus
extern "C" {
#endif

double stego_compute_psnr(const StegoImage *img1, const StegoImage *img2);
double stego_compute_ssim(const StegoImage *img1, const StegoImage *img2);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_ANALYSIS_H */

