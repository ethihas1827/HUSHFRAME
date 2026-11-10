/**
 * @file report.c
 * @brief Analysis report printer.
 */

#include "stego/analysis.h"
#include <stdio.h>

void analysis_print_report(const StegoImage *orig, const StegoImage *stego) {
    double psnr = stego_compute_psnr(orig, stego);
    double ssim = stego_compute_ssim(orig, stego);
    printf("PSNR: %.2f dB, SSIM: %.4f\n", psnr, ssim);
}

