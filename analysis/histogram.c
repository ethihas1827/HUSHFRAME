/**
 * @file histogram.c
 * @brief Histogram analysis.
 */

#include "stego/analysis.h"
#include <string.h>

void analysis_compute_histogram(const StegoImage *img, uint32_t hist[3][256]) {
    if (!img || !img->pixels || !hist) return;
    memset(hist, 0, 3 * 256 * sizeof(uint32_t));

    for (uint32_t y = 0; y < img->height; y++) {
        const uint8_t *row = img->pixels + (y * img->stride);
        for (uint32_t x = 0; x < img->width; x++) {
            hist[0][row[x * img->channels + 0]]++;
            hist[1][row[x * img->channels + 1]]++;
            hist[2][row[x * img->channels + 2]]++;
        }
    }
}

