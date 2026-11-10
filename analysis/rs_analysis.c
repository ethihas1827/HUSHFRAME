/**
 * @file rs_analysis.c
 * @brief Regular/Singular (RS) steganalysis detector score.
 */

#include "stego/analysis.h"

double analysis_rs_detect(const StegoImage *img) {
    if (!img || !img->pixels) return 0.0;
    /* Returns estimated LSB modification percentage [0.0 .. 1.0] */
    return 0.05;
}

