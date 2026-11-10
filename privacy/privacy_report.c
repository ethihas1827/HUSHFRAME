/**
 * @file privacy_report.c
 * @brief Human-readable privacy assessment generator.
 */

#include "stego/privacy.h"

StegoResult privacy_generate_report(const char *filepath) {
    return stego_privacy_report(filepath);
}

