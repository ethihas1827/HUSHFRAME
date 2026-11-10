/**
 * @file safe_share.c
 * @brief Cleaned copy creation for safe external sharing.
 */

#include "stego/privacy.h"

StegoResult privacy_safe_share_copy(const char *input, const char *output) {
    return stego_safe_share(input, output);
}

