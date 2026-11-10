/**
 * @file metadata_strip.c
 * @brief Metadata stripping.
 */

#include "stego/metadata.h"

StegoResult privacy_strip_all(const char *input, const char *output) {
    return stego_metadata_strip(input, output);
}

