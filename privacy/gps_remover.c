/**
 * @file gps_remover.c
 * @brief Geolocation metadata removal.
 */

#include "stego/metadata.h"

StegoResult privacy_remove_gps(const char *input, const char *output) {
    return stego_metadata_strip(input, output);
}

