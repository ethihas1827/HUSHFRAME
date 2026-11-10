/**
 * @file jpeg_carrier.c
 * @brief JPEG DCT carrier stub (Phase 2).
 */

#include "stego/jpeg_carrier.h"

StegoResult stego_jpeg_carrier_create(const char *filepath, StegoCarrier **out_carrier) {
    (void)filepath;
    if (out_carrier) *out_carrier = NULL;
    return STEGO_ERR_NOT_IMPLEMENTED;
}

