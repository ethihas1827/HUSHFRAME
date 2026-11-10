/**
 * @file heic_carrier.c
 * @brief HEIC metadata/container carrier stub (Phase 3).
 */

#include "stego/heic_carrier.h"

StegoResult stego_heic_carrier_create(const char *filepath, StegoCarrier **out_carrier) {
    (void)filepath;
    if (out_carrier) *out_carrier = NULL;
    return STEGO_ERR_NOT_IMPLEMENTED;
}

