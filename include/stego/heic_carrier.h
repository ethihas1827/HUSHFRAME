/**
 * @file heic_carrier.h
 * @brief HEIC metadata/container carrier interface (Phase 3).
 */

#ifndef STEGO_HEIC_CARRIER_H
#define STEGO_HEIC_CARRIER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "stego/error.h"
#include "stego/carrier.h"

#ifdef __cplusplus
extern "C" {
#endif

StegoResult stego_heic_carrier_create(const char *filepath, StegoCarrier **out_carrier);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_HEIC_CARRIER_H */

