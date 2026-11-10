/**
 * @file jpeg_carrier.h
 * @brief JPEG DCT coefficient carrier interface (Phase 2).
 */

#ifndef STEGO_JPEG_CARRIER_H
#define STEGO_JPEG_CARRIER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "stego/error.h"
#include "stego/carrier.h"

#ifdef __cplusplus
extern "C" {
#endif

StegoResult stego_jpeg_carrier_create(const char *filepath, StegoCarrier **out_carrier);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_JPEG_CARRIER_H */

