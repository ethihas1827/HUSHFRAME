/**
 * @file fec.h
 * @brief Forward Error Correction (Reed-Solomon) interface.
 */

#ifndef STEGO_FEC_H
#define STEGO_FEC_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "stego/error.h"

#ifdef __cplusplus
extern "C" {
#endif

StegoResult stego_fec_encode(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len, size_t parity_bytes);
StegoResult stego_fec_decode(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len, size_t parity_bytes);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_FEC_H */

