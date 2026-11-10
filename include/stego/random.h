/**
 * @file random.h
 * @brief Cryptographically secure random byte generation and permutation tools.
 */

#ifndef STEGO_RANDOM_H
#define STEGO_RANDOM_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "stego/error.h"

#ifdef __cplusplus
extern "C" {
#endif

StegoResult stego_random_bytes(uint8_t *dest, size_t count);
void stego_shuffle_indices(size_t *indices, size_t count, uint32_t seed);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_RANDOM_H */

