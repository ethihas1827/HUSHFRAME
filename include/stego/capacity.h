/**
 * @file capacity.h
 * @brief Capacity estimation, pre-embedding validation, and shortfall analysis.
 */

#ifndef STEGO_CAPACITY_H
#define STEGO_CAPACITY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "stego/error.h"
#include "stego/carrier.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char secret_name[256];
    size_t secret_size;
    bool is_encrypted;
    bool is_compressed;
    size_t envelope_overhead;      /**< 52 bytes for CMC2, 8 bytes for CMC1 */
    size_t total_required;         /**< secret_size + overhead */

    int bits_per_channel;          /**< 1 (default), 2, or 3 */
    size_t capacity_1bit;
    size_t capacity_2bit;
    size_t capacity_3bit;
    size_t available_capacity;     /**< Capacity for currently selected bit depth */

    bool fits;
    size_t additional_required;    /**< Bytes needed beyond available capacity */

    uint32_t cover_width;
    uint32_t cover_height;
    uint32_t rec_min_width;        /**< Recommended 4:3 width */
    uint32_t rec_min_height;       /**< Recommended 4:3 height */
    uint32_t rec_square_dim;       /**< Recommended square dimension */

    char error_summary[256];       /**< "This image does not have enough space for the selected secret." */
    char formatted_details[2048];  /**< Multi-line detailed explanation with recommendations */
} StegoCapacityAssessment;

/**
 * @brief Calculate complete capacity assessment before attempting to embed.
 */
StegoResult stego_assess_capacity(const StegoCarrier *carrier,
                                  const char *secret_name,
                                  size_t secret_size,
                                  bool is_encrypted,
                                  bool is_compressed,
                                  int bits_per_channel,
                                  StegoCapacityAssessment *out);

/**
 * @brief Helper to format bytes into KB or MB string.
 */
void stego_format_bytes(size_t bytes, char *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_CAPACITY_H */
