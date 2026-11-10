/**
 * @file bmp_extract.c
 * @brief 24-bit uncompressed BMP LSB extraction implementation.
 */

#include "stego/bmp_carrier.h"
#include "stego/payload.h"
#include <stdlib.h>
#include <string.h>

bool bmp_has_payload(const BMPImage *image, size_t *out_payload_size) {
    if (!image || !image->raw_data) return false;
    if (out_payload_size) *out_payload_size = 0;

    uint8_t header[STEGO_CMC2_HEADER_SIZE] = { 0 };
    size_t bit_idx = 0;
    size_t max_bits = STEGO_CMC2_HEADER_SIZE * 8;

    for (uint32_t y = 0; y < image->height && bit_idx < max_bits; y++) {
        const uint8_t *row = image->raw_data + (y * image->row_stride);
        for (uint32_t x = 0; x < image->width && bit_idx < max_bits; x++) {
            const uint8_t *pixel = row + (x * 3);
            for (int c = 0; c < 3 && bit_idx < max_bits; c++) {
                uint8_t bit = pixel[c] & 1;
                size_t byte_pos = bit_idx / 8;
                size_t bit_pos = 7 - (bit_idx % 8);
                if (bit) {
                    header[byte_pos] |= (uint8_t)(1 << bit_pos);
                }
                bit_idx++;
            }
        }
    }

    if (bit_idx < 64) return false;

    uint32_t len = 0;
    StegoEnvelopeType env = stego_payload_detect_envelope(header, bit_idx / 8, &len);
    if (env == STEGO_ENVELOPE_NONE) {
        return false;
    }

    if (out_payload_size) *out_payload_size = (size_t)len;
    return true;
}

StegoResult bmp_decode(const BMPImage *image, uint8_t **out_payload, size_t *out_len) {
    if (!image || !image->raw_data || !out_payload || !out_len) {
        return STEGO_ERR_INVALID_ARG;
    }
    *out_payload = NULL;
    *out_len = 0;

    size_t payload_len = 0;
    if (!bmp_has_payload(image, &payload_len)) {
        return STEGO_ERR_NO_PAYLOAD;
    }

    size_t max_cap = bmp_max_payload_size(image);
    if (payload_len > max_cap) {
        return STEGO_ERR_CORRUPT_PAYLOAD;
    }

    uint8_t *payload = (uint8_t *)calloc(1, payload_len + 1);
    if (!payload) return STEGO_ERR_MEMORY;

    size_t total_bits_to_skip = STEGO_CMC1_HEADER_SIZE * 8;
    size_t total_bits_to_read = payload_len * 8;
    size_t current_bit = 0;
    size_t extracted_bits = 0;

    for (uint32_t y = 0; y < image->height && extracted_bits < total_bits_to_read; y++) {
        const uint8_t *row = image->raw_data + (y * image->row_stride);
        for (uint32_t x = 0; x < image->width && extracted_bits < total_bits_to_read; x++) {
            const uint8_t *pixel = row + (x * 3);
            for (int c = 0; c < 3 && extracted_bits < total_bits_to_read; c++) {
                if (current_bit < total_bits_to_skip) {
                    current_bit++;
                    continue;
                }

                uint8_t bit = pixel[c] & 1;
                size_t byte_pos = extracted_bits / 8;
                size_t bit_pos = 7 - (extracted_bits % 8);
                if (bit) {
                    payload[byte_pos] |= (uint8_t)(1 << bit_pos);
                }
                extracted_bits++;
                current_bit++;
            }
        }
    }

    *out_payload = payload;
    *out_len = payload_len;
    return STEGO_OK;
}

