/**
 * @file bmp_embed.c
 * @brief 24-bit uncompressed BMP LSB embedding implementation.
 */

#include "stego/bmp_carrier.h"
#include "stego/payload.h"
#include <stdlib.h>
#include <string.h>

size_t bmp_max_payload_size(const BMPImage *image) {
    if (!image || !image->raw_data || image->width == 0 || image->height == 0) return 0;
    size_t available_bits = (size_t)image->width * image->height * 3;
    size_t available_bytes = available_bits / 8;
    if (available_bytes <= STEGO_CMC1_HEADER_SIZE) return 0;
    return available_bytes - STEGO_CMC1_HEADER_SIZE;
}

StegoResult bmp_encode(BMPImage *image, const uint8_t *payload, size_t payload_len) {
    if (!image || !image->raw_data) return STEGO_ERR_INVALID_ARG;
    if (payload_len > 0 && !payload) return STEGO_ERR_INVALID_ARG;

    size_t max_cap = bmp_max_payload_size(image);
    if (payload_len > max_cap) return STEGO_ERR_CAPACITY_EXCEEDED;

    size_t total_stream_len = STEGO_CMC1_HEADER_SIZE + payload_len;
    uint8_t *stream = (uint8_t *)malloc(total_stream_len);
    if (!stream) return STEGO_ERR_MEMORY;

    stego_payload_pack_cmc1(stream, (uint32_t)payload_len);
    if (payload_len > 0) {
        memcpy(stream + STEGO_CMC1_HEADER_SIZE, payload, payload_len);
    }

    size_t total_bits = total_stream_len * 8;
    size_t bit_idx = 0;

    for (uint32_t y = 0; y < image->height && bit_idx < total_bits; y++) {
        uint8_t *row = image->raw_data + (y * image->row_stride);
        for (uint32_t x = 0; x < image->width && bit_idx < total_bits; x++) {
            uint8_t *pixel = row + (x * 3);
            for (int c = 0; c < 3 && bit_idx < total_bits; c++) {
                size_t byte_pos = bit_idx / 8;
                size_t bit_pos = 7 - (bit_idx % 8);
                uint8_t bit = (uint8_t)((stream[byte_pos] >> bit_pos) & 1);

                pixel[c] = (uint8_t)((pixel[c] & 0xFE) | bit);
                bit_idx++;
            }
        }
    }

    free(stream);
    return STEGO_OK;
}

