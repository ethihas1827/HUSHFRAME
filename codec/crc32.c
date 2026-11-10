/**
 * @file crc32.c
 * @brief CRC-32 codec implementation.
 */

#include "stego/crypto.h"

uint32_t codec_crc32(const uint8_t *data, size_t len) {
    return stego_crc32(0, data, len);
}

