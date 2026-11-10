/**
 * @file integrity.c
 * @brief CRC-32 integrity and verification helpers.
 */

#include "stego/crypto.h"

uint32_t crypto_calc_checksum(const uint8_t *data, size_t len) {
    return stego_crc32(0, data, len);
}

