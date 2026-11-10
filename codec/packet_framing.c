/**
 * @file packet_framing.c
 * @brief Steganographic packet envelope framing.
 */

#include "stego/payload.h"

void codec_pack_header(uint8_t *dest, uint32_t len) {
    stego_payload_pack_cmc1(dest, len);
}

