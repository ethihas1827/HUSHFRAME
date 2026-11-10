/**
 * @file payload.c
 * @brief Steganographic envelope packaging and validation (CMC1 and CMC2).
 */

#include "stego/payload.h"
#include <string.h>

void stego_payload_pack_cmc1(uint8_t *dest, uint32_t payload_len) {
    if (!dest) return;
    dest[0] = STEGO_MAGIC_CMC1_BYTE0; /* 'C' */
    dest[1] = STEGO_MAGIC_CMC1_BYTE1; /* 'M' */
    dest[2] = STEGO_MAGIC_CMC1_BYTE2; /* 'C' */
    dest[3] = STEGO_MAGIC_CMC1_BYTE3; /* '1' */

    /* 32-bit payload length in Big-Endian */
    dest[4] = (uint8_t)((payload_len >> 24) & 0xFF);
    dest[5] = (uint8_t)((payload_len >> 16) & 0xFF);
    dest[6] = (uint8_t)((payload_len >> 8)  & 0xFF);
    dest[7] = (uint8_t)(payload_len         & 0xFF);
}

bool stego_payload_unpack_cmc1(const uint8_t *src, uint32_t *out_payload_len) {
    if (!src) return false;

    if (src[0] != STEGO_MAGIC_CMC1_BYTE0 ||
        src[1] != STEGO_MAGIC_CMC1_BYTE1 ||
        src[2] != STEGO_MAGIC_CMC1_BYTE2 ||
        src[3] != STEGO_MAGIC_CMC1_BYTE3) {
        return false;
    }

    if (out_payload_len) {
        *out_payload_len = ((uint32_t)src[4] << 24) |
                           ((uint32_t)src[5] << 16) |
                           ((uint32_t)src[6] << 8)  |
                           ((uint32_t)src[7]);
    }
    return true;
}

void stego_payload_pack_cmc2(uint8_t *dest, uint32_t payload_len, const uint8_t *salt, const uint8_t *nonce, const uint8_t *tag) {
    if (!dest || !salt || !nonce || !tag) return;

    /* Bytes 0..3: Magic "CMC2" */
    dest[0] = STEGO_MAGIC_CMC2_BYTE0; /* 'C' */
    dest[1] = STEGO_MAGIC_CMC2_BYTE1; /* 'M' */
    dest[2] = STEGO_MAGIC_CMC2_BYTE2; /* 'C' */
    dest[3] = STEGO_MAGIC_CMC2_BYTE3; /* '2' */

    /* Bytes 4..7: 32-bit payload length in Big-Endian */
    dest[4] = (uint8_t)((payload_len >> 24) & 0xFF);
    dest[5] = (uint8_t)((payload_len >> 16) & 0xFF);
    dest[6] = (uint8_t)((payload_len >> 8)  & 0xFF);
    dest[7] = (uint8_t)(payload_len         & 0xFF);

    /* Bytes 8..23: 16-byte Argon2id salt */
    memcpy(dest + 8, salt, STEGO_CMC2_SALT_SIZE);

    /* Bytes 24..35: 12-byte AES-GCM nonce */
    memcpy(dest + 24, nonce, STEGO_CMC2_NONCE_SIZE);

    /* Bytes 36..51: 16-byte AES-GCM auth tag */
    memcpy(dest + 36, tag, STEGO_CMC2_TAG_SIZE);
}

bool stego_payload_unpack_cmc2(const uint8_t *src, uint32_t *out_payload_len, uint8_t *out_salt, uint8_t *out_nonce, uint8_t *out_tag) {
    if (!src) return false;

    if (src[0] != STEGO_MAGIC_CMC2_BYTE0 ||
        src[1] != STEGO_MAGIC_CMC2_BYTE1 ||
        src[2] != STEGO_MAGIC_CMC2_BYTE2 ||
        src[3] != STEGO_MAGIC_CMC2_BYTE3) {
        return false;
    }

    if (out_payload_len) {
        *out_payload_len = ((uint32_t)src[4] << 24) |
                           ((uint32_t)src[5] << 16) |
                           ((uint32_t)src[6] << 8)  |
                           ((uint32_t)src[7]);
    }
    if (out_salt) {
        memcpy(out_salt, src + 8, STEGO_CMC2_SALT_SIZE);
    }
    if (out_nonce) {
        memcpy(out_nonce, src + 24, STEGO_CMC2_NONCE_SIZE);
    }
    if (out_tag) {
        memcpy(out_tag, src + 36, STEGO_CMC2_TAG_SIZE);
    }
    return true;
}

StegoEnvelopeType stego_payload_detect_envelope(const uint8_t *src, size_t buf_len, uint32_t *out_payload_len) {
    if (!src || buf_len < 4) return STEGO_ENVELOPE_NONE;

    if (buf_len >= STEGO_CMC4_HEADER_SIZE &&
        src[0] == STEGO_MAGIC_CMC4_BYTE0 &&
        src[1] == STEGO_MAGIC_CMC4_BYTE1 &&
        src[2] == STEGO_MAGIC_CMC4_BYTE2 &&
        src[3] == STEGO_MAGIC_CMC4_BYTE3) {
        if (out_payload_len) {
            *out_payload_len = ((uint32_t)src[8] << 24) |
                               ((uint32_t)src[9] << 16) |
                               ((uint32_t)src[10] << 8) |
                                ((uint32_t)src[11]);
        }
        return STEGO_ENVELOPE_CMC4;
    }

    if (buf_len >= STEGO_CMC3_HEADER_SIZE &&
        src[0] == STEGO_MAGIC_CMC3_BYTE0 &&
        src[1] == STEGO_MAGIC_CMC3_BYTE1 &&
        src[2] == STEGO_MAGIC_CMC3_BYTE2 &&
        src[3] == STEGO_MAGIC_CMC3_BYTE3) {
        if (out_payload_len) {
            *out_payload_len = ((uint32_t)src[8] << 24) |
                               ((uint32_t)src[9] << 16) |
                               ((uint32_t)src[10] << 8) |
                                ((uint32_t)src[11]);
        }
        return STEGO_ENVELOPE_CMC3;
    }

    if (buf_len >= STEGO_CMC2_HEADER_SIZE &&
        src[0] == STEGO_MAGIC_CMC2_BYTE0 &&
        src[1] == STEGO_MAGIC_CMC2_BYTE1 &&
        src[2] == STEGO_MAGIC_CMC2_BYTE2 &&
        src[3] == STEGO_MAGIC_CMC2_BYTE3) {
        if (out_payload_len) {
            *out_payload_len = ((uint32_t)src[4] << 24) |
                               ((uint32_t)src[5] << 16) |
                               ((uint32_t)src[6] << 8)  |
                               ((uint32_t)src[7]);
        }
        return STEGO_ENVELOPE_CMC2;
    }

    if (buf_len >= STEGO_CMC1_HEADER_SIZE &&
        src[0] == STEGO_MAGIC_CMC1_BYTE0 &&
        src[1] == STEGO_MAGIC_CMC1_BYTE1 &&
        src[2] == STEGO_MAGIC_CMC1_BYTE2 &&
        src[3] == STEGO_MAGIC_CMC1_BYTE3) {
        if (out_payload_len) {
            *out_payload_len = ((uint32_t)src[4] << 24) |
                               ((uint32_t)src[5] << 16) |
                               ((uint32_t)src[6] << 8)  |
                               ((uint32_t)src[7]);
        }
        return STEGO_ENVELOPE_CMC1;
    }

    return STEGO_ENVELOPE_NONE;
}
