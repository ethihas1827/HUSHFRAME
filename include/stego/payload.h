/**
 * @file payload.h
 * @brief Steganographic envelope framing (8-byte CMC1 and 52-byte authenticated CMC2).
 */

#ifndef STEGO_PAYLOAD_H
#define STEGO_PAYLOAD_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "stego/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* Phase 1 CMC1 Unencrypted Header (8 bytes)                                 */
/* ========================================================================= */
#define STEGO_MAGIC_CMC1_BYTE0 'C'
#define STEGO_MAGIC_CMC1_BYTE1 'M'
#define STEGO_MAGIC_CMC1_BYTE2 'C'
#define STEGO_MAGIC_CMC1_BYTE3 '1'

#define STEGO_CMC1_HEADER_SIZE 8

/* ========================================================================= */
/* Phase 3 CMC2 Authenticated Encrypted Header (52 bytes)                     */
/* ========================================================================= */
#define STEGO_MAGIC_CMC2_BYTE0 'C'
#define STEGO_MAGIC_CMC2_BYTE1 'M'
#define STEGO_MAGIC_CMC2_BYTE2 'C'
#define STEGO_MAGIC_CMC2_BYTE3 '2'

#define STEGO_CMC2_SALT_SIZE   16
#define STEGO_CMC2_NONCE_SIZE  12
#define STEGO_CMC2_TAG_SIZE    16
#define STEGO_CMC2_AAD_SIZE    36 /* 4 magic + 4 len + 16 salt + 12 nonce */
#define STEGO_CMC2_HEADER_SIZE 52 /* 36 AAD + 16 Tag */

/* ========================================================================= */
/* Phase 4 CMC3 Multi-Part Unencrypted Header (118 bytes)                     */
/* ========================================================================= */
#define STEGO_MAGIC_CMC3_BYTE0 'C'
#define STEGO_MAGIC_CMC3_BYTE1 'M'
#define STEGO_MAGIC_CMC3_BYTE2 'C'
#define STEGO_MAGIC_CMC3_BYTE3 '3'
#define STEGO_CMC3_HEADER_SIZE 118

/* ========================================================================= */
/* Phase 4 CMC4 Multi-Part Authenticated Encrypted Header (162 bytes)         */
/* ========================================================================= */
#define STEGO_MAGIC_CMC4_BYTE0 'C'
#define STEGO_MAGIC_CMC4_BYTE1 'M'
#define STEGO_MAGIC_CMC4_BYTE2 'C'
#define STEGO_MAGIC_CMC4_BYTE3 '4'
#define STEGO_CMC4_HEADER_SIZE 162

typedef enum {
    STEGO_ENVELOPE_NONE = 0,
    STEGO_ENVELOPE_CMC1,
    STEGO_ENVELOPE_CMC2,
    STEGO_ENVELOPE_CMC3,
    STEGO_ENVELOPE_CMC4
} StegoEnvelopeType;

/**
 * @brief Pack an 8-byte CMC1 header into destination buffer.
 */
void stego_payload_pack_cmc1(uint8_t *dest, uint32_t payload_len);

/**
 * @brief Validate and unpack an 8-byte CMC1 header.
 */
bool stego_payload_unpack_cmc1(const uint8_t *src, uint32_t *out_payload_len);

/**
 * @brief Pack a 52-byte CMC2 authenticated header into destination buffer.
 */
void stego_payload_pack_cmc2(uint8_t *dest, uint32_t payload_len, const uint8_t *salt, const uint8_t *nonce, const uint8_t *tag);

/**
 * @brief Validate and unpack a 52-byte CMC2 header.
 */
bool stego_payload_unpack_cmc2(const uint8_t *src, uint32_t *out_payload_len, uint8_t *out_salt, uint8_t *out_nonce, uint8_t *out_tag);

/**
 * @brief Detect envelope type (CMC1 or CMC2) from raw header buffer.
 */
StegoEnvelopeType stego_payload_detect_envelope(const uint8_t *src, size_t buf_len, uint32_t *out_payload_len);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_PAYLOAD_H */
