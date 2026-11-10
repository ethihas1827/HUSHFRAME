/**
 * @file carrier.h
 * @brief Common carrier abstraction for multi-format steganography.
 */

#ifndef STEGO_CARRIER_H
#define STEGO_CARRIER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "stego/error.h"
#include "stego/image_loader.h"
#include "stego/payload.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct StegoCarrier StegoCarrier;

struct StegoCarrier {
    StegoImage *image;
    StegoImageFormat format;
    bool is_adaptive;

    size_t (*max_capacity)(const StegoCarrier *self);
    bool (*has_payload)(const StegoCarrier *self, size_t *out_payload_len);
    StegoEnvelopeType (*detect_envelope)(const StegoCarrier *self, uint32_t *out_payload_len);
    StegoResult (*embed)(StegoCarrier *self, const uint8_t *payload, size_t payload_len);
    StegoResult (*extract)(const StegoCarrier *self, uint8_t **out_payload, size_t *out_len);
    StegoResult (*embed_secure)(StegoCarrier *self, const uint8_t *payload, size_t payload_len, const char *passphrase);
    StegoResult (*extract_secure)(const StegoCarrier *self, const char *passphrase, uint8_t **out_payload, size_t *out_len);
    void (*free)(StegoCarrier *self);
};

StegoResult stego_carrier_open(const char *filepath, bool adaptive, StegoCarrier **out_carrier);
void stego_carrier_close(StegoCarrier *carrier);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_CARRIER_H */
