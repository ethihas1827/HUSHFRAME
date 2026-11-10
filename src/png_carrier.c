/**
 * @file png_carrier.c
 * @brief PNG polymorphic carrier binding.
 */

#include "stego/png_carrier.h"
#include <stdlib.h>

static size_t png_carrier_max_capacity(const StegoCarrier *self) {
    if (!self || !self->image) return 0;
    return png_max_payload_size(self->image, self->is_adaptive);
}

static bool png_carrier_has_payload(const StegoCarrier *self, size_t *out_payload_len) {
    if (!self || !self->image) return false;
    return png_has_payload(self->image, self->is_adaptive, out_payload_len);
}

static StegoEnvelopeType png_carrier_detect_envelope(const StegoCarrier *self, uint32_t *out_payload_len) {
    if (!self || !self->image) return STEGO_ENVELOPE_NONE;
    return png_detect_envelope(self->image, self->is_adaptive, out_payload_len);
}

static StegoResult png_carrier_embed(StegoCarrier *self, const uint8_t *payload, size_t payload_len) {
    if (!self || !self->image) return STEGO_ERR_INVALID_ARG;
    return png_encode(self->image, payload, payload_len, self->is_adaptive);
}

static StegoResult png_carrier_extract(const StegoCarrier *self, uint8_t **out_payload, size_t *out_len) {
    if (!self || !self->image) return STEGO_ERR_INVALID_ARG;
    return png_decode(self->image, out_payload, out_len, self->is_adaptive);
}

static StegoResult png_carrier_embed_secure(StegoCarrier *self, const uint8_t *payload, size_t payload_len, const char *passphrase) {
    if (!self || !self->image) return STEGO_ERR_INVALID_ARG;
    return png_encode_secure(self->image, payload, payload_len, passphrase, self->is_adaptive);
}

static StegoResult png_carrier_extract_secure(const StegoCarrier *self, const char *passphrase, uint8_t **out_payload, size_t *out_len) {
    if (!self || !self->image) return STEGO_ERR_INVALID_ARG;
    return png_decode_secure(self->image, passphrase, out_payload, out_len, self->is_adaptive);
}

static void png_carrier_free(StegoCarrier *self) {
    if (!self) return;
    if (self->image) {
        stego_image_free(self->image);
        self->image = NULL;
    }
    free(self);
}

StegoResult stego_png_carrier_create(StegoImage *image, bool adaptive, StegoCarrier **out_carrier) {
    if (!image || !out_carrier) return STEGO_ERR_INVALID_ARG;
    *out_carrier = NULL;

    StegoCarrier *c = (StegoCarrier *)calloc(1, sizeof(StegoCarrier));
    if (!c) return STEGO_ERR_MEMORY;

    c->image = image;
    c->format = STEGO_FORMAT_PNG;
    c->is_adaptive = adaptive;
    c->max_capacity = png_carrier_max_capacity;
    c->has_payload = png_carrier_has_payload;
    c->detect_envelope = png_carrier_detect_envelope;
    c->embed = png_carrier_embed;
    c->extract = png_carrier_extract;
    c->embed_secure = png_carrier_embed_secure;
    c->extract_secure = png_carrier_extract_secure;
    c->free = png_carrier_free;

    *out_carrier = c;
    return STEGO_OK;
}
