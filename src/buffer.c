/**
 * @file buffer.c
 * @brief Dynamic buffer management with secure zeroing.
 */

#include "stego/buffer.h"
#include "stego/crypto.h"
#include <stdlib.h>
#include <string.h>

StegoResult stego_buffer_init(StegoBuffer *buf, size_t initial_capacity) {
    if (!buf) return STEGO_ERR_INVALID_ARG;
    buf->data = NULL;
    buf->size = 0;
    buf->capacity = 0;

    if (initial_capacity > 0) {
        buf->data = (uint8_t *)malloc(initial_capacity);
        if (!buf->data) return STEGO_ERR_MEMORY;
        buf->capacity = initial_capacity;
    }
    return STEGO_OK;
}

StegoResult stego_buffer_append(StegoBuffer *buf, const uint8_t *data, size_t len) {
    if (!buf || (!data && len > 0)) return STEGO_ERR_INVALID_ARG;
    if (len == 0) return STEGO_OK;

    if (buf->size + len > buf->capacity) {
        size_t new_cap = buf->capacity ? buf->capacity * 2 : 256;
        while (new_cap < buf->size + len) {
            new_cap *= 2;
        }
        uint8_t *new_data = (uint8_t *)realloc(buf->data, new_cap);
        if (!new_data) return STEGO_ERR_MEMORY;
        buf->data = new_data;
        buf->capacity = new_cap;
    }

    memcpy(buf->data + buf->size, data, len);
    buf->size += len;
    return STEGO_OK;
}

void stego_buffer_free(StegoBuffer *buf) {
    if (!buf) return;
    if (buf->data) {
        stego_secure_zero(buf->data, buf->capacity);
        free(buf->data);
        buf->data = NULL;
    }
    buf->size = 0;
    buf->capacity = 0;
}

void stego_buffer_secure_wipe(StegoBuffer *buf) {
    if (!buf || !buf->data) return;
    stego_secure_zero(buf->data, buf->capacity);
}

