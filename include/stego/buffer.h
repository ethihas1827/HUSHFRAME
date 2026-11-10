/**
 * @file buffer.h
 * @brief Memory buffer management with secure zeroing utilities.
 */

#ifndef STEGO_BUFFER_H
#define STEGO_BUFFER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "stego/error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t *data;
    size_t size;
    size_t capacity;
} StegoBuffer;

StegoResult stego_buffer_init(StegoBuffer *buf, size_t initial_capacity);
StegoResult stego_buffer_append(StegoBuffer *buf, const uint8_t *data, size_t len);
void stego_buffer_free(StegoBuffer *buf);
void stego_buffer_secure_wipe(StegoBuffer *buf);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_BUFFER_H */

