/**
 * @file error.h
 * @brief Unified error codes and error string utilities for steganography toolkit.
 */

#ifndef STEGO_ERROR_H
#define STEGO_ERROR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    STEGO_OK = 0,
    STEGO_ERR_FILE_NOT_FOUND,
    STEGO_ERR_FILE_WRITE,
    STEGO_ERR_FILE_READ,
    STEGO_ERR_INVALID_BMP,
    STEGO_ERR_INVALID_PNG,
    STEGO_ERR_INVALID_FORMAT,
    STEGO_ERR_UNSUPPORTED_FORMAT,
    STEGO_ERR_CAPACITY_EXCEEDED,
    STEGO_ERR_NO_PAYLOAD,
    STEGO_ERR_CORRUPT_PAYLOAD,
    STEGO_ERR_AUTH_FAILED,
    STEGO_ERR_MEMORY,
    STEGO_ERR_INVALID_ARG,
    STEGO_ERR_UNSAFE_CONVERSION,
    STEGO_ERR_NOT_IMPLEMENTED,
    STEGO_ERR_IMAGE_TOO_LARGE,
    STEGO_ERR_IMAGE_DECODE,
    STEGO_ERR_IMAGE_INVALID_DATA
} StegoResult;

/**
 * @brief Convert StegoResult enum value to human-readable error description.
 */
const char *stego_strerror(StegoResult result);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_ERROR_H */

