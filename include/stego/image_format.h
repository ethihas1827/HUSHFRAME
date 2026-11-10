/**
 * @file image_format.h
 * @brief Image format detection by magic bytes and conversion safety validation.
 */

#ifndef STEGO_IMAGE_FORMAT_H
#define STEGO_IMAGE_FORMAT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    STEGO_FORMAT_UNKNOWN = 0,
    STEGO_FORMAT_BMP,
    STEGO_FORMAT_PNG,
    STEGO_FORMAT_JPEG,
    STEGO_FORMAT_WEBP,
    STEGO_FORMAT_GIF,
    STEGO_FORMAT_TGA,
    STEGO_FORMAT_HEIC
} StegoImageFormat;

/**
 * @brief Detect image format by inspecting magic bytes of an on-disk file.
 *
 * Never relies on file extension. Returns STEGO_FORMAT_UNKNOWN if file
 * cannot be opened or magic bytes do not match a known format.
 */
StegoImageFormat stego_detect_format(const char *filepath);

/**
 * @brief Detect image format from a memory buffer.
 */
StegoImageFormat stego_detect_format_buffer(const uint8_t *buffer, size_t size);

/**
 * @brief Get human-readable format name string (e.g. "PNG", "BMP", "JPEG", "HEIC").
 */
const char *stego_format_name(StegoImageFormat format);

/**
 * @brief Check whether the format supports lossless pixel steganography.
 *
 * BMP and PNG are lossless; JPEG is lossy and will destroy spatial LSB bits.
 */
bool stego_format_is_lossless(StegoImageFormat format);

/**
 * @brief Verify safety of saving steganographic data from cover to target format.
 *
 * Returns true if safe, false if target format is lossy or incompatible.
 */
bool stego_is_safe_carrier_format(StegoImageFormat input_fmt, StegoImageFormat output_fmt);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_IMAGE_FORMAT_H */

