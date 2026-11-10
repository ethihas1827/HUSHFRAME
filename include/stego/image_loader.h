/**
 * @file image_loader.h
 * @brief Unified image loading abstraction supporting BMP and PNG.
 */

#ifndef STEGO_IMAGE_LOADER_H
#define STEGO_IMAGE_LOADER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "stego/error.h"
#include "stego/image_format.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STEGO_MAX_IMAGE_DIMENSION   16384
#define STEGO_MAX_IMAGE_PIXEL_BYTES (256 * 1024 * 1024) /* 256 MB */

typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t channels;          /**< Normalized channels: 3 for RGB, 4 for RGBA */
    size_t stride;              /**< Bytes per row */
    size_t data_size;           /**< Total bytes in pixels buffer */
    uint8_t *pixels;            /**< Raw contiguous interleaved 8-bit RGB or RGBA pixel bytes */
    StegoImageFormat format;    /**< Original source format detected from magic bytes */

    /* Original Image Properties prior to 8-bit RGB/RGBA normalization */
    int orig_channels;          /**< Original channels: 1 (gray), 2 (gray+alpha), 3 (RGB), 4 (RGBA) */
    int orig_bit_depth;         /**< Original bit depth per channel (1, 2, 4, 8, 16) */
    char orig_color_mode[32];   /**< Human-readable description ("Grayscale", "Palette", "RGB", "RGBA") */
    bool was_converted;         /**< True if converted from palette, grayscale, 16-bit, or non-PNG/BMP */
    StegoImageFormat target_fmt;/**< Safe target stego format (always STEGO_FORMAT_PNG for normalized carriers) */
} StegoImage;

/**
 * @brief Load an image file into memory, automatically detecting format from magic bytes.
 */
StegoResult stego_image_load(const char *filepath, StegoImage **out_image);

/**
 * @brief Create a blank in-memory image buffer with given dimensions.
 */
StegoResult stego_image_create(uint32_t width, uint32_t height, uint32_t channels, StegoImageFormat format, StegoImage **out_image);

/**
 * @brief Free a StegoImage and its allocated pixel memory.
 */
void stego_image_free(StegoImage *image);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_IMAGE_LOADER_H */

