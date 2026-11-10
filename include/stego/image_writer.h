/**
 * @file image_writer.h
 * @brief Unified image saving abstraction supporting BMP and PNG.
 */

#ifndef STEGO_IMAGE_WRITER_H
#define STEGO_IMAGE_WRITER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "stego/error.h"
#include "stego/image_loader.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Save a StegoImage to disk in the specified target format.
 */
StegoResult stego_image_save(const char *filepath, const StegoImage *image, StegoImageFormat target_format);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_IMAGE_WRITER_H */

