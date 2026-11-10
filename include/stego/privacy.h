/**
 * @file privacy.h
 * @brief Privacy verification, safe sharing, and secure file wiping.
 */

#ifndef STEGO_PRIVACY_H
#define STEGO_PRIVACY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "stego/error.h"
#include "stego/metadata.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Overwrite file contents with zeroes before unlinking from filesystem.
 */
StegoResult stego_secure_delete_file(const char *filepath);

/**
 * @brief Generate human-readable privacy risk report for an image file.
 */
StegoResult stego_privacy_report(const char *filepath);

/**
 * @brief Create safe-share cleaned image (strips metadata, keeps image intact).
 */
StegoResult stego_safe_share(const char *input_path, const char *output_path);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_PRIVACY_H */

