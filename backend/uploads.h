/**
 * @file uploads.h
 * @brief Multipart upload handling, magic byte validation, and secure temporary files.
 */

#ifndef STEGO_UPLOADS_H
#define STEGO_UPLOADS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "core/stego_core.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STEGO_MAX_UPLOAD_SIZE (64 * 1024 * 1024) /* 64 MB maximum request body */

typedef struct {
    char *name;             /**< Form field name */
    char *filename;         /**< Original client filename (NULL if text field) */
    char *content_type;     /**< Content-Type header (NULL if omitted) */
    uint8_t *data;          /**< Raw binary or text payload */
    size_t size;            /**< Size of payload in bytes */
    bool is_file;           /**< True if part represents an uploaded file */
} UploadPart;

typedef struct {
    UploadPart *parts;
    size_t count;
    size_t capacity;
} MultipartForm;

/**
 * @brief Parse a raw HTTP body encoded as multipart/form-data.
 *
 * @param body Raw body buffer
 * @param body_len Length of raw body in bytes
 * @param boundary Boundary string extracted from Content-Type header (without leading dashes)
 * @return Allocated MultipartForm, or NULL on parse error
 */
MultipartForm *multipart_parse(const uint8_t *body, size_t body_len, const char *boundary);

/**
 * @brief Retrieve a part by its form field name.
 */
const UploadPart *multipart_get_part(const MultipartForm *form, const char *name);

/**
 * @brief Retrieve the value of a text form field as a null-terminated string.
 * Returns NULL if field is missing or empty.
 */
const char *multipart_get_string(const MultipartForm *form, const char *name);

/**
 * @brief Free all memory in a MultipartForm, scrubbing sensitive fields with stego_secure_zero.
 */
void multipart_free(MultipartForm *form);

/**
 * @brief Check whether data buffer begins with valid image magic bytes.
 */
bool uploads_is_valid_image(const uint8_t *data, size_t size, StegoImageFormat *out_fmt);

/**
 * @brief Create a secure temporary file with the given contents and suffix.
 *
 * Returns an allocated path string that must be freed by the caller.
 * The file must be deleted using uploads_cleanup_temp_file() immediately after use.
 */
char *uploads_create_temp_file(const uint8_t *data, size_t size, const char *suffix);

/**
 * @brief Securely zero-overwrite and delete a temporary file.
 */
void uploads_cleanup_temp_file(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_UPLOADS_H */

