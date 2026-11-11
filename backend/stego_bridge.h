/**
 * @file stego_bridge.h
 * @brief Bridge between HTTP request payloads and the native C steganography engine.
 */

#ifndef STEGO_BRIDGE_H
#define STEGO_BRIDGE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "core/stego_core.h"
#include "stego/split.h"
#include "stego/capacity.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t *png_data;
    size_t png_size;
    char notice[256];
    char protection_label[64];
    char envelope_name[64];
    bool is_protected;
    bool is_compressed;
    int bits_per_channel;
    uint32_t width;
    uint32_t height;

    /* Capacity shortfall details if capacity exceeded */
    bool capacity_exceeded;
    char secret_name[256];
    size_t secret_size;
    size_t available_capacity;
    size_t additional_required;
    uint32_t rec_min_width;
    uint32_t rec_min_height;
    uint32_t rec_square_dim;

    char error_msg[256];
} BridgeHideResult;

typedef struct {
    uint8_t *payload_data;
    size_t payload_size;
    bool is_text;
    bool is_file;
    char filename[256];
    char sha256_hex[65];
    bool is_protected;
    bool is_split_part;
    uint16_t part_num;
    uint16_t total_parts;
    char envelope_name[64];
    char protection_label[64];
    char error_msg[256];
} BridgeRevealResult;

typedef struct {
    bool has_exif;
    bool has_gps;
    bool has_camera_info;
    char camera_make[64];
    char camera_model[64];
    char software[64];
    char datetime[32];
    double latitude;
    double longitude;
    char latitude_ref[4];
    char longitude_ref[4];
    double altitude;
    bool has_altitude;
    char gps_timestamp[64];
    bool has_timestamp;
    char risk_level[16];     /* "Low", "Medium", "High" */
    char risk_reason[128];
    size_t metadata_bytes;
    char error_msg[256];
} BridgeMetadataScanResult;

typedef struct {
    uint8_t *clean_image_data;
    size_t clean_image_size;
    char clean_filename[256];
    char format[16];
    size_t bytes_removed;
    char error_msg[256];
} BridgeMetadataStripResult;

typedef struct {
    bool has_payload;
    bool is_protected;
    uint32_t payload_length;
    char envelope_name[64];
    char protection_label[64];
    char error_msg[256];
} BridgeVerifyResult;

typedef struct {
    char format[32];
    char mime_type[64];
    size_t file_size;
    char original_mode[64];
    char normalized_mode[64];
    uint32_t width;
    uint32_t height;
    uint32_t channels;
    bool was_converted;
    size_t unencrypted_capacity;
    size_t encrypted_capacity;
    size_t capacity_2bit;
    size_t capacity_3bit;
    bool has_payload;
    char envelope_name[64];
    char notice[256];
    char error_msg[256];
} BridgeCapacityResult;

typedef struct {
    uint16_t total_parts;
    char manifest_json[4096];
    struct {
        uint16_t part_num;
        char filename[128];
        uint8_t *png_data;
        size_t png_size;
    } parts[STEGO_MAX_SPLIT_PARTS];
    char error_msg[256];
} BridgeSplitHideResult;

/**
 * @brief Base64 encode binary buffer. Returns newly allocated null-terminated string.
 */
char *stego_base64_encode(const uint8_t *data, size_t input_length);

/**
 * @brief Base64 decode string. Returns newly allocated byte buffer.
 */
uint8_t *stego_base64_decode(const char *data, size_t *out_len);

/**
 * @brief Bridge operation for /api/hide (standard).
 */
StegoResult bridge_hide(const uint8_t *cover_bytes, size_t cover_len,
                        const uint8_t *secret_bytes, size_t secret_len,
                        const char *passphrase, bool adaptive,
                        BridgeHideResult *out);

/**
 * @brief Advanced bridge operation for /api/hide with compression and bit depth.
 */
StegoResult bridge_hide_advanced(const uint8_t *cover_bytes, size_t cover_len,
                                 const uint8_t *secret_bytes, size_t secret_len,
                                 const char *secret_filename,
                                 const char *passphrase, bool adaptive,
                                 bool compress, int bits_per_channel,
                                 BridgeHideResult *out);

/**
 * @brief Bridge operation for multi-image splitting (/api/split-hide).
 */
StegoResult bridge_split_hide(const uint8_t **cover_bytes_array, const size_t *cover_lens,
                              uint16_t num_covers,
                              const uint8_t *secret_bytes, size_t secret_len,
                              const char *secret_filename,
                              const char *passphrase, bool compress, int bits_per_channel,
                              BridgeSplitHideResult *out);

/**
 * @brief Bridge operation for multi-image recombination (/api/split-reveal).
 */
StegoResult bridge_split_reveal(const uint8_t **stego_bytes_array, const size_t *stego_lens,
                                uint16_t num_stego_images,
                                const char *passphrase,
                                BridgeRevealResult *out);

/**
 * @brief Bridge operation for /api/reveal.
 */
StegoResult bridge_reveal(const uint8_t *stego_bytes, size_t stego_len,
                          const char *passphrase,
                          BridgeRevealResult *out);

/**
 * @brief Bridge operation for /api/verify.
 */
StegoResult bridge_verify(const uint8_t *img_bytes, size_t img_len,
                          BridgeVerifyResult *out);

/**
 * @brief Bridge operation for /api/capacity.
 */
StegoResult bridge_capacity(const uint8_t *img_bytes, size_t img_len,
                            bool adaptive,
                            BridgeCapacityResult *out);

/**
 * @brief Free heap allocations inside BridgeHideResult.
 */
void bridge_hide_result_free(BridgeHideResult *res);

/**
 * @brief Free heap allocations inside BridgeSplitHideResult.
 */
void bridge_split_hide_result_free(BridgeSplitHideResult *res);

/**
 * @brief Free heap allocations inside BridgeRevealResult.
 */
void bridge_reveal_result_free(BridgeRevealResult *res);

/**
 * @brief Bridge operation for /api/metadata-scan.
 */
StegoResult bridge_metadata_scan(const uint8_t *img_bytes, size_t img_len,
                                 BridgeMetadataScanResult *out);

/**
 * @brief Bridge operation for /api/metadata-strip.
 */
StegoResult bridge_metadata_strip(const uint8_t *img_bytes, size_t img_len,
                                  const char *orig_filename,
                                  BridgeMetadataStripResult *out);

/**
 * @brief Free heap allocations inside BridgeMetadataStripResult.
 */
void bridge_metadata_strip_result_free(BridgeMetadataStripResult *res);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_BRIDGE_H */
