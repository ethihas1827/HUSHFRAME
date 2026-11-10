/**
 * @file metadata.h
 * @brief EXIF, GPS, and image metadata inspection and stripping.
 */

#ifndef STEGO_METADATA_H
#define STEGO_METADATA_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "stego/error.h"

#ifdef __cplusplus
extern "C" {
#endif

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
    char latitude_ref[4];    /* "N" or "S" */
    char longitude_ref[4];   /* "E" or "W" */
    double altitude;
    bool has_altitude;
    char gps_timestamp[64];
    bool has_timestamp;
    size_t metadata_bytes;
    char risk_level[16];   /* "Low", "Medium", "High" */
    char risk_reason[128];
} StegoMetadataInfo;

StegoResult stego_metadata_scan(const char *filepath, StegoMetadataInfo *info);
StegoResult stego_metadata_strip(const char *input_path, const char *output_path);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_METADATA_H */

