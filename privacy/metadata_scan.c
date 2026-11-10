/**
 * @file metadata_scan.c
 * @brief EXIF and GPS metadata scanner.
 */

#include "stego/metadata.h"

StegoResult privacy_scan_exif(const char *filepath, StegoMetadataInfo *info) {
    return stego_metadata_scan(filepath, info);
}

