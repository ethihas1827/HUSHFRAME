/**
 * @file privacy.c
 * @brief Secure file shredding, privacy risk reports, and safe sharing.
 */

#include "stego/privacy.h"
#include "stego/crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

StegoResult stego_secure_delete_file(const char *filepath) {
    if (!filepath) return STEGO_ERR_INVALID_ARG;

    FILE *fp = fopen(filepath, "r+b");
    if (!fp) return STEGO_ERR_FILE_NOT_FOUND;

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    if (fsize < 0) {
        fclose(fp);
        return STEGO_ERR_FILE_READ;
    }

    fseek(fp, 0, SEEK_SET);
    uint8_t zeros[4096] = { 0 };
    size_t remaining = (size_t)fsize;

    while (remaining > 0) {
        size_t chunk = remaining > sizeof(zeros) ? sizeof(zeros) : remaining;
        if (fwrite(zeros, 1, chunk, fp) != chunk) {
            fclose(fp);
            return STEGO_ERR_FILE_WRITE;
        }
        remaining -= chunk;
    }

    fflush(fp);
    fclose(fp);

    /* Unlink file */
    if (remove(filepath) != 0) {
        return STEGO_ERR_FILE_WRITE;
    }
    return STEGO_OK;
}

StegoResult stego_privacy_report(const char *filepath) {
    if (!filepath) return STEGO_ERR_INVALID_ARG;

    StegoMetadataInfo info;
    StegoResult res = stego_metadata_scan(filepath, &info);
    if (res != STEGO_OK) return res;

    printf("\n================ Privacy & Metadata Risk Report ================\n");
    printf("Target File      : %s\n", filepath);
    printf("EXIF Metadata    : %s\n", info.has_exif ? "DETECTED (Potential privacy risk)" : "None detected");
    printf("GPS Location Data: %s\n", info.has_gps ? "DETECTED (High geolocation risk!)" : "None detected");
    printf("Privacy Status   : %s\n", (info.has_exif || info.has_gps) ? "Action Recommended (use 'strip-metadata' or 'safe-share')" : "Clean (No sensitive tags identified)");
    printf("Processing Mode  : 100%% Local-Only (Zero network requests, zero telemetry)\n");
    printf("=================================================================\n");
    return STEGO_OK;
}

StegoResult stego_safe_share(const char *input_path, const char *output_path) {
    return stego_metadata_strip(input_path, output_path);
}

