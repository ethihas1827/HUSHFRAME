/**
 * @file stego.c
 * @brief Unified steganography engine supporting BMP and PNG carriers with AES-256-GCM encryption.
 */

#include "stego/stego.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================= */
/* Backward Compatibility API (BMPImage)                                     */
/* ========================================================================= */

size_t stego_max_payload_size(const BMPImage *image) {
    return bmp_max_payload_size(image);
}

bool stego_has_payload(const BMPImage *image, size_t *out_payload_size) {
    return bmp_has_payload(image, out_payload_size);
}

StegoResult stego_encode(BMPImage *image, const uint8_t *payload, size_t payload_len) {
    return bmp_encode(image, payload, payload_len);
}

StegoResult stego_decode(const BMPImage *image, uint8_t **out_payload, size_t *out_len) {
    return bmp_decode(image, out_payload, out_len);
}

StegoResult stego_hide_file(const char *cover_path, const char *stego_path, const char *secret_file_path) {
    return stego_hide_file_unified_secure(cover_path, stego_path, secret_file_path, NULL, false);
}

StegoResult stego_extract_file(const char *stego_path, const char *output_path) {
    return stego_extract_file_unified_secure(stego_path, output_path, NULL, false);
}

StegoResult stego_hide_file_secure(const char *cover_path, const char *stego_path, const char *secret_file_path, const char *passphrase) {
    return stego_hide_file_unified_secure(cover_path, stego_path, secret_file_path, passphrase, false);
}

StegoResult stego_extract_file_secure(const char *stego_path, const char *output_path, const char *passphrase) {
    return stego_extract_file_unified_secure(stego_path, output_path, passphrase, false);
}

StegoResult stego_hide_file_unified(const char *cover_path, const char *stego_path, const char *secret_file_path, bool adaptive) {
    return stego_hide_file_unified_secure(cover_path, stego_path, secret_file_path, NULL, adaptive);
}

StegoResult stego_extract_file_unified(const char *stego_path, const char *output_path, bool adaptive) {
    return stego_extract_file_unified_secure(stego_path, output_path, NULL, adaptive);
}

/* ========================================================================= */
/* Unified Multi-Format High-Level API (BMP & PNG)                           */
/* ========================================================================= */

StegoResult stego_hide_file_unified_advanced(const char *cover_path, const char *stego_path, const char *secret_file_path, const char *passphrase, bool adaptive, bool compress, int bits_per_channel) {
    if (!cover_path || !stego_path || !secret_file_path) return STEGO_ERR_INVALID_ARG;
    if (bits_per_channel < 1) bits_per_channel = 1;
    if (bits_per_channel > 3) bits_per_channel = 3;

    /* Detect format of cover image by magic bytes */
    StegoImageFormat in_fmt = stego_detect_format(cover_path);
    if (in_fmt == STEGO_FORMAT_UNKNOWN) return STEGO_ERR_INVALID_FORMAT;

    /* Determine output format based on target file name or inherit from input */
    StegoImageFormat out_fmt = STEGO_FORMAT_PNG;
    if (in_fmt == STEGO_FORMAT_BMP) {
        out_fmt = STEGO_FORMAT_BMP;
    }

    const char *dot = strrchr(stego_path, '.');
    if (dot) {
        if (_stricmp(dot, ".png") == 0) out_fmt = STEGO_FORMAT_PNG;
        else if (_stricmp(dot, ".bmp") == 0) out_fmt = STEGO_FORMAT_BMP;
        else if (_stricmp(dot, ".jpg") == 0 || _stricmp(dot, ".jpeg") == 0 ||
                 _stricmp(dot, ".webp") == 0 || _stricmp(dot, ".gif") == 0) {
            fprintf(stderr, "[-] Warning: Target format '%s' is lossy/unsuitable and will destroy spatial LSB bits!\n", dot);
            return STEGO_ERR_UNSAFE_CONVERSION;
        }
    }

    if (!stego_is_safe_carrier_format(in_fmt, out_fmt)) {
        return STEGO_ERR_UNSAFE_CONVERSION;
    }

    if (in_fmt != STEGO_FORMAT_PNG && in_fmt != STEGO_FORMAT_BMP) {
        printf("[*] Notice: Input '%s' (%s) normalized to 8-bit pixels; saving stego output as lossless PNG.\n",
               cover_path, stego_format_name(in_fmt));
    }

    /* Read secret payload from disk */
    FILE *sfp = fopen(secret_file_path, "rb");
    if (!sfp) return STEGO_ERR_FILE_NOT_FOUND;

    fseek(sfp, 0, SEEK_END);
    long fsize = ftell(sfp);
    fseek(sfp, 0, SEEK_SET);

    if (fsize < 0) {
        fclose(sfp);
        return STEGO_ERR_FILE_READ;
    }

    size_t raw_payload_len = (size_t)fsize;
    uint8_t *raw_payload = NULL;
    if (raw_payload_len > 0) {
        raw_payload = (uint8_t *)malloc(raw_payload_len);
        if (!raw_payload) {
            fclose(sfp);
            return STEGO_ERR_MEMORY;
        }
        if (fread(raw_payload, 1, raw_payload_len, sfp) != raw_payload_len) {
            stego_secure_zero(raw_payload, raw_payload_len);
            free(raw_payload);
            fclose(sfp);
            return STEGO_ERR_FILE_READ;
        }
    }
    fclose(sfp);

    /* Open carrier */
    StegoCarrier *carrier = NULL;
    StegoResult res = stego_carrier_open(cover_path, adaptive, &carrier);
    if (res != STEGO_OK) {
        if (raw_payload) {
            stego_secure_zero(raw_payload, raw_payload_len);
            free(raw_payload);
        }
        return res;
    }

    /* Pack file into authenticated FIL1 container */
    uint8_t *fil_payload = NULL;
    size_t fil_payload_len = 0;
    res = stego_file_payload_pack(secret_file_path, raw_payload, raw_payload_len, &fil_payload, &fil_payload_len);
    if (res != STEGO_OK) {
        if (raw_payload) {
            stego_secure_zero(raw_payload, raw_payload_len);
            free(raw_payload);
        }
        stego_carrier_close(carrier);
        return res;
    }
    if (raw_payload) {
        stego_secure_zero(raw_payload, raw_payload_len);
        free(raw_payload);
        raw_payload = NULL;
    }

    /* Optional pre-encryption compression */
    uint8_t *final_payload = fil_payload;
    size_t final_payload_len = fil_payload_len;
    bool was_compressed = false;
    if (compress && fil_payload_len > 0) {
        uint8_t *comp_buf = NULL;
        size_t comp_len = 0;
        stego_compress_payload_if_beneficial(fil_payload, fil_payload_len, &comp_buf, &comp_len, &was_compressed);
        if (was_compressed) {
            stego_secure_zero(fil_payload, fil_payload_len);
            free(fil_payload);
            final_payload = comp_buf;
            final_payload_len = comp_len;
            printf("[*] Lossless compression: %zu -> %zu bytes (%.1f%% reduction)\n",
                   fil_payload_len, final_payload_len,
                   (1.0 - (double)final_payload_len / (double)fil_payload_len) * 100.0);
        } else {
            if (stego_is_already_compressed_format(secret_file_path)) {
                printf("[*] Notice: Payload format appears already compressed (ZIP/JPEG/MP4/etc.). Skipping compression.\n");
            }
        }
    }

    /* Assess capacity before embedding */
    StegoCapacityAssessment assess;
    stego_assess_capacity(carrier, secret_file_path, final_payload_len, passphrase != NULL, was_compressed, bits_per_channel, &assess);
    if (!assess.fits) {
        fprintf(stderr, "%s\n", assess.formatted_details);
        stego_carrier_close(carrier);
        if (final_payload) {
            stego_secure_zero(final_payload, final_payload_len);
            free(final_payload);
        }
        return STEGO_ERR_CAPACITY_EXCEEDED;
    }

    /* Embed payload with secure packaging (CMC1 or CMC2) using requested bit depth */
    res = png_encode_secure_ex(carrier->image, final_payload, final_payload_len, passphrase, adaptive, bits_per_channel);

    /* Zero and free payload plaintext immediately */
    if (final_payload) {
        stego_secure_zero(final_payload, final_payload_len);
        free(final_payload);
        final_payload = NULL;
    }

    if (res != STEGO_OK) {
        stego_carrier_close(carrier);
        return res;
    }

    /* Save modified image in target format */
    res = stego_image_save(stego_path, carrier->image, out_fmt);
    stego_carrier_close(carrier);
    return res;
}

StegoResult stego_hide_file_unified_secure(const char *cover_path, const char *stego_path, const char *secret_file_path, const char *passphrase, bool adaptive) {
    return stego_hide_file_unified_advanced(cover_path, stego_path, secret_file_path, passphrase, adaptive, false, 1);
}

StegoResult stego_extract_file_unified_secure(const char *stego_path, const char *output_path, const char *passphrase, bool adaptive) {
    if (!stego_path) return STEGO_ERR_INVALID_ARG;

    StegoCarrier *carrier = NULL;
    StegoResult res = stego_carrier_open(stego_path, adaptive, &carrier);
    if (res != STEGO_OK) return res;

    uint8_t *payload = NULL;
    size_t payload_len = 0;
    res = carrier->extract_secure(carrier, passphrase, &payload, &payload_len);
    stego_carrier_close(carrier);

    if (res != STEGO_OK) return res;

    /* Optional decompression check */
    uint8_t *decomp_payload = NULL;
    size_t decomp_len = 0;
    bool was_decomp = false;
    stego_decompress_payload_if_packed(payload, payload_len, &decomp_payload, &decomp_len, &was_decomp);

    uint8_t *working_payload = was_decomp ? decomp_payload : payload;
    size_t working_len = was_decomp ? decomp_len : payload_len;

    /* Check for FIL1 authenticated container */
    uint8_t *restored_file = NULL;
    size_t restored_file_len = 0;
    StegoFileMetadata meta;
    memset(&meta, 0, sizeof(meta));
    bool is_fil1 = stego_file_payload_is_fil1(working_payload, working_len);

    if (is_fil1) {
        res = stego_file_payload_unpack(working_payload, working_len, &meta, &restored_file, &restored_file_len);
        if (res != STEGO_OK) {
            fprintf(stderr, "[-] File integrity check failed: SHA-256 hash mismatch or data truncation.\n");
            if (decomp_payload) {
                stego_secure_zero(decomp_payload, decomp_len);
                free(decomp_payload);
            }
            stego_secure_zero(payload, payload_len);
            free(payload);
            return STEGO_ERR_CORRUPT_PAYLOAD;
        }
    } else {
        restored_file = (uint8_t *)malloc(working_len > 0 ? working_len : 1);
        if (restored_file) {
            memcpy(restored_file, working_payload, working_len);
            restored_file_len = working_len;
        }
    }

    if (decomp_payload) {
        stego_secure_zero(decomp_payload, decomp_len);
        free(decomp_payload);
    }
    stego_secure_zero(payload, payload_len);
    free(payload);

    /* Determine actual output destination */
    char resolved_out_path[512] = {0};
    if (output_path && output_path[0] != '\0') {
        size_t olen = strlen(output_path);
        if (output_path[olen - 1] == '/' || output_path[olen - 1] == '\\') {
            snprintf(resolved_out_path, sizeof(resolved_out_path), "%s%s",
                     output_path, is_fil1 ? meta.filename : "recovered_secret.bin");
        } else {
            snprintf(resolved_out_path, sizeof(resolved_out_path), "%s", output_path);
        }
    } else if (is_fil1) {
        snprintf(resolved_out_path, sizeof(resolved_out_path), "%s", meta.filename);
    }

    if (resolved_out_path[0] != '\0') {
        FILE *ofp = fopen(resolved_out_path, "wb");
        if (!ofp) {
            if (restored_file) {
                stego_secure_zero(restored_file, restored_file_len);
                free(restored_file);
            }
            return STEGO_ERR_FILE_WRITE;
        }
        if (restored_file_len > 0 && restored_file) {
            if (fwrite(restored_file, 1, restored_file_len, ofp) != restored_file_len) {
                fclose(ofp);
                stego_secure_zero(restored_file, restored_file_len);
                free(restored_file);
                remove(resolved_out_path);
                return STEGO_ERR_FILE_WRITE;
            }
        }
        fclose(ofp);
        if (is_fil1) {
            printf("[+] Restored original file '%s' -> saved to '%s' (%zu bytes, MIME: %s)\n",
                   meta.filename, resolved_out_path, restored_file_len, meta.mime_type);
            printf("[+] Cryptographic SHA-256 verified: %s\n", meta.sha256_hex);
        } else {
            printf("[+] Payload successfully extracted (%zu bytes) -> saved to '%s'\n",
                   restored_file_len, resolved_out_path);
        }
    } else {
        printf("\n[+] Payload successfully extracted (%zu bytes):\n", restored_file_len);
        printf("----------------------------------------------------\n");
        fwrite(restored_file, 1, restored_file_len, stdout);
        printf("\n----------------------------------------------------\n");
    }

    if (restored_file) {
        stego_secure_zero(restored_file, restored_file_len);
        free(restored_file);
    }
    return STEGO_OK;
}
