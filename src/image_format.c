/**
 * @file image_format.c
 * @brief Image format detection by magic bytes and conversion safety validation.
 */

#include "stego/image_format.h"
#include <stdio.h>
#include <string.h>

StegoImageFormat stego_detect_format_buffer(const uint8_t *buffer, size_t size) {
    if (!buffer || size < 2) {
        return STEGO_FORMAT_UNKNOWN;
    }

    /* 1. BMP Magic: 0x42, 0x4D ("BM") */
    if (buffer[0] == 0x42 && buffer[1] == 0x4D) {
        return STEGO_FORMAT_BMP;
    }

    /* 2. PNG Magic: 8-byte signature 89 50 4E 47 0D 0A 1A 0A */
    if (size >= 8) {
        static const uint8_t png_sig[8] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
        if (memcmp(buffer, png_sig, 8) == 0) {
            return STEGO_FORMAT_PNG;
        }
    }

    /* 3. JPEG Magic: FF D8 FF */
    if (size >= 3) {
        if (buffer[0] == 0xFF && buffer[1] == 0xD8 && buffer[2] == 0xFF) {
            return STEGO_FORMAT_JPEG;
        }
    }

    /* 4. WebP Magic: "RIFF" .... "WEBP" */
    if (size >= 12) {
        if (memcmp(buffer, "RIFF", 4) == 0 && memcmp(buffer + 8, "WEBP", 4) == 0) {
            return STEGO_FORMAT_WEBP;
        }
    }

    /* 5. GIF Magic: "GIF87a" or "GIF89a" */
    if (size >= 6) {
        if (memcmp(buffer, "GIF87a", 6) == 0 || memcmp(buffer, "GIF89a", 6) == 0) {
            return STEGO_FORMAT_GIF;
        }
    }

    /* 6. HEIC / HEIF Magic: ISOBMFF box with ftyp at offset 4 */
    if (size >= 12) {
        if (memcmp(buffer + 4, "ftyp", 4) == 0) {
            const uint8_t *brand = buffer + 8;
            if (memcmp(brand, "heic", 4) == 0 ||
                memcmp(brand, "heix", 4) == 0 ||
                memcmp(brand, "heim", 4) == 0 ||
                memcmp(brand, "heis", 4) == 0 ||
                memcmp(brand, "mif1", 4) == 0 ||
                memcmp(brand, "msf1", 4) == 0) {
                return STEGO_FORMAT_HEIC;
            }
        }
    }

    /* 7. TGA Check: Check typical uncompressed/RLE truecolor/grayscale header */
    if (size >= 18) {
        uint8_t colormap_type = buffer[1];
        uint8_t image_type = buffer[2];
        uint8_t bpp = buffer[16];
        uint16_t w = (uint16_t)(buffer[12] | (buffer[13] << 8));
        uint16_t h = (uint16_t)(buffer[14] | (buffer[15] << 8));

        if (colormap_type <= 1 && w > 0 && h > 0 &&
            (image_type == 1 || image_type == 2 || image_type == 3 ||
             image_type == 9 || image_type == 10 || image_type == 11) &&
            (bpp == 8 || bpp == 15 || bpp == 16 || bpp == 24 || bpp == 32)) {
            return STEGO_FORMAT_TGA;
        }
    }

    return STEGO_FORMAT_UNKNOWN;
}

StegoImageFormat stego_detect_format(const char *filepath) {
    if (!filepath) return STEGO_FORMAT_UNKNOWN;

    FILE *fp = fopen(filepath, "rb");
    if (!fp) return STEGO_FORMAT_UNKNOWN;

    /* Check file footer for TGA 2.0 signature "TRUEVISION-XFILE.\0" */
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    if (fsize >= 26) {
        fseek(fp, fsize - 26, SEEK_SET);
        char footer[26];
        if (fread(footer, 1, 26, fp) == 26) {
            if (memcmp(footer + 8, "TRUEVISION-XFILE", 16) == 0) {
                fclose(fp);
                return STEGO_FORMAT_TGA;
            }
        }
    }

    fseek(fp, 0, SEEK_SET);
    uint8_t header[32];
    size_t read_bytes = fread(header, 1, sizeof(header), fp);
    fclose(fp);

    if (read_bytes < 2) return STEGO_FORMAT_UNKNOWN;

    StegoImageFormat detected = stego_detect_format_buffer(header, read_bytes);
    if (detected == STEGO_FORMAT_UNKNOWN) {
        /* Check extension fallback for TGA if header structure is valid */
        const char *dot = strrchr(filepath, '.');
        if (dot && (_stricmp(dot, ".tga") == 0 || _stricmp(dot, ".icb") == 0 || _stricmp(dot, ".vda") == 0)) {
            if (read_bytes >= 18) {
                uint8_t colormap_type = header[1];
                uint8_t image_type = header[2];
                if (colormap_type <= 1 &&
                    (image_type == 1 || image_type == 2 || image_type == 3 ||
                     image_type == 9 || image_type == 10 || image_type == 11)) {
                    return STEGO_FORMAT_TGA;
                }
            }
        }
    }
    return detected;
}

const char *stego_format_name(StegoImageFormat format) {
    switch (format) {
        case STEGO_FORMAT_BMP:  return "BMP";
        case STEGO_FORMAT_PNG:  return "PNG";
        case STEGO_FORMAT_JPEG: return "JPEG";
        case STEGO_FORMAT_WEBP: return "WebP";
        case STEGO_FORMAT_GIF:  return "GIF";
        case STEGO_FORMAT_TGA:  return "TGA";
        case STEGO_FORMAT_HEIC: return "HEIC";
        default:                return "Unknown";
    }
}

bool stego_format_is_lossless(StegoImageFormat format) {
    return (format == STEGO_FORMAT_BMP || format == STEGO_FORMAT_PNG || format == STEGO_FORMAT_TGA);
}

bool stego_is_safe_carrier_format(StegoImageFormat input_fmt, StegoImageFormat output_fmt) {
    (void)input_fmt;
    /* Output format MUST be a lossless carrier (PNG or BMP).
     * Saving to lossy or animation formats (JPEG, WEBP, GIF) is strictly prohibited
     * because lossy compression destroys spatial LSB payload bits. */
    if (output_fmt == STEGO_FORMAT_JPEG ||
        output_fmt == STEGO_FORMAT_WEBP ||
        output_fmt == STEGO_FORMAT_GIF) {
        return false;
    }
    return (output_fmt == STEGO_FORMAT_PNG || output_fmt == STEGO_FORMAT_BMP);
}

