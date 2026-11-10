/**
 * @file image_loader.c
 * @brief Unified image loading abstraction with broad format support (PNG, BMP, JPEG, WEBP, GIF, TGA).
 *
 * Normalizes all supported formats into internal 8-bit RGB or RGBA pixel buffers,
 * preserves alpha transparency channels, and provides detailed original image diagnostics.
 */

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wtype-limits"
#endif

#define STB_IMAGE_IMPLEMENTATION
#define STBI_NO_HDR
#define STBI_NO_LINEAR
#include "stb_image.h"

#define SIMPLEWEBP_IMPLEMENTATION
#include "simplewebp.h"

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#include "stego/image_loader.h"
#include "stego/crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

StegoResult stego_image_create(uint32_t width, uint32_t height, uint32_t channels, StegoImageFormat format, StegoImage **out_image) {
    if (width == 0 || height == 0 || (channels != 3 && channels != 4) || !out_image) {
        return STEGO_ERR_INVALID_ARG;
    }
    if (width > STEGO_MAX_IMAGE_DIMENSION || height > STEGO_MAX_IMAGE_DIMENSION) {
        return STEGO_ERR_IMAGE_TOO_LARGE;
    }

    uint64_t total_bytes = (uint64_t)width * height * channels;
    if (total_bytes > STEGO_MAX_IMAGE_PIXEL_BYTES) {
        return STEGO_ERR_IMAGE_TOO_LARGE;
    }

    *out_image = NULL;
    size_t stride = (size_t)width * channels;
    size_t data_size = stride * height;

    StegoImage *img = (StegoImage *)calloc(1, sizeof(StegoImage));
    if (!img) return STEGO_ERR_MEMORY;

    img->pixels = (uint8_t *)calloc(1, data_size);
    if (!img->pixels) {
        free(img);
        return STEGO_ERR_MEMORY;
    }

    img->width = width;
    img->height = height;
    img->channels = channels;
    img->stride = stride;
    img->data_size = data_size;
    img->format = format;
    img->orig_channels = (int)channels;
    img->orig_bit_depth = 8;
    snprintf(img->orig_color_mode, sizeof(img->orig_color_mode), "%s", channels == 4 ? "RGBA" : "RGB");
    img->was_converted = false;
    img->target_fmt = (format == STEGO_FORMAT_BMP) ? STEGO_FORMAT_BMP : STEGO_FORMAT_PNG;

    *out_image = img;
    return STEGO_OK;
}

void stego_image_free(StegoImage *image) {
    if (!image) return;
    if (image->pixels) {
        stego_secure_zero(image->pixels, image->data_size);
        free(image->pixels);
        image->pixels = NULL;
    }
    free(image);
}

/* Helper to inspect PNG IHDR and auxiliary chunks for detailed metadata diagnostics */
static void inspect_png_properties(const char *filepath, int *out_bit_depth, int *out_color_type, bool *out_has_trns) {
    *out_bit_depth = 8;
    *out_color_type = 2;
    *out_has_trns = false;

    FILE *fp = fopen(filepath, "rb");
    if (!fp) return;

    uint8_t header[33];
    if (fread(header, 1, 33, fp) == 33) {
        if (memcmp(header + 12, "IHDR", 4) == 0) {
            *out_bit_depth = (int)header[24];
            *out_color_type = (int)header[25];
        }
    }

    /* Scan for tRNS chunk */
    fseek(fp, 8, SEEK_SET);
    uint8_t chunk_hdr[8];
    while (fread(chunk_hdr, 1, 8, fp) == 8) {
        uint32_t len = ((uint32_t)chunk_hdr[0] << 24) | ((uint32_t)chunk_hdr[1] << 16) |
                       ((uint32_t)chunk_hdr[2] << 8)  | (uint32_t)chunk_hdr[3];
        if (memcmp(chunk_hdr + 4, "tRNS", 4) == 0) {
            *out_has_trns = true;
            break;
        }
        if (memcmp(chunk_hdr + 4, "IEND", 4) == 0) {
            break;
        }
        if (fseek(fp, (long)(len + 4), SEEK_CUR) != 0) {
            break;
        }
    }

    fclose(fp);
}

/* Helper to decode WebP inputs via simplewebp */
static StegoResult load_webp_as_stego_image(const char *filepath, StegoImage **out_image) {
    simplewebp *webp = NULL;
    simplewebp_error err = simplewebp_load_from_filename(filepath, NULL, &webp);
    if (err != SIMPLEWEBP_NO_ERROR) {
        fprintf(stderr, "[debug] simplewebp_load_from_filename error: %d\n", err);
        return (err == SIMPLEWEBP_ALLOC_ERROR) ? STEGO_ERR_MEMORY : STEGO_ERR_IMAGE_DECODE;
    }

    size_t w = 0, h = 0;
    simplewebp_get_dimensions(webp, &w, &h);
    if (w == 0 || h == 0) {
        simplewebp_unload(webp);
        return STEGO_ERR_IMAGE_INVALID_DATA;
    }

    if (w > STEGO_MAX_IMAGE_DIMENSION || h > STEGO_MAX_IMAGE_DIMENSION ||
        ((uint64_t)w * h * 4) > STEGO_MAX_IMAGE_PIXEL_BYTES) {
        simplewebp_unload(webp);
        return STEGO_ERR_IMAGE_TOO_LARGE;
    }

    size_t rgba_size = w * h * 4;
    uint8_t *rgba_buf = (uint8_t *)malloc(rgba_size);
    if (!rgba_buf) {
        simplewebp_unload(webp);
        return STEGO_ERR_MEMORY;
    }

    err = simplewebp_decode(webp, rgba_buf, NULL);
    simplewebp_bool is_lossless = simplewebp_is_lossless(webp);
    simplewebp_unload(webp);

    if (err != SIMPLEWEBP_NO_ERROR) {
        free(rgba_buf);
        return STEGO_ERR_IMAGE_DECODE;
    }

    /* Check if any pixel actually uses transparency */
    bool has_transparency = false;
    for (size_t i = 0; i < w * h; i++) {
        if (rgba_buf[i * 4 + 3] < 255) {
            has_transparency = true;
            break;
        }
    }

    StegoImage *img = (StegoImage *)calloc(1, sizeof(StegoImage));
    if (!img) {
        free(rgba_buf);
        return STEGO_ERR_MEMORY;
    }

    img->width = (uint32_t)w;
    img->height = (uint32_t)h;
    img->format = STEGO_FORMAT_WEBP;
    img->orig_channels = has_transparency ? 4 : 3;
    img->orig_bit_depth = 8;
    snprintf(img->orig_color_mode, sizeof(img->orig_color_mode), "WebP (%s)", is_lossless ? "Lossless" : "Lossy");
    img->was_converted = true;
    img->target_fmt = STEGO_FORMAT_PNG;

    if (has_transparency) {
        img->channels = 4;
        img->stride = w * 4;
        img->data_size = rgba_size;
        img->pixels = rgba_buf;
    } else {
        /* Pack to 3 channels (RGB) to save memory and optimize capacity */
        size_t rgb_size = w * h * 3;
        uint8_t *rgb_buf = (uint8_t *)malloc(rgb_size);
        if (!rgb_buf) {
            free(rgba_buf);
            free(img);
            return STEGO_ERR_MEMORY;
        }
        for (size_t i = 0; i < w * h; i++) {
            rgb_buf[i * 3 + 0] = rgba_buf[i * 4 + 0];
            rgb_buf[i * 3 + 1] = rgba_buf[i * 4 + 1];
            rgb_buf[i * 3 + 2] = rgba_buf[i * 4 + 2];
        }
        free(rgba_buf);
        img->channels = 3;
        img->stride = w * 3;
        img->data_size = rgb_size;
        img->pixels = rgb_buf;
    }

    *out_image = img;
    return STEGO_OK;
}

StegoResult stego_image_load(const char *filepath, StegoImage **out_image) {
    if (!filepath || !out_image) return STEGO_ERR_INVALID_ARG;
    *out_image = NULL;

    FILE *fp = fopen(filepath, "rb");
    if (!fp) return STEGO_ERR_FILE_NOT_FOUND;

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0) {
        fclose(fp);
        return STEGO_ERR_IMAGE_INVALID_DATA;
    }

    StegoImageFormat fmt = stego_detect_format(filepath);
    if (fmt == STEGO_FORMAT_UNKNOWN) {
        fclose(fp);
        return STEGO_ERR_UNSUPPORTED_FORMAT;
    }
    if (fmt == STEGO_FORMAT_HEIC) {
        fclose(fp);
        return STEGO_ERR_UNSUPPORTED_FORMAT;
    }

    /* WebP uses dedicated simplewebp decoder */
    if (fmt == STEGO_FORMAT_WEBP) {
        fclose(fp);
        return load_webp_as_stego_image(filepath, out_image);
    }

    /* Check dimension limits with stbi_info */
    int w = 0, h = 0, comp = 0;
    if (!stbi_info_from_file(fp, &w, &h, &comp)) {
        fclose(fp);
        return STEGO_ERR_IMAGE_DECODE;
    }
    fseek(fp, 0, SEEK_SET);

    if (w <= 0 || h <= 0) {
        fclose(fp);
        return STEGO_ERR_IMAGE_INVALID_DATA;
    }

    if ((uint32_t)w > STEGO_MAX_IMAGE_DIMENSION || (uint32_t)h > STEGO_MAX_IMAGE_DIMENSION ||
        ((uint64_t)w * h * 4) > STEGO_MAX_IMAGE_PIXEL_BYTES) {
        fclose(fp);
        return STEGO_ERR_IMAGE_TOO_LARGE;
    }

    /* Determine original image metadata and transparency requirement */
    int orig_bit_depth = 8;
    char orig_color_mode[32] = {0};
    bool has_alpha = false;
    bool was_converted = false;
    StegoImageFormat target_fmt = STEGO_FORMAT_PNG;

    if (fmt == STEGO_FORMAT_PNG) {
        int png_bd = 8, png_ct = 2;
        bool has_trns = false;
        inspect_png_properties(filepath, &png_bd, &png_ct, &has_trns);

        orig_bit_depth = png_bd;
        switch (png_ct) {
            case 0:
                snprintf(orig_color_mode, sizeof(orig_color_mode), "Grayscale");
                has_alpha = has_trns;
                was_converted = true;
                break;
            case 2:
                snprintf(orig_color_mode, sizeof(orig_color_mode), "RGB");
                has_alpha = has_trns;
                was_converted = (png_bd != 8);
                break;
            case 3:
                snprintf(orig_color_mode, sizeof(orig_color_mode), "Indexed/Palette");
                has_alpha = has_trns;
                was_converted = true;
                break;
            case 4:
                snprintf(orig_color_mode, sizeof(orig_color_mode), "Grayscale + Alpha");
                has_alpha = true;
                was_converted = true;
                break;
            case 6:
                snprintf(orig_color_mode, sizeof(orig_color_mode), "RGBA");
                has_alpha = true;
                was_converted = (png_bd != 8);
                break;
            default:
                snprintf(orig_color_mode, sizeof(orig_color_mode), "PNG (Custom)");
                has_alpha = (comp == 4);
                was_converted = true;
                break;
        }
        target_fmt = STEGO_FORMAT_PNG;
    } else if (fmt == STEGO_FORMAT_BMP) {
        snprintf(orig_color_mode, sizeof(orig_color_mode), "%s", (comp == 4) ? "RGBA" : "RGB");
        has_alpha = (comp == 4);
        target_fmt = STEGO_FORMAT_BMP;
    } else if (fmt == STEGO_FORMAT_JPEG) {
        snprintf(orig_color_mode, sizeof(orig_color_mode), "Lossy YCbCr");
        has_alpha = false;
        was_converted = true;
        target_fmt = STEGO_FORMAT_PNG;
    } else if (fmt == STEGO_FORMAT_GIF) {
        snprintf(orig_color_mode, sizeof(orig_color_mode), "GIF (Indexed Frame)");
        has_alpha = (comp == 4 || comp == 2);
        was_converted = true;
        target_fmt = STEGO_FORMAT_PNG;
    } else if (fmt == STEGO_FORMAT_TGA) {
        snprintf(orig_color_mode, sizeof(orig_color_mode), "%s", (comp == 4) ? "TGA (RGBA)" : "TGA (RGB)");
        has_alpha = (comp == 4);
        was_converted = true;
        target_fmt = STEGO_FORMAT_PNG;
    }

    /* Load normalized 8-bit RGB (3 channels) or RGBA (4 channels) */
    int req_comp = has_alpha ? 4 : 3;
    stbi_uc *raw_pixels = stbi_load_from_file(fp, &w, &h, &comp, req_comp);
    fclose(fp);

    if (!raw_pixels) {
        return STEGO_ERR_IMAGE_DECODE;
    }

    size_t stride = (size_t)w * req_comp;
    size_t data_size = stride * h;

    StegoImage *img = (StegoImage *)calloc(1, sizeof(StegoImage));
    if (!img) {
        stbi_image_free(raw_pixels);
        return STEGO_ERR_MEMORY;
    }

    img->pixels = (uint8_t *)malloc(data_size);
    if (!img->pixels) {
        stbi_image_free(raw_pixels);
        free(img);
        return STEGO_ERR_MEMORY;
    }
    memcpy(img->pixels, raw_pixels, data_size);
    stbi_image_free(raw_pixels);

    img->width = (uint32_t)w;
    img->height = (uint32_t)h;
    img->channels = (uint32_t)req_comp;
    img->stride = stride;
    img->data_size = data_size;
    img->format = fmt;
    img->orig_channels = comp;
    img->orig_bit_depth = orig_bit_depth;
    snprintf(img->orig_color_mode, sizeof(img->orig_color_mode), "%s", orig_color_mode);
    img->was_converted = was_converted;
    img->target_fmt = target_fmt;

    *out_image = img;
    return STEGO_OK;
}
