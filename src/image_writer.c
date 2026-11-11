/**
 * @file image_writer.c
 * @brief Unified image saving abstraction supporting standard BMP and PNG.
 */

#include "stego/image_writer.h"
#include "stego/bmp_carrier.h"
#include "stego/crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Standard Adler-32 Checksum for zlib wrapper */
static uint32_t compute_adler32(const uint8_t *data, size_t len) {
    uint32_t a = 1, b = 0;
    while (len > 0) {
        size_t tlen = len > 5552 ? 5552 : len;
        len -= tlen;
        while (tlen-- > 0) {
            a += *data++;
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    return (b << 16) | a;
}

static void write_png_chunk(FILE *fp, const char type[4], const uint8_t *data, uint32_t len) {
    /* 1. Length (4 bytes, big endian) */
    uint8_t len_bytes[4] = {
        (uint8_t)((len >> 24) & 0xFF),
        (uint8_t)((len >> 16) & 0xFF),
        (uint8_t)((len >> 8) & 0xFF),
        (uint8_t)(len & 0xFF)
    };
    fwrite(len_bytes, 1, 4, fp);

    /* 2. Type (4 bytes) */
    fwrite(type, 1, 4, fp);

    /* 3. Data */
    if (len > 0 && data) {
        fwrite(data, 1, len, fp);
    }

    /* 4. CRC32 over type + data */
    uint32_t crc = stego_crc32(0, (const uint8_t *)type, 4);
    if (len > 0 && data) {
        crc = stego_crc32(crc, data, len);
    }
    uint8_t crc_bytes[4] = {
        (uint8_t)((crc >> 24) & 0xFF),
        (uint8_t)((crc >> 16) & 0xFF),
        (uint8_t)((crc >> 8) & 0xFF),
        (uint8_t)(crc & 0xFF)
    };
    fwrite(crc_bytes, 1, 4, fp);
}

static StegoResult save_image_as_png(const char *filepath, const StegoImage *img) {
    FILE *fp = fopen(filepath, "wb");
    if (!fp) return STEGO_ERR_FILE_WRITE;

    /* 1. 8-byte PNG Signature */
    static const uint8_t png_sig[8] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
    fwrite(png_sig, 1, 8, fp);

    /* 2. IHDR Chunk */
    uint8_t color_type = (img->channels == 4) ? 6 : 2; /* 6 = RGBA, 2 = RGB */
    uint8_t ihdr[13] = {
        (uint8_t)((img->width >> 24) & 0xFF),
        (uint8_t)((img->width >> 16) & 0xFF),
        (uint8_t)((img->width >> 8) & 0xFF),
        (uint8_t)(img->width & 0xFF),
        (uint8_t)((img->height >> 24) & 0xFF),
        (uint8_t)((img->height >> 16) & 0xFF),
        (uint8_t)((img->height >> 8) & 0xFF),
        (uint8_t)(img->height & 0xFF),
        8,           /* Bit depth: 8 bits per channel */
        color_type,  /* Color type */
        0,           /* Compression method: 0 (deflate) */
        0,           /* Filter method: 0 (adaptive) */
        0            /* Interlace method: 0 (none) */
    };
    write_png_chunk(fp, "IHDR", ihdr, 13);

    /* 3. Prepare unfiltered scanlines (filter type 0 = None for each row) */
    size_t line_raw_bytes = (size_t)img->width * img->channels;
    size_t uncompressed_len = (line_raw_bytes + 1) * img->height;
    uint8_t *uncomp = (uint8_t *)malloc(uncompressed_len);
    if (!uncomp) {
        fclose(fp);
        return STEGO_ERR_MEMORY;
    }

    for (uint32_t y = 0; y < img->height; y++) {
        size_t row_dest_offset = (line_raw_bytes + 1) * y;
        uncomp[row_dest_offset] = 0; /* Filter 0: None */
        memcpy(uncomp + row_dest_offset + 1, img->pixels + (y * img->stride), line_raw_bytes);
    }

    uint32_t adler = compute_adler32(uncomp, uncompressed_len);

    /* 4. Pack into standard uncompressed DEFLATE blocks (BTYPE = 00, max 65535 bytes per block) */
    /* Estimate max IDAT size: 2 bytes zlib header + 5 bytes per 65535 block + uncomp_len + 4 bytes adler */
    size_t num_blocks = (uncompressed_len + 65534) / 65535;
    if (num_blocks == 0) num_blocks = 1;
    size_t idat_cap = 2 + (num_blocks * 5) + uncompressed_len + 4;
    uint8_t *idat = (uint8_t *)malloc(idat_cap);
    if (!idat) {
        free(uncomp);
        fclose(fp);
        return STEGO_ERR_MEMORY;
    }

    size_t idat_pos = 0;
    idat[idat_pos++] = 0x78; /* zlib header */
    idat[idat_pos++] = 0x01;

    size_t bytes_left = uncompressed_len;
    size_t src_pos = 0;

    while (bytes_left > 0 || idat_pos == 2) {
        size_t chunk = (bytes_left > 65535) ? 65535 : bytes_left;
        bool is_final = (bytes_left <= 65535);

        idat[idat_pos++] = is_final ? 0x01 : 0x00; /* BFINAL and BTYPE=00 */
        idat[idat_pos++] = (uint8_t)(chunk & 0xFF);
        idat[idat_pos++] = (uint8_t)((chunk >> 8) & 0xFF);
        uint16_t nlen = (uint16_t)(~chunk);
        idat[idat_pos++] = (uint8_t)(nlen & 0xFF);
        idat[idat_pos++] = (uint8_t)((nlen >> 8) & 0xFF);

        if (chunk > 0) {
            memcpy(idat + idat_pos, uncomp + src_pos, chunk);
            idat_pos += chunk;
            src_pos += chunk;
            bytes_left -= chunk;
        }
        if (is_final) break;
    }
    free(uncomp);

    /* Append Adler32 */
    idat[idat_pos++] = (uint8_t)((adler >> 24) & 0xFF);
    idat[idat_pos++] = (uint8_t)((adler >> 16) & 0xFF);
    idat[idat_pos++] = (uint8_t)((adler >> 8) & 0xFF);
    idat[idat_pos++] = (uint8_t)(adler & 0xFF);

    /* Write IDAT Chunk */
    write_png_chunk(fp, "IDAT", idat, (uint32_t)idat_pos);
    free(idat);

    /* 5. Write IEND Chunk */
    write_png_chunk(fp, "IEND", NULL, 0);

    fclose(fp);
    return STEGO_OK;
}

static StegoResult save_image_as_bmp(const char *filepath, const StegoImage *img) {
    BMPImage *bmp = NULL;
    StegoResult res = bmp_create(img->width, img->height, &bmp);
    if (res != STEGO_OK) return res;

    /* Copy top-down RGB pixels to bottom-up BMP raw_data in BGR order */
    for (uint32_t y = 0; y < img->height; y++) {
        uint32_t dst_y = img->height - 1 - y;
        uint8_t *dst_row = bmp->raw_data + (dst_y * bmp->row_stride);
        const uint8_t *src_row = img->pixels + (y * img->stride);

        for (uint32_t x = 0; x < img->width; x++) {
            /* Windows BMP 24-bit requires BGR channel ordering */
            dst_row[x * 3 + 0] = src_row[x * img->channels + 2]; /* Blue */
            dst_row[x * 3 + 1] = src_row[x * img->channels + 1]; /* Green */
            dst_row[x * 3 + 2] = src_row[x * img->channels + 0]; /* Red */
        }
    }

    res = bmp_save(filepath, bmp);
    bmp_free(bmp);
    return res;
}

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#endif

static void ensure_parent_dirs(const char *path) {
    if (!path) return;
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            char sep = *p;
            *p = '\0';
#if defined(_WIN32)
            _mkdir(tmp);
#else
            mkdir(tmp, 0755);
#endif
            *p = sep;
        }
    }
}

StegoResult stego_image_save(const char *filepath, const StegoImage *image, StegoImageFormat target_format) {
    if (!filepath || !image) return STEGO_ERR_INVALID_ARG;
    ensure_parent_dirs(filepath);

    switch (target_format) {
        case STEGO_FORMAT_BMP:
            return save_image_as_bmp(filepath, image);
        case STEGO_FORMAT_PNG:
            return save_image_as_png(filepath, image);
        case STEGO_FORMAT_JPEG:
        case STEGO_FORMAT_HEIC:
            return STEGO_ERR_UNSAFE_CONVERSION;
        default:
            return STEGO_ERR_INVALID_FORMAT;
    }
}

