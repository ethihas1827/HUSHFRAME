/**
 * @file bmp_carrier.c
 * @brief 24-bit uncompressed BMP carrier implementation and polymorphic wrapper.
 */

#include "stego/bmp_carrier.h"
#include "stego/payload.h"
#include "stego/png_carrier.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

StegoResult bmp_load(const char *filename, BMPImage **image) {
    if (!filename || !image) return STEGO_ERR_INVALID_ARG;
    *image = NULL;

    FILE *fp = fopen(filename, "rb");
    if (!fp) return STEGO_ERR_FILE_NOT_FOUND;

    BMPFileHeader file_hdr;
    if (fread(&file_hdr, sizeof(BMPFileHeader), 1, fp) != 1) {
        fclose(fp);
        return STEGO_ERR_INVALID_BMP;
    }

    if (file_hdr.bfType != 0x4D42) {
        fclose(fp);
        return STEGO_ERR_INVALID_BMP;
    }

    BMPInfoHeader info_hdr;
    if (fread(&info_hdr, sizeof(BMPInfoHeader), 1, fp) != 1) {
        fclose(fp);
        return STEGO_ERR_INVALID_BMP;
    }

    if (info_hdr.biSize < sizeof(BMPInfoHeader)) {
        fclose(fp);
        return STEGO_ERR_INVALID_BMP;
    }

    if (info_hdr.biBitCount != 24 || info_hdr.biCompression != 0) {
        fclose(fp);
        return STEGO_ERR_UNSUPPORTED_FORMAT;
    }

    if (info_hdr.biWidth <= 0 || info_hdr.biHeight == 0) {
        fclose(fp);
        return STEGO_ERR_INVALID_BMP;
    }

    uint32_t width = (uint32_t)info_hdr.biWidth;
    bool is_top_down = (info_hdr.biHeight < 0);
    uint32_t height = is_top_down ? (uint32_t)(-info_hdr.biHeight) : (uint32_t)info_hdr.biHeight;

    size_t pixel_bytes_per_row = (size_t)width * 3;
    size_t row_stride = (pixel_bytes_per_row + 3) & ~3;
    size_t row_padding = row_stride - pixel_bytes_per_row;
    size_t data_size = row_stride * height;

    BMPImage *img = (BMPImage *)malloc(sizeof(BMPImage));
    if (!img) {
        fclose(fp);
        return STEGO_ERR_MEMORY;
    }

    img->file_header = file_hdr;
    img->info_header = info_hdr;
    img->width = width;
    img->height = height;
    img->is_top_down = is_top_down;
    img->row_stride = row_stride;
    img->row_padding = row_padding;
    img->data_size = data_size;

    img->raw_data = (uint8_t *)malloc(data_size);
    if (!img->raw_data) {
        free(img);
        fclose(fp);
        return STEGO_ERR_MEMORY;
    }

    if (fseek(fp, (long)file_hdr.bfOffBits, SEEK_SET) != 0) {
        free(img->raw_data);
        free(img);
        fclose(fp);
        return STEGO_ERR_INVALID_BMP;
    }

    size_t read_bytes = fread(img->raw_data, 1, data_size, fp);
    fclose(fp);

    if (read_bytes < data_size) {
        free(img->raw_data);
        free(img);
        return STEGO_ERR_INVALID_BMP;
    }

    *image = img;
    return STEGO_OK;
}

StegoResult bmp_save(const char *filename, const BMPImage *image) {
    if (!filename || !image || !image->raw_data) return STEGO_ERR_INVALID_ARG;

    FILE *fp = fopen(filename, "wb");
    if (!fp) return STEGO_ERR_FILE_WRITE;

    if (fwrite(&image->file_header, sizeof(BMPFileHeader), 1, fp) != 1 ||
        fwrite(&image->info_header, sizeof(BMPInfoHeader), 1, fp) != 1) {
        fclose(fp);
        return STEGO_ERR_FILE_WRITE;
    }

    size_t header_written = sizeof(BMPFileHeader) + sizeof(BMPInfoHeader);
    if (image->file_header.bfOffBits > header_written) {
        size_t pad = image->file_header.bfOffBits - header_written;
        uint8_t zero = 0;
        for (size_t i = 0; i < pad; i++) {
            fwrite(&zero, 1, 1, fp);
        }
    }

    if (fwrite(image->raw_data, 1, image->data_size, fp) != image->data_size) {
        fclose(fp);
        return STEGO_ERR_FILE_WRITE;
    }

    fclose(fp);
    return STEGO_OK;
}

StegoResult bmp_create(uint32_t width, uint32_t height, BMPImage **image) {
    if (!image || width == 0 || height == 0) return STEGO_ERR_INVALID_ARG;
    *image = NULL;

    size_t pixel_bytes_per_row = (size_t)width * 3;
    size_t row_stride = (pixel_bytes_per_row + 3) & ~3;
    size_t row_padding = row_stride - pixel_bytes_per_row;
    size_t data_size = row_stride * height;

    BMPImage *img = (BMPImage *)malloc(sizeof(BMPImage));
    if (!img) return STEGO_ERR_MEMORY;

    img->raw_data = (uint8_t *)calloc(1, data_size);
    if (!img->raw_data) {
        free(img);
        return STEGO_ERR_MEMORY;
    }

    uint32_t off_bits = (uint32_t)(sizeof(BMPFileHeader) + sizeof(BMPInfoHeader));
    uint32_t file_size = off_bits + (uint32_t)data_size;

    img->file_header.bfType = 0x4D42;
    img->file_header.bfSize = file_size;
    img->file_header.bfReserved1 = 0;
    img->file_header.bfReserved2 = 0;
    img->file_header.bfOffBits = off_bits;

    img->info_header.biSize = sizeof(BMPInfoHeader);
    img->info_header.biWidth = (int32_t)width;
    img->info_header.biHeight = (int32_t)height;
    img->info_header.biPlanes = 1;
    img->info_header.biBitCount = 24;
    img->info_header.biCompression = 0;
    img->info_header.biSizeImage = (uint32_t)data_size;
    img->info_header.biXPelsPerMeter = 2835;
    img->info_header.biYPelsPerMeter = 2835;
    img->info_header.biClrUsed = 0;
    img->info_header.biClrImportant = 0;

    img->width = width;
    img->height = height;
    img->is_top_down = false;
    img->row_stride = row_stride;
    img->row_padding = row_padding;
    img->data_size = data_size;

    *image = img;
    return STEGO_OK;
}

void bmp_free(BMPImage *image) {
    if (!image) return;
    if (image->raw_data) {
        free(image->raw_data);
        image->raw_data = NULL;
    }
    free(image);
}

void bmp_print_info(const BMPImage *image) {
    if (!image) return;
    size_t cap = bmp_max_payload_size(image);
    size_t detected_len = 0;
    bool has_cmc1 = bmp_has_payload(image, &detected_len);

    printf("================ BMP Image Information ================\n");
    printf("Dimensions       : %u x %u pixels\n", image->width, image->height);
    printf("Color Depth      : 24-bit RGB (24 bpp)\n");
    printf("Orientation      : %s\n", image->is_top_down ? "Top-down" : "Bottom-up (Standard)");
    printf("Row Stride       : %zu bytes (Padding: %zu bytes/row)\n", image->row_stride, image->row_padding);
    printf("Raw Data Size    : %zu bytes (%.1f KB)\n", image->data_size, (double)image->data_size / 1024.0);
    printf("Stego Capacity   : %zu bytes (%.2f KB) [%zu bits]\n", cap, (double)cap / 1024.0, cap * 8);
    if (has_cmc1) {
        printf("Stego Payload    : DETECTED (%zu bytes embedded)\n", detected_len);
    } else {
        printf("Stego Payload    : None detected\n");
    }
    printf("========================================================\n");
}

/* ========================================================================= */
/* Polymorphic StegoCarrier binding for BMP                                  */
/* ========================================================================= */

static size_t bmp_carrier_max_capacity(const StegoCarrier *self) {
    if (!self || !self->image) return 0;
    return png_max_payload_size(self->image, false);
}

static bool bmp_carrier_has_payload(const StegoCarrier *self, size_t *out_payload_len) {
    if (!self || !self->image) return false;
    return png_has_payload(self->image, false, out_payload_len);
}

static StegoEnvelopeType bmp_carrier_detect_envelope(const StegoCarrier *self, uint32_t *out_payload_len) {
    if (!self || !self->image) return STEGO_ENVELOPE_NONE;
    return png_detect_envelope(self->image, false, out_payload_len);
}

static StegoResult bmp_carrier_embed(StegoCarrier *self, const uint8_t *payload, size_t payload_len) {
    if (!self || !self->image) return STEGO_ERR_INVALID_ARG;
    return png_encode(self->image, payload, payload_len, false);
}

static StegoResult bmp_carrier_extract(const StegoCarrier *self, uint8_t **out_payload, size_t *out_len) {
    if (!self || !self->image) return STEGO_ERR_INVALID_ARG;
    return png_decode(self->image, out_payload, out_len, false);
}

static StegoResult bmp_carrier_embed_secure(StegoCarrier *self, const uint8_t *payload, size_t payload_len, const char *passphrase) {
    if (!self || !self->image) return STEGO_ERR_INVALID_ARG;
    return png_encode_secure(self->image, payload, payload_len, passphrase, false);
}

static StegoResult bmp_carrier_extract_secure(const StegoCarrier *self, const char *passphrase, uint8_t **out_payload, size_t *out_len) {
    if (!self || !self->image) return STEGO_ERR_INVALID_ARG;
    return png_decode_secure(self->image, passphrase, out_payload, out_len, false);
}

static void bmp_carrier_free(StegoCarrier *self) {
    if (!self) return;
    if (self->image) {
        stego_image_free(self->image);
        self->image = NULL;
    }
    free(self);
}

StegoResult stego_bmp_carrier_create(StegoImage *image, StegoCarrier **out_carrier) {
    if (!image || !out_carrier) return STEGO_ERR_INVALID_ARG;
    *out_carrier = NULL;

    StegoCarrier *c = (StegoCarrier *)calloc(1, sizeof(StegoCarrier));
    if (!c) return STEGO_ERR_MEMORY;

    c->image = image;
    c->format = STEGO_FORMAT_BMP;
    c->is_adaptive = false;
    c->max_capacity = bmp_carrier_max_capacity;
    c->has_payload = bmp_carrier_has_payload;
    c->detect_envelope = bmp_carrier_detect_envelope;
    c->embed = bmp_carrier_embed;
    c->extract = bmp_carrier_extract;
    c->embed_secure = bmp_carrier_embed_secure;
    c->extract_secure = bmp_carrier_extract_secure;
    c->free = bmp_carrier_free;

    *out_carrier = c;
    return STEGO_OK;
}
