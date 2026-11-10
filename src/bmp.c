/**
 * @file bmp.c
 * @brief BMP image processing implementation for 24-bit uncompressed bitmaps.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__has_include)
  #if __has_include("stego.h")
    #include "stego.h"
  #elif __has_include("../include/stego.h")
    #include "../include/stego.h"
  #elif __has_include("include/stego.h")
    #include "include/stego.h"
  #else
    #include "stego.h"
  #endif
#else
  #include "stego.h"
#endif

StegoResult bmp_load(const char *filename, BMPImage **image) {
    if (!filename || !image) {
        return STEGO_ERR_INVALID_ARG;
    }
    *image = NULL;

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        return STEGO_ERR_FILE_NOT_FOUND;
    }

    BMPFileHeader file_hdr;
    if (fread(&file_hdr, sizeof(BMPFileHeader), 1, fp) != 1) {
        fclose(fp);
        return STEGO_ERR_INVALID_BMP;
    }

    /* Check "BM" signature */
    if (file_hdr.bfType != 0x4D42) {
        fclose(fp);
        return STEGO_ERR_INVALID_BMP;
    }

    BMPInfoHeader info_hdr;
    if (fread(&info_hdr, sizeof(BMPInfoHeader), 1, fp) != 1) {
        fclose(fp);
        return STEGO_ERR_INVALID_BMP;
    }

    /* Validate header format */
    if (info_hdr.biSize < sizeof(BMPInfoHeader)) {
        fclose(fp);
        return STEGO_ERR_INVALID_BMP;
    }

    if (info_hdr.biBitCount != 24) {
        fclose(fp);
        return STEGO_ERR_UNSUPPORTED_FORMAT;
    }

    if (info_hdr.biCompression != 0) { /* BI_RGB uncompressed only */
        fclose(fp);
        return STEGO_ERR_UNSUPPORTED_FORMAT;
    }

    if (info_hdr.biWidth <= 0 || info_hdr.biHeight == 0) {
        fclose(fp);
        return STEGO_ERR_INVALID_BMP;
    }

    uint32_t width = (uint32_t)info_hdr.biWidth;
    bool is_top_down = false;
    uint32_t height;

    if (info_hdr.biHeight < 0) {
        is_top_down = true;
        height = (uint32_t)(-info_hdr.biHeight);
    } else {
        height = (uint32_t)info_hdr.biHeight;
    }

    /* Row stride must be aligned to 4 bytes */
    size_t pixel_bytes_per_row = (size_t)width * 3;
    size_t row_stride = (pixel_bytes_per_row + 3) & ~3;
    size_t row_padding = row_stride - pixel_bytes_per_row;
    size_t data_size = row_stride * height;

    /* Allocate BMPImage container */
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

    /* Seek to pixel data offset indicated in file header */
    if (fseek(fp, (long)file_hdr.bfOffBits, SEEK_SET) != 0) {
        free(img->raw_data);
        free(img);
        fclose(fp);
        return STEGO_ERR_INVALID_BMP;
    }

    size_t bytes_read = fread(img->raw_data, 1, data_size, fp);
    fclose(fp);

    if (bytes_read != data_size) {
        free(img->raw_data);
        free(img);
        return STEGO_ERR_INVALID_BMP;
    }

    *image = img;
    return STEGO_OK;
}

StegoResult bmp_save(const char *filename, const BMPImage *image) {
    if (!filename || !image || !image->raw_data) {
        return STEGO_ERR_INVALID_ARG;
    }

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        return STEGO_ERR_FILE_WRITE;
    }

    /* Prepare headers */
    BMPFileHeader file_hdr = image->file_header;
    BMPInfoHeader info_hdr = image->info_header;

    uint32_t header_total = sizeof(BMPFileHeader) + sizeof(BMPInfoHeader);
    file_hdr.bfType = 0x4D42;
    file_hdr.bfReserved1 = 0;
    file_hdr.bfReserved2 = 0;
    file_hdr.bfOffBits = header_total;
    file_hdr.bfSize = header_total + (uint32_t)image->data_size;

    info_hdr.biSize = sizeof(BMPInfoHeader);
    info_hdr.biWidth = (int32_t)image->width;
    info_hdr.biHeight = image->is_top_down ? -(int32_t)image->height : (int32_t)image->height;
    info_hdr.biPlanes = 1;
    info_hdr.biBitCount = 24;
    info_hdr.biCompression = 0;
    info_hdr.biSizeImage = (uint32_t)image->data_size;

    if (fwrite(&file_hdr, sizeof(BMPFileHeader), 1, fp) != 1) {
        fclose(fp);
        return STEGO_ERR_FILE_WRITE;
    }

    if (fwrite(&info_hdr, sizeof(BMPInfoHeader), 1, fp) != 1) {
        fclose(fp);
        return STEGO_ERR_FILE_WRITE;
    }

    if (fwrite(image->raw_data, 1, image->data_size, fp) != image->data_size) {
        fclose(fp);
        return STEGO_ERR_FILE_WRITE;
    }

    fclose(fp);
    return STEGO_OK;
}

StegoResult bmp_create(uint32_t width, uint32_t height, BMPImage **image) {
    if (width == 0 || height == 0 || !image) {
        return STEGO_ERR_INVALID_ARG;
    }
    *image = NULL;

    size_t pixel_bytes_per_row = (size_t)width * 3;
    size_t row_stride = (pixel_bytes_per_row + 3) & ~3;
    size_t row_padding = row_stride - pixel_bytes_per_row;
    size_t data_size = row_stride * height;

    BMPImage *img = (BMPImage *)calloc(1, sizeof(BMPImage));
    if (!img) {
        return STEGO_ERR_MEMORY;
    }

    img->raw_data = (uint8_t *)calloc(1, data_size);
    if (!img->raw_data) {
        free(img);
        return STEGO_ERR_MEMORY;
    }

    img->width = width;
    img->height = height;
    img->is_top_down = false;
    img->row_stride = row_stride;
    img->row_padding = row_padding;
    img->data_size = data_size;

    /* Fill headers */
    uint32_t header_total = sizeof(BMPFileHeader) + sizeof(BMPInfoHeader);
    img->file_header.bfType = 0x4D42;
    img->file_header.bfOffBits = header_total;
    img->file_header.bfSize = header_total + (uint32_t)data_size;

    img->info_header.biSize = sizeof(BMPInfoHeader);
    img->info_header.biWidth = (int32_t)width;
    img->info_header.biHeight = (int32_t)height;
    img->info_header.biPlanes = 1;
    img->info_header.biBitCount = 24;
    img->info_header.biCompression = 0;
    img->info_header.biSizeImage = (uint32_t)data_size;
    img->info_header.biXPelsPerMeter = 2835; /* 72 DPI */
    img->info_header.biYPelsPerMeter = 2835;

    *image = img;
    return STEGO_OK;
}

void bmp_free(BMPImage *image) {
    if (image) {
        if (image->raw_data) {
            free(image->raw_data);
            image->raw_data = NULL;
        }
        free(image);
    }
}

void bmp_print_info(const BMPImage *image) {
    if (!image) {
        printf("BMP Image: (null)\n");
        return;
    }

    size_t total_pixels = (size_t)image->width * image->height;
    size_t max_payload = stego_max_payload_size(image);
    size_t existing_payload = 0;
    bool has_stego = stego_has_payload(image, &existing_payload);

    printf("================ BMP Image Information ================\n");
    printf("Dimensions       : %u x %u pixels\n", image->width, image->height);
    printf("Total Pixels     : %zu\n", total_pixels);
    printf("Color Depth      : 24-bit RGB (%u bpp)\n", image->info_header.biBitCount);
    printf("Orientation      : %s\n", image->is_top_down ? "Top-down" : "Bottom-up (Standard)");
    printf("Row Stride       : %zu bytes (Padding: %zu bytes/row)\n", image->row_stride, image->row_padding);
    printf("Raw Data Size    : %zu bytes (%u KB)\n", image->data_size, (unsigned int)(image->data_size / 1024));
    printf("Stego Capacity   : %zu bytes (%.2f KB) [%zu bits]\n",
           max_payload, (double)max_payload / 1024.0, max_payload * 8);
    printf("Stego Payload    : %s", has_stego ? "DETECTED (" : "None detected\n");
    if (has_stego) {
        printf("%zu bytes embedded)\n", existing_payload);
    }
    printf("========================================================\n");
}

