/**
 * @file gen_sample.c
 * @brief Generates a sample 24-bit uncompressed BMP image (400x300 gradient).
 */

#include "stego.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    const char *out_path = (argc > 1) ? argv[1] : "cover.bmp";
    uint32_t width = 400;
    uint32_t height = 300;

    BMPImage *img = NULL;
    StegoResult res = bmp_create(width, height, &img);
    if (res != STEGO_OK || !img) {
        fprintf(stderr, "Failed to create BMP image\n");
        return 1;
    }

    /* Fill with a smooth colorful gradient (cyan-magenta-gold) */
    for (uint32_t y = 0; y < height; y++) {
        uint8_t *row = img->raw_data + (y * img->row_stride);
        for (uint32_t x = 0; x < width; x++) {
            uint8_t b = (uint8_t)((x * 255) / width);
            uint8_t g = (uint8_t)((y * 255) / height);
            uint8_t r = (uint8_t)(((x + y) * 255) / (width + height));

            row[x * 3 + 0] = b;
            row[x * 3 + 1] = g;
            row[x * 3 + 2] = r;
        }
    }

    res = bmp_save(out_path, img);
    bmp_free(img);

    if (res != STEGO_OK) {
        fprintf(stderr, "Failed to save sample image to %s\n", out_path);
        return 1;
    }

    printf("[+] Successfully generated 24-bit BMP image (%ux%u) at: %s\n", width, height, out_path);
    return 0;
}
