/**
 * @file carrier.c
 * @brief Polymorphic carrier factory and lifecycle management.
 */

#include "stego/carrier.h"
#include "stego/bmp_carrier.h"
#include "stego/png_carrier.h"

StegoResult stego_carrier_open(const char *filepath, bool adaptive, StegoCarrier **out_carrier) {
    if (!filepath || !out_carrier) return STEGO_ERR_INVALID_ARG;
    *out_carrier = NULL;

    StegoImage *img = NULL;
    StegoResult res = stego_image_load(filepath, &img);
    if (res != STEGO_OK) return res;

    switch (img->format) {
        case STEGO_FORMAT_BMP:
            return stego_bmp_carrier_create(img, out_carrier);
        case STEGO_FORMAT_PNG:
        case STEGO_FORMAT_JPEG:
        case STEGO_FORMAT_WEBP:
        case STEGO_FORMAT_GIF:
        case STEGO_FORMAT_TGA:
            return stego_png_carrier_create(img, adaptive, out_carrier);
        default:
            stego_image_free(img);
            return STEGO_ERR_UNSUPPORTED_FORMAT;
    }
}

void stego_carrier_close(StegoCarrier *carrier) {
    if (!carrier) return;
    if (carrier->free) {
        carrier->free(carrier);
    }
}

