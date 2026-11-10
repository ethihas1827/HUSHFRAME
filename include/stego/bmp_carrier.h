/**
 * @file bmp_carrier.h
 * @brief 24-bit uncompressed BMP carrier with exact row-padding preservation.
 */

#ifndef STEGO_BMP_CARRIER_H
#define STEGO_BMP_CARRIER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "stego/error.h"
#include "stego/carrier.h"

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 1)

typedef struct {
    uint16_t bfType;          /**< 0x4D42 ("BM") */
    uint32_t bfSize;          /**< File size in bytes */
    uint16_t bfReserved1;     /**< 0 */
    uint16_t bfReserved2;     /**< 0 */
    uint32_t bfOffBits;       /**< Pixel array offset */
} BMPFileHeader;

typedef struct {
    uint32_t biSize;          /**< 40 */
    int32_t  biWidth;
    int32_t  biHeight;
    uint16_t biPlanes;        /**< 1 */
    uint16_t biBitCount;      /**< 24 */
    uint32_t biCompression;   /**< 0 (BI_RGB) */
    uint32_t biSizeImage;
    int32_t  biXPelsPerMeter;
    int32_t  biYPelsPerMeter;
    uint32_t biClrUsed;
    uint32_t biClrImportant;
} BMPInfoHeader;

#pragma pack(pop)

typedef struct {
    BMPFileHeader file_header;
    BMPInfoHeader info_header;
    uint32_t width;
    uint32_t height;
    bool is_top_down;
    size_t row_stride;
    size_t row_padding;
    size_t data_size;
    uint8_t *raw_data;
} BMPImage;

StegoResult bmp_load(const char *filename, BMPImage **image);
StegoResult bmp_save(const char *filename, const BMPImage *image);
StegoResult bmp_create(uint32_t width, uint32_t height, BMPImage **image);
void bmp_free(BMPImage *image);
void bmp_print_info(const BMPImage *image);

size_t bmp_max_payload_size(const BMPImage *image);
bool bmp_has_payload(const BMPImage *image, size_t *out_payload_size);
StegoResult bmp_encode(BMPImage *image, const uint8_t *payload, size_t payload_len);
StegoResult bmp_decode(const BMPImage *image, uint8_t **out_payload, size_t *out_len);

StegoResult stego_bmp_carrier_create(StegoImage *image, StegoCarrier **out_carrier);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_BMP_CARRIER_H */

