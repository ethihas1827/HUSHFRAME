/**
 * @file stego.h
 * @brief Phase 1 24-bit BMP LSB Steganography Tool with 8-byte CMC1 Header.
 *
 * Implements safe reading/writing of uncompressed 24-bit BMP files, accurate
 * capacity calculation, an 8-byte CMC1 header, LSB embedding/extraction, and
 * round-trip steganographic operations in standard C.
 */

#ifndef STEGO_H
#define STEGO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "stego/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* 8-Byte CMC1 Steganography Header Specification                            */
/* ========================================================================= */

#define STEGO_MAGIC_BYTE0 'C' /* 0x43 */
#define STEGO_MAGIC_BYTE1 'M' /* 0x4D */
#define STEGO_MAGIC_BYTE2 'C' /* 0x43 */
#define STEGO_MAGIC_BYTE3 '1' /* 0x31 */

/**
 * 8-byte CMC1 Header Layout:
 * - Bytes 0..3: Magic signature "CMC1" (ASCII 0x43, 0x4D, 0x43, 0x31)
 * - Bytes 4..7: 32-bit unsigned payload length (Big-Endian uint32_t)
 * Total size = 8 bytes (64 bits).
 */
#define STEGO_HEADER_SIZE 8

/* ========================================================================= */
/* BMP Header Structures (Packed 1-byte alignment)                           */
/* ========================================================================= */

#pragma pack(push, 1)

/**
 * @brief Standard 14-byte BITMAPFILEHEADER
 */
typedef struct {
    uint16_t bfType;          /**< 0x4D42 ("BM") */
    uint32_t bfSize;          /**< File size in bytes */
    uint16_t bfReserved1;     /**< 0 */
    uint16_t bfReserved2;     /**< 0 */
    uint32_t bfOffBits;       /**< Pixel array offset (typically 54) */
} BMPFileHeader;

/**
 * @brief Standard 40-byte BITMAPINFOHEADER
 */
typedef struct {
    uint32_t biSize;          /**< Header size (40) */
    int32_t  biWidth;         /**< Image width in pixels */
    int32_t  biHeight;        /**< Image height in pixels (>0 bottom-up, <0 top-down) */
    uint16_t biPlanes;        /**< Must be 1 */
    uint16_t biBitCount;      /**< Must be 24 for 24-bit RGB */
    uint32_t biCompression;   /**< Must be 0 for BI_RGB uncompressed */
    uint32_t biSizeImage;     /**< Image data size (can be 0 for BI_RGB) */
    int32_t  biXPelsPerMeter; /**< Horizontal resolution */
    int32_t  biYPelsPerMeter; /**< Vertical resolution */
    uint32_t biClrUsed;       /**< Colors used */
    uint32_t biClrImportant;  /**< Important colors */
} BMPInfoHeader;

#pragma pack(pop)

/**
 * @brief In-memory container for 24-bit BMP image
 */
typedef struct {
    BMPFileHeader file_header;
    BMPInfoHeader info_header;
    uint32_t width;           /**< Width in pixels */
    uint32_t height;          /**< Height in pixels (|biHeight|) */
    bool is_top_down;         /**< True if biHeight < 0 */
    size_t row_stride;        /**< Bytes per row including 4-byte padding */
    size_t row_padding;       /**< Padding bytes per scanline (0..3) */
    size_t data_size;         /**< Total size of raw_data buffer */
    uint8_t *raw_data;        /**< Raw scanline buffer */
} BMPImage;

/* ========================================================================= */
/* BMP File Operations                                                      */
/* ========================================================================= */

/**
 * @brief Safely load an uncompressed 24-bit BMP image from disk.
 */
StegoResult bmp_load(const char *filename, BMPImage **image);

/**
 * @brief Safely write a 24-bit BMP image to disk.
 */
StegoResult bmp_save(const char *filename, const BMPImage *image);

/**
 * @brief Create a blank 24-bit BMP image with given dimensions.
 */
StegoResult bmp_create(uint32_t width, uint32_t height, BMPImage **image);

/**
 * @brief Free a BMPImage and its associated pixel buffer.
 */
void bmp_free(BMPImage *image);

/**
 * @brief Display technical metadata, dimensions, and capacity of a BMP image.
 */
void bmp_print_info(const BMPImage *image);

/* ========================================================================= */
/* Steganography Engine API                                                  */
/* ========================================================================= */

/**
 * @brief Calculate the maximum secret payload capacity in bytes for an image.
 *
 * Formula: ((width * height * 3) / 8) - 8
 * Returns 0 if image is too small to fit the 8-byte CMC1 header.
 */
size_t stego_max_payload_size(const BMPImage *image);

/**
 * @brief Check if an image contains a valid 8-byte CMC1 header.
 *
 * @param image BMP image to check
 * @param out_payload_size Optional pointer to receive embedded payload size
 * @return true if valid CMC1 magic signature is present, false otherwise
 */
bool stego_has_payload(const BMPImage *image, size_t *out_payload_size);

/**
 * @brief Embed a payload into a BMP image using 1-bit LSB with an 8-byte CMC1 header.
 *
 * @param image Target BMP image (modified in-place)
 * @param payload Raw payload data bytes
 * @param payload_len Payload length in bytes
 * @return STEGO_OK on success, or appropriate error code
 */
StegoResult stego_encode(BMPImage *image, const uint8_t *payload, size_t payload_len);

/**
 * @brief Extract hidden payload from a BMP image containing an 8-byte CMC1 header.
 *
 * Caller must free *out_payload when finished.
 *
 * @param image BMP image containing hidden data
 * @param out_payload Pointer to receive allocated output buffer
 * @param out_len Pointer to receive extracted payload length
 * @return STEGO_OK on success, or appropriate error code
 */
StegoResult stego_decode(const BMPImage *image, uint8_t **out_payload, size_t *out_len);

/**
 * @brief Hide a secret file into a cover BMP and write output to stego BMP.
 */
StegoResult stego_hide_file(const char *cover_path, const char *stego_path, const char *secret_file_path);

/**
 * @brief Extract hidden file from stego BMP and write to destination file.
 */
StegoResult stego_extract_file(const char *stego_path, const char *output_path);

/**
 * @brief Convert StegoResult enum value to human-readable error description.
 */
const char *stego_strerror(StegoResult result);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_H */
