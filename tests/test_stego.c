/**
 * @file test_stego.c
 * @brief Automated test suite for Phase 1 24-bit BMP steganography (8-byte CMC1 header).
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

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

#define TEST_PASS "\033[32m[PASS]\033[0m"
#define TEST_FAIL "\033[31m[FAIL]\033[0m"

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define RUN_TEST(fn) do { \
    g_tests_run++; \
    printf("Running %-45s ... ", #fn); \
    fflush(stdout); \
    if (fn()) { \
        printf("%s\n", TEST_PASS); \
        g_tests_passed++; \
    } else { \
        printf("%s\n", TEST_FAIL); \
    } \
} while (0)

static void fill_gradient(BMPImage *img) {
    for (uint32_t y = 0; y < img->height; y++) {
        uint8_t *row = img->raw_data + (y * img->row_stride);
        for (uint32_t x = 0; x < img->width; x++) {
            row[x * 3 + 0] = (uint8_t)((x * 255) / img->width);
            row[x * 3 + 1] = (uint8_t)((y * 255) / img->height);
            row[x * 3 + 2] = (uint8_t)(((x + y) * 128) / (img->width + img->height));
        }
    }
}

/* Test 1: BMP file creation, save, and reload */
static bool test_bmp_create_save_load(void) {
    BMPImage *img = NULL;
    StegoResult res = bmp_create(64, 48, &img);
    if (res != STEGO_OK || !img) return false;

    fill_gradient(img);

    const char *tmp_path = "tmp_test_bmp.bmp";
    res = bmp_save(tmp_path, img);
    bmp_free(img);
    if (res != STEGO_OK) return false;

    BMPImage *loaded = NULL;
    res = bmp_load(tmp_path, &loaded);
    if (res != STEGO_OK || !loaded) {
        remove(tmp_path);
        return false;
    }

    bool match = (loaded->width == 64 && loaded->height == 48 &&
                  loaded->info_header.biBitCount == 24);
    bmp_free(loaded);
    remove(tmp_path);
    return match;
}

/* Test 2: Stego capacity calculation with 8-byte CMC1 header */
static bool test_capacity_calculation(void) {
    BMPImage *img = NULL;

    /* 4x2 image = 8 pixels = 24 bytes color data < 64 bits (8 bytes CMC1 header) -> capacity 0 */
    bmp_create(4, 2, &img);
    if (stego_max_payload_size(img) != 0) {
        bmp_free(img);
        return false;
    }
    bmp_free(img);

    /* 100x100 image = 10,000 pixels = 30,000 color bytes.
     * 30,000 / 8 = 3,750 bytes available.
     * Subtract 8-byte CMC1 header -> 3,742 bytes payload capacity.
     */
    bmp_create(100, 100, &img);
    size_t cap = stego_max_payload_size(img);
    bmp_free(img);
    return (cap == 3742);
}

/* Test 3: Round-trip text embedding and extraction */
static bool test_encode_decode_text(void) {
    BMPImage *img = NULL;
    bmp_create(64, 64, &img);
    fill_gradient(img);

    const char *secret = "Phase 1: BMP LSB Steganography with 8-byte CMC1 header!";
    size_t secret_len = strlen(secret);

    StegoResult res = stego_encode(img, (const uint8_t *)secret, secret_len);
    if (res != STEGO_OK) {
        bmp_free(img);
        return false;
    }

    uint8_t *decoded = NULL;
    size_t decoded_len = 0;
    res = stego_decode(img, &decoded, &decoded_len);
    bmp_free(img);

    if (res != STEGO_OK || !decoded) return false;

    bool match = (decoded_len == secret_len) && (memcmp(decoded, secret, secret_len) == 0);
    free(decoded);
    return match;
}

/* Test 4: Binary payload with all byte values (0x00 to 0xFF) */
static bool test_encode_decode_binary_data(void) {
    BMPImage *img = NULL;
    bmp_create(80, 80, &img);
    fill_gradient(img);

    uint8_t binary_payload[256];
    for (int i = 0; i < 256; i++) {
        binary_payload[i] = (uint8_t)i;
    }

    StegoResult res = stego_encode(img, binary_payload, sizeof(binary_payload));
    if (res != STEGO_OK) {
        bmp_free(img);
        return false;
    }

    uint8_t *decoded = NULL;
    size_t decoded_len = 0;
    res = stego_decode(img, &decoded, &decoded_len);
    bmp_free(img);

    if (res != STEGO_OK || !decoded) return false;

    bool match = (decoded_len == sizeof(binary_payload)) &&
                 (memcmp(decoded, binary_payload, sizeof(binary_payload)) == 0);
    free(decoded);
    return match;
}

/* Test 5: Empty payload (0 bytes) edge case */
static bool test_encode_decode_empty_payload(void) {
    BMPImage *img = NULL;
    bmp_create(50, 50, &img);

    StegoResult res = stego_encode(img, NULL, 0);
    if (res != STEGO_OK) {
        bmp_free(img);
        return false;
    }

    uint8_t *decoded = NULL;
    size_t decoded_len = 999;
    res = stego_decode(img, &decoded, &decoded_len);
    bmp_free(img);

    bool ok = (res == STEGO_OK && decoded_len == 0 && decoded != NULL);
    free(decoded);
    return ok;
}

/* Test 6: Fill image to maximum capacity */
static bool test_max_capacity_payload(void) {
    BMPImage *img = NULL;
    bmp_create(30, 30, &img); /* 900 px * 3 = 2700 bytes -> 337 - 8 = 329 bytes */
    size_t cap = stego_max_payload_size(img);

    uint8_t *buffer = (uint8_t *)malloc(cap);
    for (size_t i = 0; i < cap; i++) {
        buffer[i] = (uint8_t)(i * 31 + 7);
    }

    StegoResult res = stego_encode(img, buffer, cap);
    if (res != STEGO_OK) {
        free(buffer);
        bmp_free(img);
        return false;
    }

    uint8_t *decoded = NULL;
    size_t decoded_len = 0;
    res = stego_decode(img, &decoded, &decoded_len);

    bool match = (res == STEGO_OK && decoded_len == cap && memcmp(decoded, buffer, cap) == 0);
    free(buffer);
    free(decoded);
    bmp_free(img);
    return match;
}

/* Test 7: Untouched image returns STEGO_ERR_NO_PAYLOAD */
static bool test_detect_no_payload(void) {
    BMPImage *img = NULL;
    bmp_create(50, 50, &img);
    fill_gradient(img);

    uint8_t *decoded = NULL;
    size_t decoded_len = 0;
    StegoResult res = stego_decode(img, &decoded, &decoded_len);
    bmp_free(img);

    return (res == STEGO_ERR_NO_PAYLOAD && decoded == NULL);
}

/* Test 8: Reject payload exceeding capacity */
static bool test_capacity_exceeded(void) {
    BMPImage *img = NULL;
    bmp_create(16, 16, &img); /* 256 px * 3 = 768 bytes -> 96 - 8 = 88 bytes */
    size_t cap = stego_max_payload_size(img);

    uint8_t *too_big = (uint8_t *)malloc(cap + 10);
    memset(too_big, 0x5A, cap + 10);

    StegoResult res = stego_encode(img, too_big, cap + 10);
    free(too_big);
    bmp_free(img);

    return (res == STEGO_ERR_CAPACITY_EXCEEDED);
}

/* Test 9: Verify scanline row padding preservation (widths 7, 11, 13, 21) */
static bool test_row_padding_alignments(void) {
    uint32_t widths[] = { 7, 11, 13, 21 };
    for (size_t i = 0; i < sizeof(widths)/sizeof(widths[0]); i++) {
        BMPImage *img = NULL;
        bmp_create(widths[i], 20, &img);
        fill_gradient(img);

        const char *msg = "Row padding bytes must remain pristine!";
        size_t msg_len = strlen(msg);

        StegoResult res = stego_encode(img, (const uint8_t *)msg, msg_len);
        if (res != STEGO_OK) {
            bmp_free(img);
            return false;
        }

        uint8_t *decoded = NULL;
        size_t decoded_len = 0;
        res = stego_decode(img, &decoded, &decoded_len);
        bmp_free(img);

        if (res != STEGO_OK || decoded_len != msg_len || memcmp(decoded, msg, msg_len) != 0) {
            free(decoded);
            return false;
        }
        free(decoded);
    }
    return true;
}

/* Test 10: File-based hide and extract round-trip */
static bool test_file_api_roundtrip(void) {
    BMPImage *img = NULL;
    bmp_create(100, 100, &img);
    fill_gradient(img);
    bmp_save("tmp_test_cover.bmp", img);
    bmp_free(img);

    const char *secret_content = "Confidential document payload.\nLine 2.\nLine 3.\nEnd of file.";
    FILE *sfp = fopen("tmp_test_secret.txt", "wb");
    fwrite(secret_content, 1, strlen(secret_content), sfp);
    fclose(sfp);

    StegoResult res = stego_hide_file("tmp_test_cover.bmp", "tmp_test_stego.bmp", "tmp_test_secret.txt");
    if (res != STEGO_OK) {
        remove("tmp_test_cover.bmp");
        remove("tmp_test_secret.txt");
        return false;
    }

    res = stego_extract_file("tmp_test_stego.bmp", "tmp_test_extracted.txt");
    if (res != STEGO_OK) {
        remove("tmp_test_cover.bmp");
        remove("tmp_test_secret.txt");
        remove("tmp_test_stego.bmp");
        return false;
    }

    FILE *efp = fopen("tmp_test_extracted.txt", "rb");
    char read_buf[256] = {0};
    size_t n = fread(read_buf, 1, sizeof(read_buf) - 1, efp);
    fclose(efp);

    bool match = (n == strlen(secret_content) && memcmp(read_buf, secret_content, n) == 0);

    remove("tmp_test_cover.bmp");
    remove("tmp_test_secret.txt");
    remove("tmp_test_stego.bmp");
    remove("tmp_test_extracted.txt");

    return match;
}

int main(void) {
    printf("====================================================\n");
    printf("   BMP-STEGO PHASE 1 TEST SUITE (8-BYTE CMC1)       \n");
    printf("====================================================\n");

    RUN_TEST(test_bmp_create_save_load);
    RUN_TEST(test_capacity_calculation);
    RUN_TEST(test_encode_decode_text);
    RUN_TEST(test_encode_decode_binary_data);
    RUN_TEST(test_encode_decode_empty_payload);
    RUN_TEST(test_max_capacity_payload);
    RUN_TEST(test_detect_no_payload);
    RUN_TEST(test_capacity_exceeded);
    RUN_TEST(test_row_padding_alignments);
    RUN_TEST(test_file_api_roundtrip);

    printf("====================================================\n");
    printf("Result: %d / %d tests passed (%.1f%%)\n",
           g_tests_passed, g_tests_run, (100.0 * g_tests_passed) / g_tests_run);
    printf("====================================================\n");

    return (g_tests_passed == g_tests_run) ? EXIT_SUCCESS : EXIT_FAILURE;
}
