/**
 * @file test_png.c
 * @brief PNG carrier and adaptive LSB embedding test suite.
 */

#include "stego/stego.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

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

static void fill_png_gradient(StegoImage *img) {
    for (uint32_t y = 0; y < img->height; y++) {
        uint8_t *row = img->pixels + (y * img->stride);
        for (uint32_t x = 0; x < img->width; x++) {
            row[x * img->channels + 0] = (uint8_t)((x * 255) / img->width);
            row[x * img->channels + 1] = (uint8_t)((y * 255) / img->height);
            row[x * img->channels + 2] = (uint8_t)(((x + y) * 128) / (img->width + img->height));
            if (img->channels == 4) {
                row[x * img->channels + 3] = 255;
            }
        }
    }
}

static bool test_png_magic_detection(void) {
    uint8_t png_header[8] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
    StegoImageFormat fmt = stego_detect_format_buffer(png_header, sizeof(png_header));
    return (fmt == STEGO_FORMAT_PNG);
}

static bool test_png_create_save_reload(void) {
    StegoImage *img = NULL;
    if (stego_image_create(50, 40, 3, STEGO_FORMAT_PNG, &img) != STEGO_OK || !img) return false;
    fill_png_gradient(img);

    const char *tmp = "tmp_test_png.png";
    if (stego_image_save(tmp, img, STEGO_FORMAT_PNG) != STEGO_OK) {
        stego_image_free(img);
        return false;
    }
    stego_image_free(img);

    /* Verify magic bytes on disk */
    if (stego_detect_format(tmp) != STEGO_FORMAT_PNG) {
        remove(tmp);
        return false;
    }

    /* Reload */
    StegoImage *loaded = NULL;
    if (stego_image_load(tmp, &loaded) != STEGO_OK || !loaded) {
        remove(tmp);
        return false;
    }

    bool ok = (loaded->width == 50 && loaded->height == 40 && loaded->channels == 3);
    stego_image_free(loaded);
    remove(tmp);
    return ok;
}

static bool test_png_standard_lsb_roundtrip(void) {
    StegoImage *img = NULL;
    stego_image_create(64, 64, 3, STEGO_FORMAT_PNG, &img);
    fill_png_gradient(img);

    const char *secret = "Testing PNG Standard LSB Embedding";
    size_t slen = strlen(secret);

    if (png_encode(img, (const uint8_t *)secret, slen, false) != STEGO_OK) {
        stego_image_free(img);
        return false;
    }

    uint8_t *decoded = NULL;
    size_t dlen = 0;
    if (png_decode(img, &decoded, &dlen, false) != STEGO_OK || !decoded) {
        stego_image_free(img);
        return false;
    }
    stego_image_free(img);

    bool ok = (dlen == slen && memcmp(decoded, secret, slen) == 0);
    free(decoded);
    return ok;
}

static bool test_png_adaptive_lsb_roundtrip(void) {
    StegoImage *img = NULL;
    stego_image_create(80, 80, 3, STEGO_FORMAT_PNG, &img);
    fill_png_gradient(img);

    const char *secret = "Adaptive Texture-Aware LSB Roundtrip Test!";
    size_t slen = strlen(secret);

    if (png_encode(img, (const uint8_t *)secret, slen, true) != STEGO_OK) {
        stego_image_free(img);
        return false;
    }

    uint8_t *decoded = NULL;
    size_t dlen = 0;
    if (png_decode(img, &decoded, &dlen, true) != STEGO_OK || !decoded) {
        stego_image_free(img);
        return false;
    }
    stego_image_free(img);

    bool ok = (dlen == slen && memcmp(decoded, secret, slen) == 0);
    free(decoded);
    return ok;
}

static bool test_png_binary_data_roundtrip(void) {
    StegoImage *img = NULL;
    stego_image_create(70, 70, 3, STEGO_FORMAT_PNG, &img);
    fill_png_gradient(img);

    uint8_t bin[128];
    for (int i = 0; i < 128; i++) bin[i] = (uint8_t)(i ^ 0xAA);

    if (png_encode(img, bin, sizeof(bin), false) != STEGO_OK) {
        stego_image_free(img);
        return false;
    }

    uint8_t *decoded = NULL;
    size_t dlen = 0;
    if (png_decode(img, &decoded, &dlen, false) != STEGO_OK || !decoded) {
        stego_image_free(img);
        return false;
    }
    stego_image_free(img);

    bool ok = (dlen == sizeof(bin) && memcmp(decoded, bin, sizeof(bin)) == 0);
    free(decoded);
    return ok;
}

static bool test_png_capacity_exceeded_check(void) {
    StegoImage *img = NULL;
    stego_image_create(10, 10, 3, STEGO_FORMAT_PNG, &img);
    size_t cap = png_max_payload_size(img, false);

    uint8_t *buf = (uint8_t *)malloc(cap + 10);
    StegoResult res = png_encode(img, buf, cap + 10, false);
    free(buf);
    stego_image_free(img);

    return (res == STEGO_ERR_CAPACITY_EXCEEDED);
}

static bool test_png_file_unified_api(void) {
    /* 1. Create cover PNG */
    StegoImage *img = NULL;
    stego_image_create(64, 64, 3, STEGO_FORMAT_PNG, &img);
    fill_png_gradient(img);
    const char *cover_file = "tmp_test_cover.png";
    const char *stego_file = "tmp_test_stego.png";
    const char *secret_file = "tmp_test_secret.txt";
    const char *recovered_file = "tmp_test_recovered.txt";

    stego_image_save(cover_file, img, STEGO_FORMAT_PNG);
    stego_image_free(img);

    /* 2. Create secret file */
    const char *msg = "Unified PNG File Hide and Extract Test Passed!";
    FILE *sfp = fopen(secret_file, "wb");
    fwrite(msg, 1, strlen(msg), sfp);
    fclose(sfp);

    /* 3. Hide file */
    StegoResult res = stego_hide_file_unified(cover_file, stego_file, secret_file, false);
    if (res != STEGO_OK) {
        remove(cover_file);
        remove(secret_file);
        return false;
    }

    /* 4. Extract file */
    res = stego_extract_file_unified(stego_file, recovered_file, false);
    if (res != STEGO_OK) {
        remove(cover_file);
        remove(stego_file);
        remove(secret_file);
        return false;
    }

    /* 5. Compare */
    FILE *rfp = fopen(recovered_file, "rb");
    char read_buf[128] = { 0 };
    size_t r = fread(read_buf, 1, sizeof(read_buf) - 1, rfp);
    fclose(rfp);

    bool ok = (r == strlen(msg) && memcmp(read_buf, msg, r) == 0);

    remove(cover_file);
    remove(stego_file);
    remove(secret_file);
    remove(recovered_file);
    return ok;
}

int main(void) {
    printf("====================================================\n");
    printf("     PNG CARRIER & ADAPTIVE LSB TEST SUITE          \n");
    printf("====================================================\n");
    RUN_TEST(test_png_magic_detection);
    RUN_TEST(test_png_create_save_reload);
    RUN_TEST(test_png_standard_lsb_roundtrip);
    RUN_TEST(test_png_adaptive_lsb_roundtrip);
    RUN_TEST(test_png_binary_data_roundtrip);
    RUN_TEST(test_png_capacity_exceeded_check);
    RUN_TEST(test_png_file_unified_api);
    printf("====================================================\n");
    printf("Result: %d / %d tests passed\n", g_tests_passed, g_tests_run);
    printf("====================================================\n");
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}

