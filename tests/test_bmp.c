/**
 * @file test_bmp.c
 * @brief BMP carrier unit and integration tests.
 */

#include "stego/bmp_carrier.h"
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

static bool test_bmp_create_and_reload(void) {
    BMPImage *img = NULL;
    if (bmp_create(45, 33, &img) != STEGO_OK || !img) return false;

    const char *tmp = "tmp_test_bmp_carrier.bmp";
    if (bmp_save(tmp, img) != STEGO_OK) {
        bmp_free(img);
        return false;
    }
    bmp_free(img);

    BMPImage *loaded = NULL;
    if (bmp_load(tmp, &loaded) != STEGO_OK || !loaded) {
        remove(tmp);
        return false;
    }
    bool ok = (loaded->width == 45 && loaded->height == 33 && loaded->info_header.biBitCount == 24);
    bmp_free(loaded);
    remove(tmp);
    return ok;
}

static bool test_bmp_roundtrip_payload(void) {
    BMPImage *img = NULL;
    bmp_create(64, 48, &img);

    const char *msg = "Automated BMP Carrier Integration Test";
    size_t len = strlen(msg);

    if (bmp_encode(img, (const uint8_t *)msg, len) != STEGO_OK) {
        bmp_free(img);
        return false;
    }

    uint8_t *decoded = NULL;
    size_t dlen = 0;
    if (bmp_decode(img, &decoded, &dlen) != STEGO_OK) {
        bmp_free(img);
        return false;
    }
    bmp_free(img);

    bool ok = (dlen == len && memcmp(decoded, msg, len) == 0);
    free(decoded);
    return ok;
}

int main(void) {
    printf("====================================================\n");
    printf("           BMP CARRIER TEST SUITE                   \n");
    printf("====================================================\n");
    RUN_TEST(test_bmp_create_and_reload);
    RUN_TEST(test_bmp_roundtrip_payload);
    printf("====================================================\n");
    printf("Result: %d / %d tests passed\n", g_tests_passed, g_tests_run);
    printf("====================================================\n");
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}

