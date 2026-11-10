/**
 * @file test_jpeg.c
 * @brief JPEG format detection and safety validation tests.
 */

#include "stego/stego.h"
#include <stdio.h>
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

static bool test_jpeg_magic_detection(void) {
    uint8_t jpeg_header[4] = { 0xFF, 0xD8, 0xFF, 0xE0 };
    StegoImageFormat fmt = stego_detect_format_buffer(jpeg_header, sizeof(jpeg_header));
    return (fmt == STEGO_FORMAT_JPEG);
}

static bool test_jpeg_lossy_safety_check(void) {
    /* Saving spatial LSB from PNG/BMP into lossy JPEG is rejected as unsafe */
    bool safe = stego_is_safe_carrier_format(STEGO_FORMAT_PNG, STEGO_FORMAT_JPEG);
    return (!safe);
}

int main(void) {
    printf("====================================================\n");
    printf("          JPEG FORMAT & SAFETY TEST SUITE           \n");
    printf("====================================================\n");
    RUN_TEST(test_jpeg_magic_detection);
    RUN_TEST(test_jpeg_lossy_safety_check);
    printf("====================================================\n");
    printf("Result: %d / %d tests passed\n", g_tests_passed, g_tests_run);
    printf("====================================================\n");
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}

