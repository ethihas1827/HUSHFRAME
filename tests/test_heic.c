/**
 * @file test_heic.c
 * @brief HEIC format detection tests.
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

static bool test_heic_magic_detection(void) {
    uint8_t heic_header[16] = {
        0x00, 0x00, 0x00, 0x18,
        'f', 't', 'y', 'p',
        'h', 'e', 'i', 'c',
        0x00, 0x00, 0x00, 0x00
    };
    StegoImageFormat fmt = stego_detect_format_buffer(heic_header, sizeof(heic_header));
    return (fmt == STEGO_FORMAT_HEIC);
}

int main(void) {
    printf("====================================================\n");
    printf("          HEIC FORMAT DETECTION TEST SUITE          \n");
    printf("====================================================\n");
    RUN_TEST(test_heic_magic_detection);
    printf("====================================================\n");
    printf("Result: %d / %d tests passed\n", g_tests_passed, g_tests_run);
    printf("====================================================\n");
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}

