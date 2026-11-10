/**
 * @file test_robustness.c
 * @brief Distortion analysis (PSNR) and conversion safety tests.
 */

#include "stego/stego.h"
#include <stdio.h>

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

static bool test_psnr_identical_images(void) {
    StegoImage *img1 = NULL, *img2 = NULL;
    stego_image_create(32, 32, 3, STEGO_FORMAT_BMP, &img1);
    stego_image_create(32, 32, 3, STEGO_FORMAT_BMP, &img2);

    double psnr = stego_compute_psnr(img1, img2);
    double ssim = stego_compute_ssim(img1, img2);

    stego_image_free(img1);
    stego_image_free(img2);

    return (psnr >= 80.0 && ssim >= 0.999);
}

static bool test_format_conversion_safety_rules(void) {
    /* BMP -> PNG: safe */
    bool b2p = stego_is_safe_carrier_format(STEGO_FORMAT_BMP, STEGO_FORMAT_PNG);
    /* PNG -> BMP: safe */
    bool p2b = stego_is_safe_carrier_format(STEGO_FORMAT_PNG, STEGO_FORMAT_BMP);
    /* BMP -> JPEG: unsafe */
    bool b2j = stego_is_safe_carrier_format(STEGO_FORMAT_BMP, STEGO_FORMAT_JPEG);

    return (b2p && p2b && !b2j);
}

int main(void) {
    printf("====================================================\n");
    printf("          ROBUSTNESS & METRICS TEST SUITE           \n");
    printf("====================================================\n");
    RUN_TEST(test_psnr_identical_images);
    RUN_TEST(test_format_conversion_safety_rules);
    printf("====================================================\n");
    printf("Result: %d / %d tests passed\n", g_tests_passed, g_tests_run);
    printf("====================================================\n");
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}

