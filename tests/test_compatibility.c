/**
 * @file test_compatibility.c
 * @brief Comprehensive format compatibility & normalization test suite.
 * 
 * Verifies all 12 compatibility criteria:
 *  1. 8-bit RGB PNG
 *  2. 8-bit RGBA PNG (verifying alpha channel preservation)
 *  3. Grayscale PNG (converted to RGB)
 *  4. Palette PNG (converted to RGB)
 *  5. 16-bit PNG (converted to 8-bit RGB)
 *  6. BMP carrier roundtrip
 *  7. JPEG input converted to PNG output
 *  8. WEBP input converted to PNG output
 *  9. GIF input converted to PNG output
 * 10. Invalid image (truncated data) rejected
 * 11. Unsupported format (unknown magic) rejected
 * 12. Oversized image (> 16384 dimensions) rejected
 */

#include "stego/stego.h"
#include "stego/file_payload.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static void unpack_if_fil1(uint8_t **extracted, size_t *ext_len) {
    if (!extracted || !*extracted || *ext_len == 0) return;
    if (stego_file_payload_is_fil1(*extracted, *ext_len)) {
        StegoFileMetadata meta;
        uint8_t *unpacked = NULL;
        size_t unpacked_len = 0;
        if (stego_file_payload_unpack(*extracted, *ext_len, &meta, &unpacked, &unpacked_len) == STEGO_OK) {
            free(*extracted);
            *extracted = unpacked;
            *ext_len = unpacked_len;
        }
    }
}

#define TEST_PASS "\033[32m[PASS]\033[0m"
#define TEST_FAIL "\033[31m[FAIL]\033[0m"

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define RUN_TEST(fn) do { \
    g_tests_run++; \
    printf("Running %-50s ... ", #fn); \
    fflush(stdout); \
    if (fn()) { \
        printf("%s\n", TEST_PASS); \
        g_tests_passed++; \
    } else { \
        printf("%s\n", TEST_FAIL); \
    } \
} while (0)

/* Helper: file exists check */
static bool file_exists(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    fclose(fp);
    return true;
}

/* Helper: write binary buffer to file */
static bool write_file_bytes(const char *path, const uint8_t *data, size_t size) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return false;
    size_t w = fwrite(data, 1, size, fp);
    fclose(fp);
    return (w == size);
}

/* ------------------------------------------------------------------------- */
/* Test 1: 8-bit RGB PNG roundtrip                                           */
/* ------------------------------------------------------------------------- */
static bool test_rgb8_png(void) {
    const char *cover = "samples/compat/rgb8.png";
    const char *stego = "tmp_compat_rgb8_stego.png";
    const char *out_txt = "tmp_compat_rgb8_out.txt";
    const char *secret = "RGB8 PNG secret payload: 1234567890!";
    size_t sec_len = strlen(secret);

    if (!file_exists(cover)) return false;

    StegoResult res = stego_hide_file_unified_secure(cover, stego, "samples/secret.txt", NULL, false);
    if (res != STEGO_OK) {
        /* Write temporary secret if secret.txt is missing */
        write_file_bytes("tmp_secret.txt", (const uint8_t *)secret, sec_len);
        res = stego_hide_file_unified_secure(cover, stego, "tmp_secret.txt", NULL, false);
        remove("tmp_secret.txt");
        if (res != STEGO_OK) return false;
    }

    res = stego_extract_file_unified_secure(stego, out_txt, NULL, false);
    if (res != STEGO_OK) {
        remove(stego);
        return false;
    }

    /* Verify extracted content */
    FILE *fp = fopen(out_txt, "rb");
    if (!fp) {
        remove(stego);
        return false;
    }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fclose(fp);

    remove(stego);
    remove(out_txt);
    return (sz > 0);
}

/* ------------------------------------------------------------------------- */
/* Test 2: 8-bit RGBA PNG with alpha preservation check                      */
/* ------------------------------------------------------------------------- */
static bool test_rgba8_png_alpha_preservation(void) {
    const char *cover = "samples/compat/rgba8.png";
    const char *stego = "tmp_compat_rgba8_stego.png";
    const char *secret = "Alpha preservation payload!";

    if (!file_exists(cover)) return false;

    /* 1. Load cover image and snapshot its alpha values */
    StegoImage *cover_img = NULL;
    if (stego_image_load(cover, &cover_img) != STEGO_OK || !cover_img) return false;
    if (cover_img->channels != 4) {
        stego_image_free(cover_img);
        return false;
    }

    size_t pixel_count = (size_t)cover_img->width * cover_img->height;
    uint8_t *orig_alpha = (uint8_t *)malloc(pixel_count);
    for (size_t i = 0; i < pixel_count; i++) {
        orig_alpha[i] = cover_img->pixels[i * 4 + 3];
    }
    stego_image_free(cover_img);

    /* 2. Embed secret into RGBA image */
    write_file_bytes("tmp_alpha_sec.txt", (const uint8_t *)secret, strlen(secret));
    StegoResult res = stego_hide_file_unified_secure(cover, stego, "tmp_alpha_sec.txt", NULL, false);
    remove("tmp_alpha_sec.txt");
    if (res != STEGO_OK) {
        free(orig_alpha);
        return false;
    }

    /* 3. Load generated stego image and verify alpha preservation */
    StegoImage *stego_img = NULL;
    if (stego_image_load(stego, &stego_img) != STEGO_OK || !stego_img) {
        free(orig_alpha);
        remove(stego);
        return false;
    }

    bool alpha_preserved = true;
    if (stego_img->channels != 4) {
        alpha_preserved = false;
    } else {
        for (size_t i = 0; i < pixel_count; i++) {
            if (stego_img->pixels[i * 4 + 3] != orig_alpha[i]) {
                alpha_preserved = false;
                break;
            }
        }
    }
    stego_image_free(stego_img);
    free(orig_alpha);

    /* 4. Verify extraction succeeds */
    uint8_t *extracted = NULL;
    size_t ext_len = 0;
    StegoCarrier *carrier = NULL;
    if (stego_carrier_open(stego, false, &carrier) == STEGO_OK) {
        res = carrier->extract(carrier, &extracted, &ext_len);
        stego_carrier_close(carrier);
    }
    remove(stego);
    unpack_if_fil1(&extracted, &ext_len);

    bool payload_matches = (res == STEGO_OK && ext_len == strlen(secret) &&
                            memcmp(extracted, secret, ext_len) == 0);
    free(extracted);

    return (alpha_preserved && payload_matches);
}

/* ------------------------------------------------------------------------- */
/* Test 3: Grayscale PNG normalized to RGB roundtrip                         */
/* ------------------------------------------------------------------------- */
static bool test_grayscale_png(void) {
    const char *cover = "samples/compat/gray8.png";
    const char *stego = "tmp_compat_gray_stego.png";
    const char *secret = "Grayscale normalized to RGB secret!";

    if (!file_exists(cover)) return false;

    /* Verify loader detects Grayscale and converts to 3 channels */
    StegoImage *img = NULL;
    if (stego_image_load(cover, &img) != STEGO_OK || !img) return false;
    bool was_converted = img->was_converted;
    uint32_t channels = img->channels;
    stego_image_free(img);

    if (!was_converted || channels != 3) return false;

    /* Embed and extract */
    write_file_bytes("tmp_gray_sec.txt", (const uint8_t *)secret, strlen(secret));
    StegoResult res = stego_hide_file_unified_secure(cover, stego, "tmp_gray_sec.txt", NULL, false);
    remove("tmp_gray_sec.txt");
    if (res != STEGO_OK) return false;

    uint8_t *extracted = NULL;
    size_t ext_len = 0;
    StegoCarrier *carrier = NULL;
    res = stego_carrier_open(stego, false, &carrier);
    if (res != STEGO_OK) {
        remove(stego);
        return false;
    }
    res = carrier->extract(carrier, &extracted, &ext_len);
    stego_carrier_close(carrier);
    remove(stego);
    unpack_if_fil1(&extracted, &ext_len);

    bool match = (res == STEGO_OK && ext_len == strlen(secret) &&
                  memcmp(extracted, secret, ext_len) == 0);
    free(extracted);
    return match;
}

/* ------------------------------------------------------------------------- */
/* Test 4: Palette PNG normalized to RGB roundtrip                           */
/* ------------------------------------------------------------------------- */
static bool test_palette_png(void) {
    const char *cover = "samples/compat/palette.png";
    const char *stego = "tmp_compat_palette_stego.png";
    const char *secret = "Palette normalized to RGB secret!";

    if (!file_exists(cover)) return false;

    StegoImage *img = NULL;
    if (stego_image_load(cover, &img) != STEGO_OK || !img) return false;
    bool was_converted = img->was_converted;
    uint32_t channels = img->channels;
    stego_image_free(img);

    if (!was_converted || channels != 3) return false;

    write_file_bytes("tmp_pal_sec.txt", (const uint8_t *)secret, strlen(secret));
    StegoResult res = stego_hide_file_unified_secure(cover, stego, "tmp_pal_sec.txt", NULL, false);
    remove("tmp_pal_sec.txt");
    if (res != STEGO_OK) return false;

    uint8_t *extracted = NULL;
    size_t ext_len = 0;
    StegoCarrier *carrier = NULL;
    res = stego_carrier_open(stego, false, &carrier);
    if (res != STEGO_OK) {
        remove(stego);
        return false;
    }
    res = carrier->extract(carrier, &extracted, &ext_len);
    stego_carrier_close(carrier);
    remove(stego);
    unpack_if_fil1(&extracted, &ext_len);

    bool match = (res == STEGO_OK && ext_len == strlen(secret) &&
                  memcmp(extracted, secret, ext_len) == 0);
    free(extracted);
    return match;
}

/* ------------------------------------------------------------------------- */
/* Test 5: 16-bit PNG normalized to 8-bit RGB roundtrip                      */
/* ------------------------------------------------------------------------- */
static bool test_16bit_png(void) {
    const char *cover = "samples/compat/gray16.png";
    const char *stego = "tmp_compat_16bit_stego.png";
    const char *secret = "16-bit PNG downscaled to 8-bit secret!";

    if (!file_exists(cover)) return false;

    StegoImage *img = NULL;
    if (stego_image_load(cover, &img) != STEGO_OK || !img) return false;
    bool was_16bit = (img->orig_bit_depth == 16);
    uint32_t channels = img->channels;
    stego_image_free(img);

    if (!was_16bit || channels != 3) return false;

    write_file_bytes("tmp_16_sec.txt", (const uint8_t *)secret, strlen(secret));
    StegoResult res = stego_hide_file_unified_secure(cover, stego, "tmp_16_sec.txt", NULL, false);
    remove("tmp_16_sec.txt");
    if (res != STEGO_OK) return false;

    uint8_t *extracted = NULL;
    size_t ext_len = 0;
    StegoCarrier *carrier = NULL;
    res = stego_carrier_open(stego, false, &carrier);
    if (res != STEGO_OK) {
        remove(stego);
        return false;
    }
    res = carrier->extract(carrier, &extracted, &ext_len);
    stego_carrier_close(carrier);
    remove(stego);
    unpack_if_fil1(&extracted, &ext_len);

    bool match = (res == STEGO_OK && ext_len == strlen(secret) &&
                  memcmp(extracted, secret, ext_len) == 0);
    free(extracted);
    return match;
}

/* ------------------------------------------------------------------------- */
/* Test 6: BMP carrier roundtrip                                             */
/* ------------------------------------------------------------------------- */
static bool test_bmp_carrier(void) {
    const char *cover = "samples/compat/cover.bmp";
    const char *stego = "tmp_compat_bmp_stego.bmp";
    const char *secret = "BMP 24-bit carrier payload!";

    if (!file_exists(cover)) return false;

    write_file_bytes("tmp_bmp_sec.txt", (const uint8_t *)secret, strlen(secret));
    StegoResult res = stego_hide_file_unified_secure(cover, stego, "tmp_bmp_sec.txt", NULL, false);
    remove("tmp_bmp_sec.txt");
    if (res != STEGO_OK) return false;

    uint8_t *extracted = NULL;
    size_t ext_len = 0;
    StegoCarrier *carrier = NULL;
    res = stego_carrier_open(stego, false, &carrier);
    if (res != STEGO_OK) {
        remove(stego);
        return false;
    }
    res = carrier->extract(carrier, &extracted, &ext_len);
    stego_carrier_close(carrier);
    remove(stego);
    unpack_if_fil1(&extracted, &ext_len);

    bool match = (res == STEGO_OK && ext_len == strlen(secret) &&
                  memcmp(extracted, secret, ext_len) == 0);
    free(extracted);
    return match;
}

/* ------------------------------------------------------------------------- */
/* Test 7: JPEG -> PNG conversion roundtrip                                  */
/* ------------------------------------------------------------------------- */
static bool test_jpeg_to_png(void) {
    const char *cover = "samples/compat/sample.jpg";
    const char *stego_png = "tmp_compat_jpg_stego.png";
    const char *secret = "JPEG decoded to pixels, embedded, saved as PNG!";

    if (!file_exists(cover)) return false;

    /* Verify safety check blocks saving stego output directly as JPEG */
    write_file_bytes("tmp_jpg_sec.txt", (const uint8_t *)secret, strlen(secret));
    StegoResult unsafe_res = stego_hide_file_unified_secure(cover, "tmp_unsafe.jpg", "tmp_jpg_sec.txt", NULL, false);
    if (unsafe_res != STEGO_ERR_UNSAFE_CONVERSION) {
        remove("tmp_jpg_sec.txt");
        remove("tmp_unsafe.jpg");
        return false;
    }

    /* Embed into JPEG pixels and save safely as PNG */
    StegoResult res = stego_hide_file_unified_secure(cover, stego_png, "tmp_jpg_sec.txt", NULL, false);
    remove("tmp_jpg_sec.txt");
    if (res != STEGO_OK) return false;

    /* Extract and verify */
    uint8_t *extracted = NULL;
    size_t ext_len = 0;
    StegoCarrier *carrier = NULL;
    res = stego_carrier_open(stego_png, false, &carrier);
    if (res != STEGO_OK) {
        remove(stego_png);
        return false;
    }
    res = carrier->extract(carrier, &extracted, &ext_len);
    stego_carrier_close(carrier);
    remove(stego_png);
    unpack_if_fil1(&extracted, &ext_len);

    bool match = (res == STEGO_OK && ext_len == strlen(secret) &&
                  memcmp(extracted, secret, ext_len) == 0);
    free(extracted);
    return match;
}

/* ------------------------------------------------------------------------- */
/* Test 8: WebP -> PNG conversion roundtrip (CMC2 authenticated)             */
/* ------------------------------------------------------------------------- */
static bool test_webp_to_png(void) {
    const char *cover = "samples/compat/sample.webp";
    const char *stego_png = "tmp_compat_webp_stego.png";
    const char *secret = "WebP authenticated Argon2id AES-256-GCM payload!";
    const char *passphrase = "WebP-Test-Key#2026";

    if (!file_exists(cover)) return false;

    /* Verify safety check blocks saving directly to lossy WebP */
    write_file_bytes("tmp_webp_sec.txt", (const uint8_t *)secret, strlen(secret));
    StegoResult unsafe_res = stego_hide_file_unified_secure(cover, "tmp_unsafe.webp", "tmp_webp_sec.txt", passphrase, false);
    if (unsafe_res != STEGO_ERR_UNSAFE_CONVERSION) {
        remove("tmp_webp_sec.txt");
        remove("tmp_unsafe.webp");
        return false;
    }

    /* Save stego output safely as PNG */
    StegoResult res = stego_hide_file_unified_secure(cover, stego_png, "tmp_webp_sec.txt", passphrase, false);
    remove("tmp_webp_sec.txt");
    if (res != STEGO_OK) return false;

    /* Verify correct passphrase extraction */
    uint8_t *extracted = NULL;
    size_t ext_len = 0;
    StegoCarrier *carrier = NULL;
    res = stego_carrier_open(stego_png, false, &carrier);
    if (res != STEGO_OK) {
        remove(stego_png);
        return false;
    }
    res = carrier->extract_secure(carrier, passphrase, &extracted, &ext_len);
    stego_carrier_close(carrier);
    unpack_if_fil1(&extracted, &ext_len);

    bool correct_pass_match = (res == STEGO_OK && ext_len == strlen(secret) &&
                               memcmp(extracted, secret, ext_len) == 0);
    free(extracted);

    /* Verify wrong passphrase rejection */
    res = stego_carrier_open(stego_png, false, &carrier);
    if (res != STEGO_OK) {
        remove(stego_png);
        return false;
    }
    res = carrier->extract_secure(carrier, "WrongPassword!", &extracted, &ext_len);
    stego_carrier_close(carrier);
    remove(stego_png);

    bool wrong_pass_rejected = (res == STEGO_ERR_AUTH_FAILED);
    return (correct_pass_match && wrong_pass_rejected);
}

/* ------------------------------------------------------------------------- */
/* Test 9: GIF -> PNG conversion roundtrip                                   */
/* ------------------------------------------------------------------------- */
static bool test_gif_to_png(void) {
    const char *cover = "samples/compat/sample.gif";
    const char *stego_png = "tmp_compat_gif_stego.png";
    const char *secret = "GIF indexed frame decoded and embedded safely!";

    if (!file_exists(cover)) return false;

    /* Verify safety check blocks saving directly to GIF */
    write_file_bytes("tmp_gif_sec.txt", (const uint8_t *)secret, strlen(secret));
    StegoResult unsafe_res = stego_hide_file_unified_secure(cover, "tmp_unsafe.gif", "tmp_gif_sec.txt", NULL, false);
    if (unsafe_res != STEGO_ERR_UNSAFE_CONVERSION) {
        remove("tmp_gif_sec.txt");
        remove("tmp_unsafe.gif");
        return false;
    }

    /* Save stego output safely as PNG */
    StegoResult res = stego_hide_file_unified_secure(cover, stego_png, "tmp_gif_sec.txt", NULL, false);
    remove("tmp_gif_sec.txt");
    if (res != STEGO_OK) return false;

    uint8_t *extracted = NULL;
    size_t ext_len = 0;
    StegoCarrier *carrier = NULL;
    res = stego_carrier_open(stego_png, false, &carrier);
    if (res != STEGO_OK) {
        remove(stego_png);
        return false;
    }
    res = carrier->extract(carrier, &extracted, &ext_len);
    stego_carrier_close(carrier);
    remove(stego_png);
    unpack_if_fil1(&extracted, &ext_len);

    bool match = (res == STEGO_OK && ext_len == strlen(secret) &&
                  memcmp(extracted, secret, ext_len) == 0);
    free(extracted);
    return match;
}

/* ------------------------------------------------------------------------- */
/* Test 10: Invalid / corrupted image rejection                              */
/* ------------------------------------------------------------------------- */
static bool test_invalid_image_rejected(void) {
    const char *corrupt_img = "samples/compat/invalid.png";
    if (!file_exists(corrupt_img)) {
        /* Generate truncated PNG on the fly if needed */
        const uint8_t trunc_sig[14] = { 0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n', 0x00, 0x00, 0x00, 0x0D, 'I', 'H' };
        write_file_bytes(corrupt_img, trunc_sig, sizeof(trunc_sig));
    }

    StegoImage *img = NULL;
    StegoResult res = stego_image_load(corrupt_img, &img);
    if (img) {
        stego_image_free(img);
        return false;
    }

    return (res == STEGO_ERR_IMAGE_DECODE || res == STEGO_ERR_IMAGE_INVALID_DATA);
}

/* ------------------------------------------------------------------------- */
/* Test 11: Unsupported format rejection                                     */
/* ------------------------------------------------------------------------- */
static bool test_unsupported_format_rejected(void) {
    const char *unsupp_file = "samples/compat/unsupported.xyz";
    if (!file_exists(unsupp_file)) {
        const char *junk = "THIS_IS_NOT_A_SUPPORTED_IMAGE_FORMAT_0123456789";
        write_file_bytes(unsupp_file, (const uint8_t *)junk, strlen(junk));
    }

    StegoImage *img = NULL;
    StegoResult res = stego_image_load(unsupp_file, &img);
    if (img) {
        stego_image_free(img);
        return false;
    }

    return (res == STEGO_ERR_UNSUPPORTED_FORMAT);
}

/* ------------------------------------------------------------------------- */
/* Test 12: Oversized image dimension rejection (> 16384)                    */
/* ------------------------------------------------------------------------- */
static bool test_oversized_image_rejected(void) {
    const char *oversized_file = "samples/compat/oversized.png";
    if (!file_exists(oversized_file)) return false;

    StegoImage *img = NULL;
    StegoResult res = stego_image_load(oversized_file, &img);
    if (img) {
        stego_image_free(img);
        return false;
    }

    return (res == STEGO_ERR_IMAGE_TOO_LARGE);
}

/* ------------------------------------------------------------------------- */
/* Main test runner                                                          */
/* ------------------------------------------------------------------------- */
int main(void) {
    printf("=================================================================\n");
    printf("       IMAGE COMPATIBILITY & NORMALIZATION TEST SUITE            \n");
    printf("=================================================================\n");

    RUN_TEST(test_rgb8_png);
    RUN_TEST(test_rgba8_png_alpha_preservation);
    RUN_TEST(test_grayscale_png);
    RUN_TEST(test_palette_png);
    RUN_TEST(test_16bit_png);
    RUN_TEST(test_bmp_carrier);
    RUN_TEST(test_jpeg_to_png);
    RUN_TEST(test_webp_to_png);
    RUN_TEST(test_gif_to_png);
    RUN_TEST(test_invalid_image_rejected);
    RUN_TEST(test_unsupported_format_rejected);
    RUN_TEST(test_oversized_image_rejected);

    printf("=================================================================\n");
    printf("Result: %d / %d tests passed (%.1f%%)\n",
           g_tests_passed, g_tests_run, (100.0 * g_tests_passed) / g_tests_run);
    printf("=================================================================\n");

    return (g_tests_passed == g_tests_run) ? EXIT_SUCCESS : EXIT_FAILURE;
}

