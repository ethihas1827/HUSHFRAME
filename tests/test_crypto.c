/**
 * @file test_crypto.c
 * @brief Cryptographic security, Argon2id, AES-256-GCM AEAD, and memory hygiene test suite.
 */

#include "stego/crypto.h"
#include "stego/png_carrier.h"
#include "stego/image_loader.h"
#include "stego/payload.h"
#include "stego/error.h"
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
    printf("Running %-55s ... ", #fn); \
    fflush(stdout); \
    if (fn()) { \
        printf("%s\n", TEST_PASS); \
        g_tests_passed++; \
    } else { \
        printf("%s\n", TEST_FAIL); \
    } \
} while (0)

static StegoImage *create_test_image(uint32_t width, uint32_t height) {
    StegoImage *img = NULL;
    StegoResult res = stego_image_create(width, height, 3, STEGO_FORMAT_PNG, &img);
    if (res != STEGO_OK || !img) return NULL;

    for (size_t i = 0; i < img->data_size; i++) {
        img->pixels[i] = (uint8_t)((i * 37) & 0xFF);
    }
    return img;
}

static bool test_crc32_standard_vector(void) {
    const char *text = "123456789";
    uint32_t crc = stego_crc32(0, (const uint8_t *)text, 9);
    return (crc == 0xCBF43926);
}

static bool test_secure_memory_zeroing(void) {
    uint8_t buffer[128];
    memset(buffer, 0x5A, sizeof(buffer));
    stego_secure_zero(buffer, sizeof(buffer));

    for (size_t i = 0; i < sizeof(buffer); i++) {
        if (buffer[i] != 0) return false;
    }
    return true;
}

static bool test_embed_with_passphrase_creates_cmc2_encrypted_envelope(void) {
    StegoImage *img = create_test_image(48, 48);
    if (!img) return false;

    const char *secret = "Encrypted Payload Test";
    size_t secret_len = strlen(secret);
    const char *passphrase = "my-strong-password";

    StegoResult res = png_encode_secure(img, (const uint8_t *)secret, secret_len, passphrase, false);
    if (res != STEGO_OK) {
        stego_image_free(img);
        return false;
    }

    /* Verify payload envelope detection confirms CMC2 */
    uint32_t detected_len = 0;
    StegoEnvelopeType env = png_detect_envelope(img, false, &detected_len);
    stego_image_free(img);

    return (env == STEGO_ENVELOPE_CMC2 && detected_len == (uint32_t)secret_len);
}

static bool test_extract_with_correct_passphrase_succeeds(void) {
    StegoImage *img = create_test_image(48, 48);
    if (!img) return false;

    const char *secret = "Top Secret Multi-Format Payload 2026!";
    size_t secret_len = strlen(secret);
    const char *passphrase = "SuperSecurePassphrase#99";

    StegoResult res = png_encode_secure(img, (const uint8_t *)secret, secret_len, passphrase, false);
    if (res != STEGO_OK) {
        stego_image_free(img);
        return false;
    }

    uint8_t *recovered = NULL;
    size_t recovered_len = 0;
    res = png_decode_secure(img, passphrase, &recovered, &recovered_len, false);
    if (res != STEGO_OK || !recovered || recovered_len != secret_len) {
        if (recovered) free(recovered);
        stego_image_free(img);
        return false;
    }

    bool match = (memcmp(recovered, secret, secret_len) == 0);
    stego_secure_zero(recovered, recovered_len);
    free(recovered);
    stego_image_free(img);
    return match;
}

static bool test_extract_with_wrong_passphrase_fails(void) {
    StegoImage *img = create_test_image(48, 48);
    if (!img) return false;

    const char *secret = "Confidential Financial Data";
    size_t secret_len = strlen(secret);
    const char *passphrase = "CorrectPassword123";

    StegoResult res = png_encode_secure(img, (const uint8_t *)secret, secret_len, passphrase, false);
    if (res != STEGO_OK) {
        stego_image_free(img);
        return false;
    }

    /* Attempt extraction with incorrect passphrase */
    uint8_t *recovered = NULL;
    size_t recovered_len = 0;
    res = png_decode_secure(img, "WrongPassword456", &recovered, &recovered_len, false);

    /* Must fail with STEGO_ERR_AUTH_FAILED and return NULL payload */
    bool rejected = (res == STEGO_ERR_AUTH_FAILED && recovered == NULL && recovered_len == 0);

    if (recovered) {
        stego_secure_zero(recovered, recovered_len);
        free(recovered);
    }
    stego_image_free(img);
    return rejected;
}

static bool test_extract_without_passphrase_on_encrypted_payload_fails(void) {
    StegoImage *img = create_test_image(48, 48);
    if (!img) return false;

    const char *secret = "Protected Without Password Test";
    size_t secret_len = strlen(secret);
    const char *passphrase = "SecretPass123";

    StegoResult res = png_encode_secure(img, (const uint8_t *)secret, secret_len, passphrase, false);
    if (res != STEGO_OK) {
        stego_image_free(img);
        return false;
    }

    /* Attempt extraction with NULL or empty passphrase */
    uint8_t *recovered = NULL;
    size_t recovered_len = 0;
    res = png_decode_secure(img, NULL, &recovered, &recovered_len, false);
    bool rejected_null = (res == STEGO_ERR_AUTH_FAILED && recovered == NULL);

    res = png_decode_secure(img, "", &recovered, &recovered_len, false);
    bool rejected_empty = (res == STEGO_ERR_AUTH_FAILED && recovered == NULL);

    stego_image_free(img);
    return (rejected_null && rejected_empty);
}

static bool test_tampered_stego_image_fails_authentication(void) {
    StegoImage *img = create_test_image(48, 48);
    if (!img) return false;

    const char *secret = "Integrity check test string";
    size_t secret_len = strlen(secret);
    const char *passphrase = "PasswordForTamper";

    StegoResult res = png_encode_secure(img, (const uint8_t *)secret, secret_len, passphrase, false);
    if (res != STEGO_OK) {
        stego_image_free(img);
        return false;
    }

    /* Tamper with authentication tag (bytes 36..51 in header stream) */
    size_t tamper_pixel_byte = (38 * 8) / 3;
    if (tamper_pixel_byte < img->data_size) {
        img->pixels[tamper_pixel_byte] ^= 0x01;
    }

    uint8_t *recovered = NULL;
    size_t recovered_len = 0;
    res = png_decode_secure(img, passphrase, &recovered, &recovered_len, false);

    bool rejected_tag = (res == STEGO_ERR_AUTH_FAILED && recovered == NULL);
    stego_image_free(img);

    /* Test 2: Tamper with ciphertext */
    img = create_test_image(48, 48);
    if (!img) return false;

    res = png_encode_secure(img, (const uint8_t *)secret, secret_len, passphrase, false);
    if (res != STEGO_OK) {
        stego_image_free(img);
        return false;
    }

    size_t corrupt_pixel_byte = (55 * 8) / 3;
    if (corrupt_pixel_byte < img->data_size) {
        img->pixels[corrupt_pixel_byte] ^= 0x01;
    }

    recovered = NULL;
    recovered_len = 0;
    res = png_decode_secure(img, passphrase, &recovered, &recovered_len, false);

    bool rejected_ciphertext = (res == STEGO_ERR_AUTH_FAILED && recovered == NULL);
    stego_image_free(img);

    return (rejected_tag && rejected_ciphertext);
}

static bool test_capacity_reports_encrypted_overhead_correctly(void) {
    /* 16x16 image: raw capacity = (16*16*3)/8 = 96 bytes */
    StegoImage *img = create_test_image(16, 16);
    if (!img) return false;

    size_t raw_cap = png_raw_capacity(img, false);
    if (raw_cap != 96) {
        stego_image_free(img);
        return false;
    }

    /* CMC1 overhead is 8 bytes -> max payload is 96 - 8 = 88 bytes */
    size_t max_cmc1 = png_max_payload_size(img, false);
    if (max_cmc1 != 88) {
        stego_image_free(img);
        return false;
    }

    /* CMC2 overhead is 52 bytes -> max payload is 96 - 52 = 44 bytes */
    size_t max_cmc2 = png_max_payload_size_cmc2(img, false);
    if (max_cmc2 != 44) {
        stego_image_free(img);
        return false;
    }

    /* Difference between CMC1 and CMC2 overhead must be exactly 52 - 8 = 44 bytes */
    if (max_cmc1 - max_cmc2 != 44) {
        stego_image_free(img);
        return false;
    }

    /* Test boundary at 44 bytes (must succeed) */
    uint8_t payload44[44];
    memset(payload44, 0x42, sizeof(payload44));
    StegoResult res = png_encode_secure(img, payload44, 44, "passphrase", false);
    if (res != STEGO_OK) {
        stego_image_free(img);
        return false;
    }

    /* Test boundary at 45 bytes (must fail with capacity exceeded) */
    uint8_t payload45[45];
    memset(payload45, 0x42, sizeof(payload45));
    res = png_encode_secure(img, payload45, 45, "passphrase", false);
    if (res != STEGO_ERR_CAPACITY_EXCEEDED) {
        stego_image_free(img);
        return false;
    }

    stego_image_free(img);
    return true;
}

int main(void) {
    printf("===============================================================\n");
    printf("       CRYPTO & AUTHENTICATED SECURITY TEST SUITE              \n");
    printf("===============================================================\n");
    RUN_TEST(test_crc32_standard_vector);
    RUN_TEST(test_secure_memory_zeroing);
    RUN_TEST(test_embed_with_passphrase_creates_cmc2_encrypted_envelope);
    RUN_TEST(test_extract_with_correct_passphrase_succeeds);
    RUN_TEST(test_extract_with_wrong_passphrase_fails);
    RUN_TEST(test_extract_without_passphrase_on_encrypted_payload_fails);
    RUN_TEST(test_tampered_stego_image_fails_authentication);
    RUN_TEST(test_capacity_reports_encrypted_overhead_correctly);
    printf("===============================================================\n");
    printf("Result: %d / %d tests passed\n", g_tests_passed, g_tests_run);
    printf("===============================================================\n");
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
