/**
 * @file test_payload.c
 * @brief CMC1 and CMC2 envelope header framing, validation, and serialization tests.
 */

#include "stego/payload.h"
#include <stdio.h>
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

static bool test_cmc1_pack_unpack(void) {
    uint8_t header[STEGO_CMC1_HEADER_SIZE] = { 0 };
    uint32_t len = 0x12345678;

    stego_payload_pack_cmc1(header, len);

    uint32_t unpacked_len = 0;
    if (!stego_payload_unpack_cmc1(header, &unpacked_len)) return false;

    return (unpacked_len == len);
}

static bool test_cmc1_corrupted_magic_rejection(void) {
    uint8_t header[STEGO_CMC1_HEADER_SIZE] = { 'B', 'A', 'D', '1', 0, 0, 0, 10 };
    uint32_t len = 0;
    return (!stego_payload_unpack_cmc1(header, &len));
}

static bool test_cmc2_pack_unpack(void) {
    uint8_t header[STEGO_CMC2_HEADER_SIZE] = { 0 };
    uint32_t len = 1024;
    uint8_t salt[STEGO_CMC2_SALT_SIZE] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    uint8_t nonce[STEGO_CMC2_NONCE_SIZE] = { 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120 };
    uint8_t tag[STEGO_CMC2_TAG_SIZE] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00 };

    stego_payload_pack_cmc2(header, len, salt, nonce, tag);

    uint32_t out_len = 0;
    uint8_t out_salt[STEGO_CMC2_SALT_SIZE];
    uint8_t out_nonce[STEGO_CMC2_NONCE_SIZE];
    uint8_t out_tag[STEGO_CMC2_TAG_SIZE];

    if (!stego_payload_unpack_cmc2(header, &out_len, out_salt, out_nonce, out_tag)) return false;
    if (out_len != len) return false;
    if (memcmp(salt, out_salt, sizeof(salt)) != 0) return false;
    if (memcmp(nonce, out_nonce, sizeof(nonce)) != 0) return false;
    if (memcmp(tag, out_tag, sizeof(tag)) != 0) return false;

    return true;
}

static bool test_envelope_detection(void) {
    uint8_t cmc1_buf[STEGO_CMC1_HEADER_SIZE];
    stego_payload_pack_cmc1(cmc1_buf, 500);

    uint32_t len1 = 0;
    if (stego_payload_detect_envelope(cmc1_buf, sizeof(cmc1_buf), &len1) != STEGO_ENVELOPE_CMC1 || len1 != 500) {
        return false;
    }

    uint8_t cmc2_buf[STEGO_CMC2_HEADER_SIZE];
    uint8_t dummy[16] = { 0 };
    stego_payload_pack_cmc2(cmc2_buf, 999, dummy, dummy, dummy);

    uint32_t len2 = 0;
    if (stego_payload_detect_envelope(cmc2_buf, sizeof(cmc2_buf), &len2) != STEGO_ENVELOPE_CMC2 || len2 != 999) {
        return false;
    }

    uint8_t bad_buf[52] = { 0 };
    uint32_t len3 = 0;
    if (stego_payload_detect_envelope(bad_buf, sizeof(bad_buf), &len3) != STEGO_ENVELOPE_NONE) {
        return false;
    }

    return true;
}

int main(void) {
    printf("====================================================\n");
    printf("          PAYLOAD ENVELOPE TEST SUITE               \n");
    printf("====================================================\n");
    RUN_TEST(test_cmc1_pack_unpack);
    RUN_TEST(test_cmc1_corrupted_magic_rejection);
    RUN_TEST(test_cmc2_pack_unpack);
    RUN_TEST(test_envelope_detection);
    printf("====================================================\n");
    printf("Result: %d / %d tests passed\n", g_tests_passed, g_tests_run);
    printf("====================================================\n");
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
