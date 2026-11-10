/**
 * @file test_capacity_split.c
 * @brief Comprehensive test suite for capacity estimation, Deflate compression,
 *        and multi-image authenticated splitting & reconstruction.
 */

#include "stego/capacity.h"
#include "stego/compress.h"
#include "stego/split.h"
#include "stego/stego.h"
#include "stego/carrier.h"
#include "stego/crypto.h"
#include "stego/image_loader.h"
#include "stego/image_writer.h"
#include "stego/error.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

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

static StegoImage *create_dummy_image(uint32_t width, uint32_t height) {
    StegoImage *img = NULL;
    StegoResult res = stego_image_create(width, height, 3, STEGO_FORMAT_PNG, &img);
    if (res != STEGO_OK || !img) return NULL;
    for (size_t i = 0; i < img->data_size; i++) {
        img->pixels[i] = (uint8_t)((i * 41 + 13) & 0xFF);
    }
    return img;
}

static bool save_dummy_png(const char *path, uint32_t width, uint32_t height) {
    StegoImage *img = create_dummy_image(width, height);
    if (!img) return false;
    StegoResult res = stego_image_save(path, img, STEGO_FORMAT_PNG);
    stego_image_free(img);
    return (res == STEGO_OK);
}

static bool write_test_file(const char *path, const uint8_t *data, size_t size) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return false;
    size_t written = fwrite(data, 1, size, fp);
    fclose(fp);
    return (written == size);
}

static bool read_test_file(const char *path, uint8_t **out_data, size_t *out_size) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz < 0) { fclose(fp); return false; }
    uint8_t *buf = (uint8_t *)malloc(sz > 0 ? sz : 1);
    if (!buf) { fclose(fp); return false; }
    if (sz > 0) fread(buf, 1, sz, fp);
    fclose(fp);
    *out_data = buf;
    *out_size = (size_t)sz;
    return true;
}

/* 1. Payload smaller than capacity */
static bool test_payload_smaller_than_capacity(void) {
    const char *cover_path = "tmp_cap_cover.png";
    const char *secret_path = "tmp_cap_secret.txt";
    const char *stego_path = "tmp_cap_stego.png";
    const char *extract_path = "tmp_cap_extracted.txt";

    if (!save_dummy_png(cover_path, 80, 80)) return false;
    const char *msg = "Confidential test payload smaller than capacity.";
    if (!write_test_file(secret_path, (const uint8_t *)msg, strlen(msg))) return false;

    StegoCarrier *carrier = NULL;
    if (stego_carrier_open(cover_path, false, &carrier) != STEGO_OK) return false;

    StegoCapacityAssessment assess;
    stego_assess_capacity(carrier, "tmp_cap_secret.txt", strlen(msg), true, false, 1, &assess);
    stego_carrier_close(carrier);

    if (!assess.fits) return false;
    if (assess.additional_required != 0) return false;

    StegoResult res = stego_hide_file_unified_advanced(cover_path, stego_path, secret_path,
                                                       "StrongPass123", false, false, 1);
    if (res != STEGO_OK) return false;

    res = stego_extract_file_unified_secure(stego_path, extract_path, "StrongPass123", false);
    if (res != STEGO_OK) return false;

    uint8_t *rec_data = NULL;
    size_t rec_sz = 0;
    if (!read_test_file(extract_path, &rec_data, &rec_sz)) return false;
    bool match = (rec_sz == strlen(msg) && memcmp(rec_data, msg, rec_sz) == 0);

    free(rec_data);
    remove(cover_path);
    remove(secret_path);
    remove(stego_path);
    remove(extract_path);
    return match;
}

/* 2. Payload exactly at capacity */
static bool test_payload_exactly_at_capacity(void) {
    const char *cover_path = "tmp_exact_cover.png";
    const char *secret_path = "tmp_exact_secret.bin";
    const char *stego_path = "tmp_exact_stego.png";
    const char *extract_path = "tmp_exact_extracted.bin";

    uint32_t w = 40, h = 40;
    if (!save_dummy_png(cover_path, w, h)) return false;

    StegoCarrier *carrier = NULL;
    if (stego_carrier_open(cover_path, false, &carrier) != STEGO_OK) return false;

    size_t raw_cap = carrier->max_capacity(carrier);
    size_t fil1_overhead = 48 + strlen("tmp_exact_secret.bin") + strlen("application/octet-stream");
    size_t max_payload = (raw_cap > fil1_overhead) ? (raw_cap - fil1_overhead) : 0;

    StegoCapacityAssessment assess;
    stego_assess_capacity(carrier, "tmp_exact_secret.bin", max_payload, false, false, 1, &assess);
    stego_carrier_close(carrier);

    if (!assess.fits || assess.additional_required != 0) {
        return false;
    }

    uint8_t *exact_buf = (uint8_t *)malloc(max_payload);
    for (size_t i = 0; i < max_payload; i++) exact_buf[i] = (uint8_t)(i ^ 0xAA);
    if (!write_test_file(secret_path, exact_buf, max_payload)) {
        free(exact_buf);
        return false;
    }

    StegoResult res = stego_hide_file_unified_advanced(cover_path, stego_path, secret_path,
                                                       NULL, false, false, 1);
    if (res != STEGO_OK) { free(exact_buf); return false; }

    res = stego_extract_file_unified_secure(stego_path, extract_path, NULL, false);
    if (res != STEGO_OK) { free(exact_buf); return false; }

    uint8_t *rec_data = NULL;
    size_t rec_sz = 0;
    if (!read_test_file(extract_path, &rec_data, &rec_sz)) { free(exact_buf); return false; }
    bool match = (rec_sz == max_payload && memcmp(rec_data, exact_buf, max_payload) == 0);

    free(exact_buf);
    free(rec_data);
    remove(cover_path);
    remove(secret_path);
    remove(stego_path);
    remove(extract_path);
    return match;
}

/* 3. Payload larger than capacity: assert exact error message and shortfall */
static bool test_payload_larger_than_capacity(void) {
    const char *cover_path = "tmp_small_cover.png";
    const char *secret_path = "tmp_large_secret.bin";
    const char *stego_path = "tmp_should_fail_stego.png";

    uint32_t w = 20, h = 20; // 400 pixels * 3 channels / 8 = 150 bytes raw capacity
    if (!save_dummy_png(cover_path, w, h)) return false;

    StegoCarrier *carrier = NULL;
    if (stego_carrier_open(cover_path, false, &carrier) != STEGO_OK) return false;

    size_t large_size = 1000; // Much larger than 150 bytes
    uint8_t large_buf[1000];
    memset(large_buf, 0x42, sizeof(large_buf));
    if (!write_test_file(secret_path, large_buf, sizeof(large_buf))) {
        stego_carrier_close(carrier);
        return false;
    }

    StegoCapacityAssessment assess;
    stego_assess_capacity(carrier, "tmp_large_secret.bin", large_size, true, false, 1, &assess);
    stego_carrier_close(carrier);

    /* Requirement 2: Exact error message */
    if (assess.fits != false) return false;
    if (strcmp(assess.error_summary, "This image does not have enough space for the selected secret.") != 0) {
        printf("\n[ERROR] assess.error_summary mismatch: got '%s'\n", assess.error_summary);
        return false;
    }

    /* Requirement 3: Additional space and recommended dimensions */
    if (assess.additional_required == 0) return false;
    if (assess.rec_min_width == 0 || assess.rec_min_height == 0) return false;

    /* Embedding must fail with STEGO_ERR_CAPACITY_EXCEEDED */
    StegoResult res = stego_hide_file_unified_advanced(cover_path, stego_path, secret_path,
                                                       "Pass123", false, false, 1);
    if (res != STEGO_ERR_CAPACITY_EXCEEDED) {
        printf("\n[ERROR] Expected STEGO_ERR_CAPACITY_EXCEEDED, got %d\n", res);
        return false;
    }

    remove(cover_path);
    remove(secret_path);
    remove(stego_path);
    return true;
}

/* 4. Compression reducing payload size */
static bool test_compression_reducing_payload(void) {
    const char *test_text = "This is a redundant string designed for high compressibility. "
                            "Antigravity steganography privacy toolkit Deflate compression testing. "
                            "Lossless compression enables larger payloads inside smaller carriers. ";
    size_t text_len = strlen(test_text);
    size_t big_len = text_len * 40; // ~5 KB
    uint8_t *big_payload = (uint8_t *)malloc(big_len);
    for (size_t i = 0; i < 40; i++) {
        memcpy(big_payload + i * text_len, test_text, text_len);
    }

    uint8_t *compressed = NULL;
    size_t comp_len = 0;
    bool was_compressed = false;
    StegoResult res = stego_compress_payload_if_beneficial(big_payload, big_len, &compressed, &comp_len, &was_compressed);
    if (res != STEGO_OK || !was_compressed || !compressed) {
        free(big_payload);
        return false;
    }

    if (comp_len >= big_len) {
        free(big_payload);
        free(compressed);
        return false;
    }

    uint8_t *decompressed = NULL;
    size_t decomp_len = 0;
    bool was_decomp = false;
    res = stego_decompress_payload_if_packed(compressed, comp_len, &decompressed, &decomp_len, &was_decomp);
    if (res != STEGO_OK || !was_decomp || !decompressed) {
        free(big_payload);
        free(compressed);
        return false;
    }

    bool match = (decomp_len == big_len && memcmp(decompressed, big_payload, big_len) == 0);
    free(big_payload);
    free(compressed);
    free(decompressed);
    return match;
}

/* 5. Compression on already-compressed files */
static bool test_compression_already_compressed_clean(void) {
    /* ZIP file header magic */
    uint8_t zip_header[64] = { 'P', 'K', 0x03, 0x04, 0x14, 0x00, 0x00, 0x00 };
    for (size_t i = 8; i < 64; i++) zip_header[i] = (uint8_t)(i * 7);

    if (!stego_is_already_compressed_format("archive.zip")) {
        return false;
    }

    uint8_t *compressed = NULL;
    size_t comp_len = 0;
    bool was_compressed = false;
    StegoResult res = stego_compress_payload_if_beneficial(zip_header, sizeof(zip_header), &compressed, &comp_len, &was_compressed);
    /* Should cleanly skip compression and leave payload uncompressed */
    if (res != STEGO_OK || was_compressed) {
        if (compressed) free(compressed);
        return false;
    }
    if (compressed) free(compressed);

    return true;
}

/* 6. Multi-image split and extract roundtrip */
static bool test_multi_image_split_and_extract_roundtrip(void) {
    const char *covers[3] = { "tmp_split_c1.png", "tmp_split_c2.png", "tmp_split_c3.png" };
    for (int i = 0; i < 3; i++) {
        if (!save_dummy_png(covers[i], 120, 120)) return false;
    }

    const char *secret_path = "tmp_split_secret.txt";
    const char *secret_text = "Multi-Image Steganography: Secret partitioned across 3 carrier images "
                              "using Argon2id key derivation, AES-256-GCM AEAD, and SHA-256 integrity binding.";
    size_t secret_len = strlen(secret_text);
    if (!write_test_file(secret_path, (const uint8_t *)secret_text, secret_len)) return false;

    StegoManifest manifest;
    char err_buf[512] = {0};
    StegoResult res = stego_split_embed(secret_path, covers, 3, "tmp_out_part",
                                        "SplitPass2026", false, 1, &manifest, err_buf, sizeof(err_buf));
    if (res != STEGO_OK) {
        printf("\n[ERROR] stego_split_embed failed: %s\n", err_buf);
        return false;
    }

    if (manifest.total_parts != 3) return false;

    /* Reconstruct from all 3 parts */
    const char *part_paths[3];
    for (int i = 0; i < 3; i++) part_paths[i] = manifest.parts[i].part_path;

    const char *rec_path = "tmp_split_reconstructed.txt";
    res = stego_split_extract(part_paths, 3, rec_path, "SplitPass2026", err_buf, sizeof(err_buf));
    if (res != STEGO_OK) {
        printf("\n[ERROR] stego_split_extract failed: %s\n", err_buf);
        return false;
    }

    uint8_t *rec_data = NULL;
    size_t rec_sz = 0;
    if (!read_test_file(rec_path, &rec_data, &rec_sz)) return false;
    bool match = (rec_sz == secret_len && memcmp(rec_data, secret_text, secret_len) == 0);

    free(rec_data);
    for (int i = 0; i < 3; i++) {
        remove(covers[i]);
        remove(manifest.parts[i].part_path);
    }
    remove("tmp_out_part_manifest.json");
    remove(secret_path);
    remove(rec_path);
    return match;
}

/* 7. Missing part rejection */
static bool test_split_missing_part_rejection(void) {
    const char *covers[3] = { "tmp_miss_c1.png", "tmp_miss_c2.png", "tmp_miss_c3.png" };
    for (int i = 0; i < 3; i++) {
        if (!save_dummy_png(covers[i], 100, 100)) return false;
    }

    const char *secret_path = "tmp_miss_secret.txt";
    const char *msg = "Missing part test data payload.";
    if (!write_test_file(secret_path, (const uint8_t *)msg, strlen(msg))) return false;

    StegoManifest manifest;
    char err_buf[512] = {0};
    StegoResult res = stego_split_embed(secret_path, covers, 3, "tmp_miss_part",
                                        "Pass1234", false, 1, &manifest, err_buf, sizeof(err_buf));
    if (res != STEGO_OK) return false;

    /* Provide only 2 of the 3 parts */
    const char *only_two[2] = { manifest.parts[0].part_path, manifest.parts[1].part_path };
    const char *rec_path = "tmp_miss_recovered.txt";
    res = stego_split_extract(only_two, 2, rec_path, "Pass1234", err_buf, sizeof(err_buf));

    /* Extraction MUST fail */
    bool failed = (res != STEGO_OK);

    for (int i = 0; i < 3; i++) {
        remove(covers[i]);
        remove(manifest.parts[i].part_path);
    }
    remove("tmp_miss_part_manifest.json");
    remove(secret_path);
    remove(rec_path);
    return failed;
}

/* 8. Wrong order handling (should reorder and reconstruct cleanly) */
static bool test_split_wrong_order_handling(void) {
    const char *covers[3] = { "tmp_ord_c1.png", "tmp_ord_c2.png", "tmp_ord_c3.png" };
    for (int i = 0; i < 3; i++) {
        if (!save_dummy_png(covers[i], 100, 100)) return false;
    }

    const char *secret_path = "tmp_ord_secret.txt";
    const char *msg = "Payload to test shuffled order reconstruction.";
    if (!write_test_file(secret_path, (const uint8_t *)msg, strlen(msg))) return false;

    StegoManifest manifest;
    char err_buf[512] = {0};
    StegoResult res = stego_split_embed(secret_path, covers, 3, "tmp_ord_part",
                                        "OrderPass", false, 1, &manifest, err_buf, sizeof(err_buf));
    if (res != STEGO_OK) return false;

    /* Reorder: Part 3, Part 1, Part 2 */
    const char *shuffled[3] = { manifest.parts[2].part_path, manifest.parts[0].part_path, manifest.parts[1].part_path };
    const char *rec_path = "tmp_ord_recovered.txt";
    res = stego_split_extract(shuffled, 3, rec_path, "OrderPass", err_buf, sizeof(err_buf));
    if (res != STEGO_OK) return false;

    uint8_t *rec_data = NULL;
    size_t rec_sz = 0;
    if (!read_test_file(rec_path, &rec_data, &rec_sz)) return false;
    bool match = (rec_sz == strlen(msg) && memcmp(rec_data, msg, rec_sz) == 0);

    free(rec_data);
    for (int i = 0; i < 3; i++) {
        remove(covers[i]);
        remove(manifest.parts[i].part_path);
    }
    remove("tmp_ord_part_manifest.json");
    remove(secret_path);
    remove(rec_path);
    return match;
}

/* 9. Corrupted part rejection */
static bool test_split_corrupted_part_rejection(void) {
    const char *covers[2] = { "tmp_cor_c1.png", "tmp_cor_c2.png" };
    for (int i = 0; i < 2; i++) {
        if (!save_dummy_png(covers[i], 100, 100)) return false;
    }

    const char *secret_path = "tmp_cor_secret.txt";
    const char *msg = "Corruption test secret payload.";
    if (!write_test_file(secret_path, (const uint8_t *)msg, strlen(msg))) return false;

    StegoManifest manifest;
    char err_buf[512] = {0};
    StegoResult res = stego_split_embed(secret_path, covers, 2, "tmp_cor_part",
                                        "CorruptPass", false, 1, &manifest, err_buf, sizeof(err_buf));
    if (res != STEGO_OK) return false;

    /* Corrupt Part 1 by overwriting arbitrary bytes in file */
    FILE *fp = fopen(manifest.parts[0].part_path, "r+b");
    if (!fp) return false;
    fseek(fp, 100, SEEK_SET);
    uint8_t garbage[16] = { 0xFF, 0x00, 0xAA, 0x55, 0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78 };
    fwrite(garbage, 1, sizeof(garbage), fp);
    fclose(fp);

    const char *parts[2] = { manifest.parts[0].part_path, manifest.parts[1].part_path };
    const char *rec_path = "tmp_cor_recovered.txt";
    res = stego_split_extract(parts, 2, rec_path, "CorruptPass", err_buf, sizeof(err_buf));

    /* Extraction MUST fail */
    bool failed = (res != STEGO_OK);

    for (int i = 0; i < 2; i++) {
        remove(covers[i]);
        remove(manifest.parts[i].part_path);
    }
    remove("tmp_cor_part_manifest.json");
    remove(secret_path);
    remove(rec_path);
    return failed;
}

/* 10. Wrong password rejection on multi-part */
static bool test_split_wrong_password_rejection(void) {
    const char *covers[2] = { "tmp_pw_c1.png", "tmp_pw_c2.png" };
    for (int i = 0; i < 2; i++) {
        if (!save_dummy_png(covers[i], 100, 100)) return false;
    }

    const char *secret_path = "tmp_pw_secret.txt";
    const char *msg = "Authentication test secret payload.";
    if (!write_test_file(secret_path, (const uint8_t *)msg, strlen(msg))) return false;

    StegoManifest manifest;
    char err_buf[512] = {0};
    StegoResult res = stego_split_embed(secret_path, covers, 2, "tmp_pw_part",
                                        "CorrectPassword", false, 1, &manifest, err_buf, sizeof(err_buf));
    if (res != STEGO_OK) return false;

    const char *parts[2] = { manifest.parts[0].part_path, manifest.parts[1].part_path };
    const char *rec_path = "tmp_pw_recovered.txt";
    res = stego_split_extract(parts, 2, rec_path, "WRONGPassword", err_buf, sizeof(err_buf));

    /* Extraction MUST fail with auth error */
    bool failed = (res != STEGO_OK);

    for (int i = 0; i < 2; i++) {
        remove(covers[i]);
        remove(manifest.parts[i].part_path);
    }
    remove("tmp_pw_part_manifest.json");
    remove(secret_path);
    remove(rec_path);
    return failed;
}

/* 11. Atomic failure cleanup: zero output files left on extraction failure */
static bool test_split_atomic_failure_cleanup(void) {
    const char *covers[2] = { "tmp_atom_c1.png", "tmp_atom_c2.png" };
    for (int i = 0; i < 2; i++) {
        if (!save_dummy_png(covers[i], 100, 100)) return false;
    }

    const char *secret_path = "tmp_atom_secret.txt";
    const char *msg = "Atomic failure test secret payload.";
    if (!write_test_file(secret_path, (const uint8_t *)msg, strlen(msg))) return false;

    StegoManifest manifest;
    char err_buf[512] = {0};
    StegoResult res = stego_split_embed(secret_path, covers, 2, "tmp_atom_part",
                                        "AtomPass", false, 1, &manifest, err_buf, sizeof(err_buf));
    if (res != STEGO_OK) return false;

    const char *parts[2] = { manifest.parts[0].part_path, manifest.parts[1].part_path };
    const char *rec_path = "tmp_atomic_recovered_should_not_exist.txt";
    remove(rec_path);

    /* Wrong password extraction */
    res = stego_split_extract(parts, 2, rec_path, "WrongPass", err_buf, sizeof(err_buf));
    if (res == STEGO_OK) return false;

    /* Verify the output file does NOT exist on disk */
    FILE *fp = fopen(rec_path, "rb");
    bool no_file_left = (fp == NULL);
    if (fp) fclose(fp);

    for (int i = 0; i < 2; i++) {
        remove(covers[i]);
        remove(manifest.parts[i].part_path);
    }
    remove("tmp_atom_part_manifest.json");
    remove(secret_path);
    remove(rec_path);
    return no_file_left;
}

/* 12. High-capacity mode (2-bit and 3-bit LSB) */
static bool test_high_capacity_bits_roundtrip(void) {
    const char *cover_path = "tmp_hicap_cover.png";
    const char *secret_path = "tmp_hicap_secret.txt";
    const char *stego_path = "tmp_hicap_stego.png";
    const char *extract_path = "tmp_hicap_extracted.txt";

    if (!save_dummy_png(cover_path, 60, 60)) return false;
    const char *msg = "High-capacity test using 2-bit and 3-bit embedding.";
    if (!write_test_file(secret_path, (const uint8_t *)msg, strlen(msg))) return false;

    /* Test 2-bit embedding */
    StegoResult res = stego_hide_file_unified_advanced(cover_path, stego_path, secret_path,
                                                       "Pass2Bit", false, false, 2);
    if (res != STEGO_OK) return false;

    res = stego_extract_file_unified_secure(stego_path, extract_path, "Pass2Bit", false);
    if (res != STEGO_OK) return false;

    uint8_t *rec_data = NULL;
    size_t rec_sz = 0;
    if (!read_test_file(extract_path, &rec_data, &rec_sz)) return false;
    bool match2 = (rec_sz == strlen(msg) && memcmp(rec_data, msg, rec_sz) == 0);
    free(rec_data);
    remove(stego_path);
    remove(extract_path);

    /* Test 3-bit embedding */
    res = stego_hide_file_unified_advanced(cover_path, stego_path, secret_path,
                                           "Pass3Bit", false, false, 3);
    if (res != STEGO_OK) return false;

    res = stego_extract_file_unified_secure(stego_path, extract_path, "Pass3Bit", false);
    if (res != STEGO_OK) return false;

    if (!read_test_file(extract_path, &rec_data, &rec_sz)) return false;
    bool match3 = (rec_sz == strlen(msg) && memcmp(rec_data, msg, rec_sz) == 0);
    free(rec_data);

    remove(cover_path);
    remove(secret_path);
    remove(stego_path);
    remove(extract_path);
    return (match2 && match3);
}

int main(void) {
    printf("====================================================\n");
    printf("     CAPACITY, COMPRESSION & SPLIT TEST SUITE       \n");
    printf("====================================================\n\n");

    RUN_TEST(test_payload_smaller_than_capacity);
    RUN_TEST(test_payload_exactly_at_capacity);
    RUN_TEST(test_payload_larger_than_capacity);
    RUN_TEST(test_compression_reducing_payload);
    RUN_TEST(test_compression_already_compressed_clean);
    RUN_TEST(test_multi_image_split_and_extract_roundtrip);
    RUN_TEST(test_split_missing_part_rejection);
    RUN_TEST(test_split_wrong_order_handling);
    RUN_TEST(test_split_corrupted_part_rejection);
    RUN_TEST(test_split_wrong_password_rejection);
    RUN_TEST(test_split_atomic_failure_cleanup);
    RUN_TEST(test_high_capacity_bits_roundtrip);

    printf("\n====================================================\n");
    printf("Results: %d/%d tests passed\n", g_tests_passed, g_tests_run);
    printf("====================================================\n");

    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
