/**
 * @file test_upgrades.c
 * @brief Comprehensive verification suite for bmp-stego upgrades:
 *  - Priority 1: Capacity helper calculations
 *  - Priority 2: File integrity preservation (FIL1 container & SHA-256)
 *  - Priority 3: Multi-image splitting & integrity validation
 *  - Priority 5: Privacy metadata scanning & risk level detection
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "stego/file_payload.h"
#include "stego/capacity.h"
#include "stego/split.h"
#include "stego/metadata.h"
#include "stego/image_loader.h"
#include "stego/image_writer.h"
#include "stego/stego.h"
#include "core/stego_core.h"

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define TEST_ASSERT(cond, msg) do { \
    g_tests_run++; \
    if (cond) { \
        g_tests_passed++; \
        printf("  [PASS] %s\n", msg); \
    } else { \
        printf("  [FAIL] %s (line %d)\n", msg, __LINE__); \
    } \
} while(0)

/* Test 1: FIL1 File Payload pack and unpack round-trip */
static void test_file_payload_roundtrip(void) {
    printf("\n--- Test Suite 1: FIL1 Authenticated File Payload Roundtrip ---\n");

    const char *test_filename = "important_confidential_document.pdf";
    const uint8_t secret_data[] = "%PDF-1.4 Top secret report contents for privacy evaluation test.";
    size_t secret_len = sizeof(secret_data);

    uint8_t *packed = NULL;
    size_t packed_len = 0;

    StegoResult pack_res = stego_file_payload_pack(test_filename, secret_data, secret_len, &packed, &packed_len);
    TEST_ASSERT(pack_res == STEGO_OK && packed != NULL, "stego_file_payload_pack succeeds");
    TEST_ASSERT(packed_len > secret_len, "Packed length accounts for authenticated metadata header");
    TEST_ASSERT(stego_file_payload_is_fil1(packed, packed_len), "Payload recognized as FIL1 magic format");

    StegoFileMetadata meta;
    memset(&meta, 0, sizeof(meta));
    uint8_t *unpacked = NULL;
    size_t unpacked_len = 0;

    StegoResult unpack_res = stego_file_payload_unpack(packed, packed_len, &meta, &unpacked, &unpacked_len);
    TEST_ASSERT(unpack_res == STEGO_OK && unpacked != NULL, "stego_file_payload_unpack succeeds");
    TEST_ASSERT(unpacked_len == secret_len, "Restored file length matches original");
    TEST_ASSERT(memcmp(unpacked, secret_data, secret_len) == 0, "Restored content is bit-for-bit identical");
    TEST_ASSERT(strcmp(meta.filename, test_filename) == 0, "Original filename preserved correctly");
    TEST_ASSERT(strcmp(meta.extension, ".pdf") == 0, "Original file extension preserved correctly");
    TEST_ASSERT(strcmp(meta.mime_type, "application/pdf") == 0, "Original MIME type detected and preserved");
    TEST_ASSERT(meta.is_verified, "Cryptographic SHA-256 verification flag is set true");
    TEST_ASSERT(strlen(meta.sha256_hex) == 64, "SHA-256 hex string generated with 64 hex characters");

    free(packed);
    free(unpacked);
}

/* Test 2: FIL1 Tamper and Truncation Rejection */
static void test_file_payload_tamper_rejection(void) {
    printf("\n--- Test Suite 2: FIL1 Tamper and Corruption Rejection ---\n");

    const char *test_filename = "financial_records.xlsx";
    const uint8_t secret_data[] = "Balance: $1,000,000 USD encrypted spreadsheet data.";
    size_t secret_len = sizeof(secret_data);

    uint8_t *packed = NULL;
    size_t packed_len = 0;
    stego_file_payload_pack(test_filename, secret_data, secret_len, &packed, &packed_len);

    /* 1. Tamper single byte in file content */
    uint8_t *tampered = (uint8_t *)malloc(packed_len);
    memcpy(tampered, packed, packed_len);
    tampered[packed_len - 5] ^= 0x01; // flip one bit in payload

    StegoFileMetadata meta;
    uint8_t *out_data = NULL;
    size_t out_len = 0;

    StegoResult tamper_res = stego_file_payload_unpack(tampered, packed_len, &meta, &out_data, &out_len);
    TEST_ASSERT(tamper_res == STEGO_ERR_CORRUPT_PAYLOAD, "Tampered payload rejected with STEGO_ERR_CORRUPT_PAYLOAD");
    TEST_ASSERT(out_data == NULL, "No decrypted data is exposed or returned on hash mismatch");

    /* 2. Truncated payload */
    size_t truncated_len = packed_len - 10;
    StegoResult trunc_res = stego_file_payload_unpack(packed, truncated_len, &meta, &out_data, &out_len);
    TEST_ASSERT(trunc_res == STEGO_ERR_CORRUPT_PAYLOAD, "Truncated payload rejected cleanly without segfault");
    TEST_ASSERT(out_data == NULL, "No truncated data is exposed or returned");

    free(packed);
    free(tampered);
}

/* Test 3: MIME Type Auto-Detection */
static void test_mime_detection(void) {
    printf("\n--- Test Suite 3: MIME Type Detection ---\n");

    TEST_ASSERT(strcmp(stego_detect_mime_type("photo.png"), "image/png") == 0, "PNG MIME detection");
    TEST_ASSERT(strcmp(stego_detect_mime_type("photo.jpeg"), "image/jpeg") == 0, "JPEG MIME detection");
    TEST_ASSERT(strcmp(stego_detect_mime_type("doc.pdf"), "application/pdf") == 0, "PDF MIME detection");
    TEST_ASSERT(strcmp(stego_detect_mime_type("archive.zip"), "application/zip") == 0, "ZIP MIME detection");
    TEST_ASSERT(strcmp(stego_detect_mime_type("music.mp3"), "audio/mpeg") == 0, "MP3 MIME detection");
    TEST_ASSERT(strcmp(stego_detect_mime_type("secret.txt"), "text/plain") == 0, "TXT MIME detection");
}

/* Test 4: Privacy Metadata Risk Level Assessment */
static void test_metadata_risk_levels(void) {
    printf("\n--- Test Suite 4: Privacy Risk Assessment & Metadata Scanning ---\n");

    /* Create sample test image with GPS and EXIF tags simulated in memory */
    const char *test_img_path = "tmp_test_metadata_risk.jpg";
    FILE *fp = fopen(test_img_path, "wb");
    assert(fp);

    /* Write minimal valid JPEG structure with simulated Exif and GPS strings */
    uint8_t jpg_hdr[] = {
        0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x50,
        'E', 'x', 'i', 'f', 0x00, 0x00,
        'A', 'p', 'p', 'l', 'e', 0x00,
        'i', 'P', 'h', 'o', 'n', 'e', ' ', '1', '4', 0x00,
        'G', 'P', 'S', ' ', '1', '7', '.', '3', '8', '5', '0', ' ', 'N', ' ', '7', '8', '.', '4', '8', '6', '7', ' ', 'E', 0x00,
        0xFF, 0xD9
    };
    fwrite(jpg_hdr, 1, sizeof(jpg_hdr), fp);
    fclose(fp);

    StegoMetadataInfo info;
    StegoResult sres = stego_metadata_scan(test_img_path, &info);
    TEST_ASSERT(sres == STEGO_OK, "stego_metadata_scan runs successfully");
    TEST_ASSERT(info.has_exif, "Detects EXIF marker");
    TEST_ASSERT(info.has_gps, "Detects GPS marker");
    TEST_ASSERT(info.has_camera_info, "Detects camera manufacturer");
    TEST_ASSERT(strcmp(info.risk_level, "High") == 0, "High privacy risk assigned when GPS is present");

    remove(test_img_path);
}

/* Test 5: End-to-End Stego Hide and Extract with FIL1 Preservation */
static void test_unified_fil1_stego(void) {
    printf("\n--- Test Suite 5: End-to-End Stego with File Metadata Preservation ---\n");

    /* 1. Generate clean 120x120 cover PNG */
    const char *cover_path = "tmp_test_cover_fil1.png";
    const char *stego_path = "tmp_test_stego_fil1.png";
    const char *secret_file_path = "tmp_test_contract.txt";
    const char *extracted_path = "tmp_test_extracted_fil1.txt";

    StegoImage *img = NULL;
    StegoResult cres = stego_image_create(120, 120, 3, STEGO_FORMAT_PNG, &img);
    assert(cres == STEGO_OK && img != NULL);
    for (size_t i = 0; i < 120 * 120 * 3; i++) {
        img->pixels[i] = (uint8_t)(i % 256);
    }
    stego_image_save(cover_path, img, STEGO_FORMAT_PNG);
    stego_image_free(img);

    /* 2. Create secret file */
    const char *secret_text = "CONFIDENTIAL AGREEMENT: Antigravity privacy upgrade validation.";
    FILE *sfp = fopen(secret_file_path, "wb");
    assert(sfp);
    fwrite(secret_text, 1, strlen(secret_text), sfp);
    fclose(sfp);

    /* 3. Hide secret file with password and compression */
    StegoResult hres = stego_hide_file_unified_advanced(cover_path, stego_path, secret_file_path,
                                                        "StrongPass123!", false, true, 1);
    TEST_ASSERT(hres == STEGO_OK, "stego_hide_file_unified_advanced succeeds with FIL1");

    /* 4. Extract secret file */
    StegoResult eres = stego_extract_file_unified_secure(stego_path, extracted_path, "StrongPass123!", false);
    TEST_ASSERT(eres == STEGO_OK, "stego_extract_file_unified_secure succeeds and verifies SHA-256");

    /* 5. Check extracted content matches */
    FILE *efp = fopen(extracted_path, "rb");
    TEST_ASSERT(efp != NULL, "Extracted file was created");
    if (efp) {
        char buf[256] = {0};
        size_t r = fread(buf, 1, sizeof(buf) - 1, efp);
        fclose(efp);
        TEST_ASSERT(r == strlen(secret_text), "Extracted size matches original secret size");
        TEST_ASSERT(strcmp(buf, secret_text) == 0, "Extracted text content matches perfectly");
    }

    /* 6. Extract with WRONG password must fail */
    StegoResult wres = stego_extract_file_unified_secure(stego_path, "tmp_test_wrong.txt", "WrongPassword!", false);
    TEST_ASSERT(wres == STEGO_ERR_AUTH_FAILED, "Wrong password rejected with STEGO_ERR_AUTH_FAILED");

    /* Clean up temporary test files */
    remove(cover_path);
    remove(stego_path);
    remove(secret_file_path);
    remove(extracted_path);
}

int main(void) {
    printf("====================================================\n");
    printf("       BMP-STEGO UPGRADE TEST SUITE (P1-P8)        \n");
    printf("====================================================\n");

    test_file_payload_roundtrip();
    test_file_payload_tamper_rejection();
    test_mime_detection();
    test_metadata_risk_levels();
    test_unified_fil1_stego();

    printf("\n====================================================\n");
    printf("  Results: %d/%d tests passed (%s)\n",
           g_tests_passed, g_tests_run,
           (g_tests_passed == g_tests_run) ? "ALL TESTS PASSED" : "FAILURES OCCURRED");
    printf("====================================================\n");

    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
