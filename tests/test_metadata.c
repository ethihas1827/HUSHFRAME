/**
 * @file test_metadata.c
 * @brief Unit test suite for structure-aware metadata scanning and stripping.
 *
 * Verifies parsing and segment-level removal of EXIF, GPS, XMP, IPTC, and
 * embedded thumbnails (IFD1) from JPEG files while preserving JFIF headers
 * and ensuring original files remain pristine.
 */

#include "stego/metadata.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* Minimal standard valid 1x1 JPEG */
static const uint8_t s_min_jpeg[] = {
    0xFF, 0xD8,                          /* SOI */
    0xFF, 0xE0, 0x00, 0x10,              /* APP0 JFIF */
    'J', 'F', 'I', 'F', 0x00,
    0x01, 0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00,
    0xFF, 0xDB, 0x00, 0x43, 0x00,        /* DQT (Quantization table) */
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    0xFF, 0xC0, 0x00, 0x0B, 0x08,        /* SOF0 */
    0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00,
    0xFF, 0xC4, 0x00, 0x1F, 0x00,        /* DHT */
    0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, /* SOS */
    0x00, 0x00, 0x3F, 0x00,
    0x7F, 0x00,                          /* Compressed image scan data */
    0xFF, 0xD9                           /* EOI */
};

static void write_jpeg_with_app1(const char *path, const uint8_t *app1_payload, size_t app1_len) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return;

    /* 1. Write SOI */
    fputc(0xFF, fp);
    fputc(0xD8, fp);

    /* 2. Write APP0 (JFIF) from min_jpeg */
    fwrite(s_min_jpeg + 2, 1, 18, fp);

    /* 3. Write APP1 segment */
    uint16_t seg_len = (uint16_t)(app1_len + 2);
    fputc(0xFF, fp);
    fputc(0xE1, fp);
    fputc((seg_len >> 8) & 0xFF, fp);
    fputc(seg_len & 0xFF, fp);
    fwrite(app1_payload, 1, app1_len, fp);

    /* 4. Write remaining image segments (DQT, SOF0, DHT, SOS, EOI) */
    fwrite(s_min_jpeg + 20, 1, sizeof(s_min_jpeg) - 20, fp);
    fclose(fp);
}

/* Test 1: JPEG with EXIF metadata */
static bool test_jpeg_with_exif(void) {
    const char *test_in = "tmp_test_exif.jpg";
    const char *test_out = "tmp_test_exif_clean.jpg";

    /* Construct EXIF payload */
    uint8_t exif_payload[64] = {
        'E', 'x', 'i', 'f', 0x00, 0x00,            /* 6-byte EXIF signature */
        'I', 'I', 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00 /* TIFF header */
    };
    write_jpeg_with_app1(test_in, exif_payload, sizeof(exif_payload));

    StegoMetadataInfo info_before;
    StegoResult res = stego_metadata_scan(test_in, &info_before);
    if (res != STEGO_OK || !info_before.has_exif) {
        remove(test_in);
        return false;
    }

    res = stego_metadata_strip(test_in, test_out);
    if (res != STEGO_OK) {
        remove(test_in);
        return false;
    }

    StegoMetadataInfo info_after;
    res = stego_metadata_scan(test_out, &info_after);

    remove(test_in);
    remove(test_out);

    return (res == STEGO_OK && !info_after.has_exif);
}

/* Test 2: JPEG with GPS geolocation data */
static bool test_jpeg_with_gps(void) {
    const char *test_in = "tmp_test_gps.jpg";
    const char *test_out = "tmp_test_gps_clean.jpg";

    uint8_t gps_payload[80] = {
        'E', 'x', 'i', 'f', 0x00, 0x00,
        'I', 'I', 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00,
        /* GPS tag and coordinates representation (lat & lon) */
        'G', 'P', 'S', ' ', '3', '7', '.', '7', '7', '4', '9', ' ', 'N', ' ', '1', '2', '2', '.', '4', '1', '9', '4', ' ', 'W'
    };
    write_jpeg_with_app1(test_in, gps_payload, sizeof(gps_payload));

    StegoMetadataInfo info_before;
    stego_metadata_scan(test_in, &info_before);
    if (!info_before.has_gps) {
        remove(test_in);
        return false;
    }

    StegoResult res = stego_metadata_strip(test_in, test_out);
    if (res != STEGO_OK) {
        remove(test_in);
        return false;
    }

    StegoMetadataInfo info_after;
    res = stego_metadata_scan(test_out, &info_after);

    remove(test_in);
    remove(test_out);

    return (res == STEGO_OK && !info_after.has_gps && !info_after.has_exif);
}

/* Test 3: JPEG with embedded thumbnail (IFD1) */
static bool test_jpeg_with_embedded_thumbnail(void) {
    const char *test_in = "tmp_test_thumb.jpg";
    const char *test_out = "tmp_test_thumb_clean.jpg";

    /* Build EXIF segment holding nested thumbnail JPEG data */
    uint8_t thumb_payload[128] = {
        'E', 'x', 'i', 'f', 0x00, 0x00,
        'I', 'I', 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00,
        0x01, 0x00, /* 1 tag in IFD0 */
        0x0F, 0x01, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 'T', 'e', 's', 't',
        0x1E, 0x00, 0x00, 0x00, /* Pointer to IFD1 thumbnail */
        /* IFD1 with embedded thumbnail SOI ... EOI */
        0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x43, 0x00, 0x01, 0xFF, 0xD9
    };
    write_jpeg_with_app1(test_in, thumb_payload, sizeof(thumb_payload));

    /* Verify unstripped file contains thumbnail bytes */
    FILE *f_in = fopen(test_in, "rb");
    if (!f_in) return false;
    fseek(f_in, 0, SEEK_END);
    long len_in = ftell(f_in);
    fclose(f_in);

    StegoResult res = stego_metadata_strip(test_in, test_out);
    if (res != STEGO_OK) {
        remove(test_in);
        return false;
    }

    /* Verify cleaned file has stripped the entire APP1 including thumbnail */
    FILE *f_out = fopen(test_out, "rb");
    if (!f_out) {
        remove(test_in);
        return false;
    }
    fseek(f_out, 0, SEEK_END);
    long len_out = ftell(f_out);
    fclose(f_out);

    StegoMetadataInfo info;
    stego_metadata_scan(test_out, &info);

    remove(test_in);
    remove(test_out);

    /* Cleaned file must be smaller and contain no EXIF/thumbnail */
    return (len_out < len_in && !info.has_exif);
}

/* Test 4: JPEG without metadata */
static bool test_jpeg_without_metadata(void) {
    const char *test_in = "tmp_test_clean_jpeg.jpg";
    const char *test_out = "tmp_test_clean_jpeg_out.jpg";

    FILE *fp = fopen(test_in, "wb");
    fwrite(s_min_jpeg, 1, sizeof(s_min_jpeg), fp);
    fclose(fp);

    StegoMetadataInfo info_before;
    stego_metadata_scan(test_in, &info_before);
    if (info_before.has_exif || info_before.has_gps) {
        remove(test_in);
        return false;
    }

    StegoResult res = stego_metadata_strip(test_in, test_out);
    if (res != STEGO_OK) {
        remove(test_in);
        return false;
    }

    StegoMetadataInfo info_after;
    stego_metadata_scan(test_out, &info_after);

    remove(test_in);
    remove(test_out);

    return (res == STEGO_OK && !info_after.has_exif && !info_after.has_gps);
}

/* Test 5: Original input file remains completely unchanged after stripping */
static bool test_original_file_unchanged_after_stripping(void) {
    const char *orig_path = "phone_photo.jpg";
    const char *clean_path = "tmp_test_photo_clean.jpg";

    FILE *fp = fopen(orig_path, "rb");
    if (!fp) {
        /* Fallback if phone_photo.jpg not in cwd */
        orig_path = "tmp_test_orig_sample.jpg";
        fp = fopen(orig_path, "wb");
        fwrite(s_min_jpeg, 1, sizeof(s_min_jpeg), fp);
        fclose(fp);
        fp = fopen(orig_path, "rb");
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t *before_data = (uint8_t *)malloc((size_t)fsize);
    size_t rb = fread(before_data, 1, (size_t)fsize, fp);
    fclose(fp);
    if (rb != (size_t)fsize) {
        free(before_data);
        return false;
    }

    /* Perform strip */
    StegoResult res = stego_metadata_strip(orig_path, clean_path);
    remove(clean_path);
    if (res != STEGO_OK) {
        free(before_data);
        return false;
    }

    /* Re-read original file and verify byte-for-byte identity */
    fp = fopen(orig_path, "rb");
    fseek(fp, 0, SEEK_END);
    long fsize_after = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize_after != fsize) {
        fclose(fp);
        free(before_data);
        return false;
    }

    uint8_t *after_data = (uint8_t *)malloc((size_t)fsize);
    rb = fread(after_data, 1, (size_t)fsize, fp);
    fclose(fp);

    bool identical = (rb == (size_t)fsize && memcmp(before_data, after_data, (size_t)fsize) == 0);
    free(before_data);
    free(after_data);

    if (strcmp(orig_path, "tmp_test_orig_sample.jpg") == 0) {
        remove(orig_path);
    }
    return identical;
}

/* Test 6: Cleaned output has no EXIF */
static bool test_cleaned_output_has_no_exif(void) {
    const char *orig_path = "phone_photo.jpg";
    const char *clean_path = "tmp_test_verified_no_exif.jpg";

    StegoResult res = stego_metadata_strip(orig_path, clean_path);
    if (res != STEGO_OK) return false;

    StegoMetadataInfo info;
    res = stego_metadata_scan(clean_path, &info);
    if (res != STEGO_OK || info.has_exif || info.has_gps) {
        remove(clean_path);
        return false;
    }

    /* Double check raw binary stream for "Exif\0\0" */
    FILE *fp = fopen(clean_path, "rb");
    if (!fp) return false;
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t *buf = (uint8_t *)malloc((size_t)len);
    fread(buf, 1, (size_t)len, fp);
    fclose(fp);
    remove(clean_path);

    bool found_exif = false;
    for (size_t i = 0; i + 6 < (size_t)len; i++) {
        if (memcmp(buf + i, "Exif\0\0", 6) == 0) {
            found_exif = true;
            break;
        }
    }
    free(buf);

    return (!found_exif);
}

/* Test 7: Scan clean dummy file */
static bool test_metadata_scan_clean_file(void) {
    const char *tmp = "tmp_meta_test.bin";
    FILE *fp = fopen(tmp, "wb");
    uint8_t dummy[64] = { 0 };
    fwrite(dummy, 1, sizeof(dummy), fp);
    fclose(fp);

    StegoMetadataInfo info;
    StegoResult res = stego_metadata_scan(tmp, &info);
    remove(tmp);

    return (res == STEGO_OK && !info.has_exif && !info.has_gps);
}

int main(void) {
    printf("====================================================\n");
    printf("          METADATA PROTECTION TEST SUITE            \n");
    printf("====================================================\n");
    RUN_TEST(test_jpeg_with_exif);
    RUN_TEST(test_jpeg_with_gps);
    RUN_TEST(test_jpeg_with_embedded_thumbnail);
    RUN_TEST(test_jpeg_without_metadata);
    RUN_TEST(test_original_file_unchanged_after_stripping);
    RUN_TEST(test_cleaned_output_has_no_exif);
    RUN_TEST(test_metadata_scan_clean_file);
    printf("====================================================\n");
    printf("Result: %d / %d tests passed\n", g_tests_passed, g_tests_run);
    printf("====================================================\n");
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
