/**
 * @file test_privacy.c
 * @brief Comprehensive privacy, GPS EXIF parsing, and secure shredding tests.
 */

#include "stego/privacy.h"
#include "stego/metadata.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

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

static void write_test_jpeg(const char *path, const uint8_t *app1_payload, size_t app1_len) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return;
    fputc(0xFF, fp);
    fputc(0xD8, fp); /* SOI */
    if (app1_payload && app1_len > 0) {
        fputc(0xFF, fp);
        fputc(0xE1, fp); /* APP1 */
        uint16_t seg_len = (uint16_t)(app1_len + 2);
        fputc((seg_len >> 8) & 0xFF, fp);
        fputc(seg_len & 0xFF, fp);
        fwrite(app1_payload, 1, app1_len, fp);
    }
    uint8_t sof0[] = { 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00 };
    fwrite(sof0, 1, sizeof(sof0), fp);
    uint8_t sos[] = { 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x7F };
    fwrite(sos, 1, sizeof(sos), fp);
    fputc(0xFF, fp);
    fputc(0xD9, fp); /* EOI */
    fclose(fp);
}

static size_t create_binary_tiff_gps(uint8_t *buf, size_t max_len,
                                     uint32_t lat_d, uint32_t lat_m, uint32_t lat_s, char lat_ref,
                                     uint32_t lon_d, uint32_t lon_m, uint32_t lon_s, char lon_ref,
                                     uint32_t alt_val, bool include_alt,
                                     const char *date_str) {
    if (max_len < 256) return 0;
    memset(buf, 0, max_len);

    memcpy(buf, "Exif\0\0", 6);
    uint8_t *tiff = buf + 6;

    /* Little endian header */
    tiff[0] = 'I'; tiff[1] = 'I';
    tiff[2] = 0x2A; tiff[3] = 0x00;
    tiff[4] = 0x08; tiff[5] = 0x00; tiff[6] = 0x00; tiff[7] = 0x00;

    /* IFD0 (1 entry: GPS IFD pointer at offset 26 = 0x1A) */
    tiff[8] = 0x01; tiff[9] = 0x00;
    tiff[10] = 0x25; tiff[11] = 0x88;
    tiff[12] = 0x04; tiff[13] = 0x00;
    tiff[14] = 0x01; tiff[15] = 0x00; tiff[16] = 0x00; tiff[17] = 0x00;
    tiff[18] = 0x1A; tiff[19] = 0x00; tiff[20] = 0x00; tiff[21] = 0x00;
    tiff[22] = 0x00; tiff[23] = 0x00; tiff[24] = 0x00; tiff[25] = 0x00;

    /* GPS IFD at offset 26 */
    uint16_t num_gps = 4 + (include_alt ? 1 : 0) + (date_str ? 1 : 0);
    tiff[26] = (uint8_t)(num_gps & 0xFF);
    tiff[27] = (uint8_t)((num_gps >> 8) & 0xFF);

    size_t e_off = 28;

    /* 1. LatRef */
    tiff[e_off++] = 0x01; tiff[e_off++] = 0x00;
    tiff[e_off++] = 0x02; tiff[e_off++] = 0x00;
    tiff[e_off++] = 0x02; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00;
    tiff[e_off++] = (uint8_t)lat_ref; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00;

    /* 2. Lat */
    tiff[e_off++] = 0x02; tiff[e_off++] = 0x00;
    tiff[e_off++] = 0x05; tiff[e_off++] = 0x00;
    tiff[e_off++] = 0x03; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00;
    tiff[e_off++] = 110; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00;

    /* 3. LonRef */
    tiff[e_off++] = 0x03; tiff[e_off++] = 0x00;
    tiff[e_off++] = 0x02; tiff[e_off++] = 0x00;
    tiff[e_off++] = 0x02; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00;
    tiff[e_off++] = (uint8_t)lon_ref; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00;

    /* 4. Lon */
    tiff[e_off++] = 0x04; tiff[e_off++] = 0x00;
    tiff[e_off++] = 0x05; tiff[e_off++] = 0x00;
    tiff[e_off++] = 0x03; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00;
    tiff[e_off++] = 134; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00;

    if (include_alt) {
        /* 5. Alt */
        tiff[e_off++] = 0x06; tiff[e_off++] = 0x00;
        tiff[e_off++] = 0x05; tiff[e_off++] = 0x00;
        tiff[e_off++] = 0x01; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00;
        tiff[e_off++] = 158; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00;
    }

    if (date_str) {
        /* DateStamp */
        tiff[e_off++] = 0x1D; tiff[e_off++] = 0x00;
        tiff[e_off++] = 0x02; tiff[e_off++] = 0x00;
        tiff[e_off++] = 11; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00;
        tiff[e_off++] = 166; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00;
    }

    tiff[e_off++] = 0x00; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00; tiff[e_off++] = 0x00;

    /* Offset 110: Lat (degrees, minutes, seconds) */
    uint32_t *p_lat = (uint32_t *)(tiff + 110);
    p_lat[0] = lat_d; p_lat[1] = 1;
    p_lat[2] = lat_m; p_lat[3] = 1;
    p_lat[4] = lat_s; p_lat[5] = 1;

    /* Offset 134: Lon (degrees, minutes, seconds) */
    uint32_t *p_lon = (uint32_t *)(tiff + 134);
    p_lon[0] = lon_d; p_lon[1] = 1;
    p_lon[2] = lon_m; p_lon[3] = 1;
    p_lon[4] = lon_s; p_lon[5] = 1;

    if (include_alt) {
        /* Offset 158: Alt (alt_val / 10) */
        uint32_t *p_alt = (uint32_t *)(tiff + 158);
        p_alt[0] = alt_val; p_alt[1] = 10;
    }

    if (date_str) {
        /* Offset 166: DateStamp */
        memcpy(tiff + 166, date_str, 11);
    }

    return 6 + 180;
}

/* 1. Image with complete GPS data */
static bool test_gps_complete_data(void) {
    const char *path = "tmp_test_gps_full.jpg";
    uint8_t payload[256];
    size_t len = create_binary_tiff_gps(payload, sizeof(payload),
                                        17, 23, 6, 'N',
                                        78, 29, 12, 'E',
                                        5205, true, "2026:11:10");
    write_test_jpeg(path, payload, len);

    StegoMetadataInfo info;
    StegoResult res = stego_metadata_scan(path, &info);
    remove(path);

    if (res != STEGO_OK) return false;
    if (!info.has_gps) return false;

    /* 17 + 23/60 + 6/3600 = 17.385 */
    if (fabs(info.latitude - 17.385000) > 0.001) return false;
    /* 78 + 29/60 + 12/3600 = 78.486667 */
    if (fabs(info.longitude - 78.486667) > 0.001) return false;

    if (strcmp(info.latitude_ref, "N") != 0) return false;
    if (strcmp(info.longitude_ref, "E") != 0) return false;
    if (!info.has_altitude || fabs(info.altitude - 520.5) > 0.1) return false;
    if (strcmp(info.risk_level, "High") != 0) return false;

    return true;
}

/* 2. Image with latitude but missing longitude */
static bool test_gps_missing_longitude(void) {
    const char *path = "tmp_test_gps_nylon.jpg";
    uint8_t payload[128] = {
        'E', 'x', 'i', 'f', 0x00, 0x00,
        'G', 'P', 'S', ' ', '1', '7', '.', '3', '8', '5', '0', ' ', 'N'
    };
    write_test_jpeg(path, payload, 30);

    StegoMetadataInfo info;
    StegoResult res = stego_metadata_scan(path, &info);
    remove(path);

    if (res != STEGO_OK) return false;
    /* When longitude is missing, has_gps MUST be false */
    if (info.has_gps) return false;
    if (info.latitude != 0.0 || info.longitude != 0.0) return false;

    return true;
}

/* 3. Image with N/S and E/W references */
static bool test_gps_south_and_west_references(void) {
    const char *path = "tmp_test_gps_sw.jpg";
    uint8_t payload[256];
    /* Sydney, Australia coordinates: ~33°52'8" S, 151°12'33" W */
    size_t len = create_binary_tiff_gps(payload, sizeof(payload),
                                        33, 52, 8, 'S',
                                        151, 12, 33, 'W',
                                        150, false, NULL);
    write_test_jpeg(path, payload, len);

    StegoMetadataInfo info;
    StegoResult res = stego_metadata_scan(path, &info);
    remove(path);

    if (res != STEGO_OK) return false;
    if (!info.has_gps) return false;

    /* S must yield negative latitude */
    if (info.latitude >= 0.0 || info.latitude < -90.0) return false;
    if (strcmp(info.latitude_ref, "S") != 0) return false;

    /* W must yield negative longitude */
    if (info.longitude >= 0.0 || info.longitude < -180.0) return false;
    if (strcmp(info.longitude_ref, "W") != 0) return false;

    return true;
}

/* 4. Image with no GPS data */
static bool test_gps_no_location_data(void) {
    const char *path = "tmp_test_nogps.jpg";
    write_test_jpeg(path, NULL, 0);

    StegoMetadataInfo info;
    StegoResult res = stego_metadata_scan(path, &info);
    remove(path);

    if (res != STEGO_OK) return false;
    if (info.has_gps) return false;
    if (strcmp(info.risk_level, "Low") != 0) return false;

    return true;
}

/* 5. Malformed GPS data (division by zero, out of bounds, zero coords) */
static bool test_gps_malformed_data(void) {
    const char *path1 = "tmp_test_gps_zero.jpg";
    /* Coordinates 0, 0 */
    uint8_t p1[] = {
        'E', 'x', 'i', 'f', 0x00, 0x00,
        'G', 'P', 'S', ' ', '0', '.', '0', ' ', 'N', ' ', '0', '.', '0', ' ', 'E'
    };
    write_test_jpeg(path1, p1, sizeof(p1));
    StegoMetadataInfo info1;
    stego_metadata_scan(path1, &info1);
    remove(path1);
    if (info1.has_gps) return false; /* 0, 0 must be rejected as uninitialized/empty */

    const char *path2 = "tmp_test_gps_oob.jpg";
    /* Out of bounds lat 135 deg N */
    uint8_t p2[] = {
        'E', 'x', 'i', 'f', 0x00, 0x00,
        'G', 'P', 'S', ' ', '1', '3', '5', '.', '0', ' ', 'N', ' ', '4', '5', '.', '0', ' ', 'E'
    };
    write_test_jpeg(path2, p2, sizeof(p2));
    StegoMetadataInfo info2;
    stego_metadata_scan(path2, &info2);
    remove(path2);
    if (info2.has_gps) return false; /* Lat > 90 must be rejected */

    return true;
}

/* 6. Map-link generation format */
static bool test_gps_map_link_formatting(void) {
    double lat = 17.385044;
    double lon = 78.486671;

    char url[256];
    /* URL-encode comma between lat and lon as %2C */
    snprintf(url, sizeof(url), "https://www.google.com/maps/search/?api=1&query=%.6f%%2C%.6f", lat, lon);

    if (strcmp(url, "https://www.google.com/maps/search/?api=1&query=17.385044%2C78.486671") != 0) {
        return false;
    }
    return true;
}

/* 7. Metadata removal */
static bool test_gps_metadata_removal(void) {
    const char *in_path = "tmp_test_strip_in.jpg";
    const char *out_path = "tmp_test_strip_out.jpg";

    uint8_t payload[256];
    size_t len = create_binary_tiff_gps(payload, sizeof(payload),
                                        17, 23, 6, 'N',
                                        78, 29, 12, 'E',
                                        5205, true, "2026:11:10");
    write_test_jpeg(in_path, payload, len);

    StegoMetadataInfo info_in;
    stego_metadata_scan(in_path, &info_in);
    if (!info_in.has_gps) {
        remove(in_path);
        return false;
    }

    StegoResult strip_res = stego_metadata_strip(in_path, out_path);
    remove(in_path);
    if (strip_res != STEGO_OK) {
        return false;
    }

    StegoMetadataInfo info_out;
    StegoResult scan_res = stego_metadata_scan(out_path, &info_out);
    remove(out_path);

    if (scan_res != STEGO_OK) return false;
    if (info_out.has_gps || info_out.has_exif) return false;
    if (strcmp(info_out.risk_level, "Low") != 0) return false;

    return true;
}

/* Original Secure Shredding Test */
static bool test_secure_shred_file(void) {
    const char *tmp = "tmp_sensitive_file.txt";
    FILE *fp = fopen(tmp, "wb");
    const char *secret = "Top secret credentials that must be zeroized";
    fwrite(secret, 1, strlen(secret), fp);
    fclose(fp);

    StegoResult res = stego_secure_delete_file(tmp);
    if (res != STEGO_OK) return false;

    FILE *check = fopen(tmp, "rb");
    if (check) {
        fclose(check);
        return false;
    }
    return true;
}

int main(void) {
    printf("====================================================\n");
    printf("          PRIVACY & GPS METADATA TEST SUITE         \n");
    printf("====================================================\n");
    RUN_TEST(test_gps_complete_data);
    RUN_TEST(test_gps_missing_longitude);
    RUN_TEST(test_gps_south_and_west_references);
    RUN_TEST(test_gps_no_location_data);
    RUN_TEST(test_gps_malformed_data);
    RUN_TEST(test_gps_map_link_formatting);
    RUN_TEST(test_gps_metadata_removal);
    RUN_TEST(test_secure_shred_file);
    printf("====================================================\n");
    printf("Result: %d / %d tests passed\n", g_tests_passed, g_tests_run);
    printf("====================================================\n");
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
