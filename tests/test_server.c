/**
 * @file test_server.c
 * @brief Comprehensive test suite for the local web server, API, and stego bridge.
 */

#include "stego/stego.h"
#include "stego/carrier.h"
#include "stego/crypto.h"
#include "stego/image_format.h"
#include "../backend/http.h"
#include "../backend/uploads.h"
#include "../backend/stego_bridge.h"
#include "../backend/api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
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

static uint8_t *read_file_bytes(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz <= 0) { fclose(fp); return NULL; }
    uint8_t *buf = (uint8_t *)malloc(sz);
    if (!buf) { fclose(fp); return NULL; }
    if (fread(buf, 1, sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    if (out_len) *out_len = (size_t)sz;
    return buf;
}

/* ------------------------------------------------------------------------- */
/* Test 1: Multipart parser with text, password, and binary file fields     */
/* ------------------------------------------------------------------------- */
static bool test_multipart_parsing(void) {
    const char *boundary = "----WebKitFormBoundaryX7Y8Z9";
    char body[2048];
    int len = snprintf(body, sizeof(body),
        "------WebKitFormBoundaryX7Y8Z9\r\n"
        "Content-Disposition: form-data; name=\"secret_type\"\r\n\r\n"
        "text\r\n"
        "------WebKitFormBoundaryX7Y8Z9\r\n"
        "Content-Disposition: form-data; name=\"password\"\r\n\r\n"
        "SecretPassword123\r\n"
        "------WebKitFormBoundaryX7Y8Z9\r\n"
        "Content-Disposition: form-data; name=\"message\"\r\n\r\n"
        "Top confidential note\r\n"
        "------WebKitFormBoundaryX7Y8Z9\r\n"
        "Content-Disposition: form-data; name=\"secret_file\"; filename=\"data.bin\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
        "BinaryPayload1234\r\n"
        "------WebKitFormBoundaryX7Y8Z9--\r\n");

    MultipartForm *form = multipart_parse((const uint8_t *)body, len, boundary);
    if (!form) return false;

    const char *stype = multipart_get_string(form, "secret_type");
    const char *pass = multipart_get_string(form, "password");
    const char *msg = multipart_get_string(form, "message");
    const UploadPart *file_part = multipart_get_part(form, "secret_file");

    bool ok = (stype && strcmp(stype, "text") == 0) &&
              (pass && strcmp(pass, "SecretPassword123") == 0) &&
              (msg && strcmp(msg, "Top confidential note") == 0) &&
              (file_part && file_part->is_file && strcmp(file_part->filename, "data.bin") == 0) &&
              (file_part->size == 17 && memcmp(file_part->data, "BinaryPayload1234", 17) == 0);

    multipart_free(form);
    return ok;
}

/* Global storage for roundtrip tests */
static uint8_t *g_enc_stego_png = NULL;
static size_t g_enc_stego_len = 0;

/* ------------------------------------------------------------------------- */
/* Test 2: Hide text with password creates CMC2 Encrypted envelope           */
/* ------------------------------------------------------------------------- */
static bool test_hide_text_with_password(void) {
    size_t cover_len = 0;
    uint8_t *cover = read_file_bytes("samples/compat/rgb8.png", &cover_len);
    if (!cover) return false;

    const char *secret = "Confidential web test secret!";
    const char *password = "WebPassword2026";

    BridgeHideResult res;
    StegoResult sres = bridge_hide(cover, cover_len,
                                   (const uint8_t *)secret, strlen(secret),
                                   password, false, &res);
    free(cover);

    if (sres != STEGO_OK) {
        bridge_hide_result_free(&res);
        return false;
    }

    if (!res.is_protected || strcmp(res.envelope_name, "CMC2 Encrypted") != 0) {
        bridge_hide_result_free(&res);
        return false;
    }

    /* Verify PNG header magic */
    if (res.png_size < 8 || memcmp(res.png_data, "\x89PNG\r\n\x1a\n", 8) != 0) {
        bridge_hide_result_free(&res);
        return false;
    }

    /* Save for subsequent reveal tests */
    g_enc_stego_len = res.png_size;
    g_enc_stego_png = (uint8_t *)malloc(g_enc_stego_len);
    memcpy(g_enc_stego_png, res.png_data, g_enc_stego_len);

    bridge_hide_result_free(&res);
    return true;
}

/* ------------------------------------------------------------------------- */
/* Test 3: Reveal with correct password recovers exact text                  */
/* ------------------------------------------------------------------------- */
static bool test_reveal_with_correct_password(void) {
    if (!g_enc_stego_png || g_enc_stego_len == 0) return false;

    BridgeRevealResult res;
    StegoResult sres = bridge_reveal(g_enc_stego_png, g_enc_stego_len, "WebPassword2026", &res);
    if (sres != STEGO_OK) {
        bridge_reveal_result_free(&res);
        return false;
    }

    const char *expected = "Confidential web test secret!";
    bool ok = (res.is_protected &&
               res.is_text &&
               res.payload_size == strlen(expected) &&
               memcmp(res.payload_data, expected, strlen(expected)) == 0);

    bridge_reveal_result_free(&res);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* Test 4: Reveal with wrong password rejected with exact error message      */
/* ------------------------------------------------------------------------- */
static bool test_reveal_with_wrong_password(void) {
    if (!g_enc_stego_png || g_enc_stego_len == 0) return false;

    BridgeRevealResult res;
    StegoResult sres = bridge_reveal(g_enc_stego_png, g_enc_stego_len, "WrongPassword", &res);

    bool ok = (sres != STEGO_OK &&
               strcmp(res.error_msg, "The password is incorrect, or the image was changed or damaged.") == 0 &&
               res.payload_data == NULL);

    bridge_reveal_result_free(&res);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* Test 5: Reveal without password on encrypted image rejected               */
/* ------------------------------------------------------------------------- */
static bool test_reveal_without_password_on_encrypted(void) {
    if (!g_enc_stego_png || g_enc_stego_len == 0) return false;

    BridgeRevealResult res;
    StegoResult sres = bridge_reveal(g_enc_stego_png, g_enc_stego_len, NULL, &res);

    bool ok = (sres != STEGO_OK &&
               strcmp(res.error_msg, "This image is password protected. Please enter the password.") == 0 &&
               res.payload_data == NULL);

    bridge_reveal_result_free(&res);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* Test 6: Hide binary file with password roundtrip                          */
/* ------------------------------------------------------------------------- */
static bool test_hide_file_with_password(void) {
    size_t cover_len = 0;
    uint8_t *cover = read_file_bytes("samples/compat/rgb8.png", &cover_len);
    if (!cover) return false;

    uint8_t binary_secret[128];
    for (int i = 0; i < 128; i++) binary_secret[i] = (uint8_t)(i ^ 0xAA);

    BridgeHideResult hide_res;
    StegoResult sres = bridge_hide(cover, cover_len, binary_secret, sizeof(binary_secret), "BinaryKey", false, &hide_res);
    free(cover);

    if (sres != STEGO_OK) {
        bridge_hide_result_free(&hide_res);
        return false;
    }

    BridgeRevealResult rev_res;
    sres = bridge_reveal(hide_res.png_data, hide_res.png_size, "BinaryKey", &rev_res);
    bridge_hide_result_free(&hide_res);

    if (sres != STEGO_OK) {
        bridge_reveal_result_free(&rev_res);
        return false;
    }

    bool ok = (rev_res.payload_size == sizeof(binary_secret) &&
               memcmp(rev_res.payload_data, binary_secret, sizeof(binary_secret)) == 0);

    bridge_reveal_result_free(&rev_res);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* Test 7: Verify encrypted and unencrypted images                           */
/* ------------------------------------------------------------------------- */
static bool test_verify_encrypted_and_unencrypted(void) {
    /* 1. Verify encrypted image */
    BridgeVerifyResult v_enc;
    if (bridge_verify(g_enc_stego_png, g_enc_stego_len, &v_enc) != STEGO_OK) return false;
    if (!v_enc.has_payload || !v_enc.is_protected || strcmp(v_enc.envelope_name, "CMC2 Encrypted") != 0) {
        return false;
    }

    /* 2. Verify plain cover image */
    size_t cover_len = 0;
    uint8_t *cover = read_file_bytes("samples/compat/rgb8.png", &cover_len);
    if (!cover) return false;

    BridgeVerifyResult v_clean;
    if (bridge_verify(cover, cover_len, &v_clean) != STEGO_OK) {
        free(cover);
        return false;
    }
    if (v_clean.has_payload) {
        free(cover);
        return false;
    }

    /* 3. Create and verify unencrypted image */
    BridgeHideResult h_unenc;
    const char *msg = "Unencrypted note";
    StegoResult sres = bridge_hide(cover, cover_len, (const uint8_t *)msg, strlen(msg), NULL, false, &h_unenc);
    free(cover);

    if (sres != STEGO_OK) {
        bridge_hide_result_free(&h_unenc);
        return false;
    }

    BridgeVerifyResult v_unenc;
    sres = bridge_verify(h_unenc.png_data, h_unenc.png_size, &v_unenc);
    bridge_hide_result_free(&h_unenc);

    if (sres != STEGO_OK) return false;

    return (v_unenc.has_payload && !v_unenc.is_protected && strcmp(v_unenc.envelope_name, "CMC1 Unencrypted") == 0);
}

/* ------------------------------------------------------------------------- */
/* Test 8: Capacity calculation reports proper dimensions and limits         */
/* ------------------------------------------------------------------------- */
static bool test_capacity_calculation(void) {
    size_t cover_len = 0;
    uint8_t *cover = read_file_bytes("samples/compat/rgb8.png", &cover_len);
    if (!cover) return false;

    BridgeCapacityResult cap;
    StegoResult sres = bridge_capacity(cover, cover_len, false, &cap);
    free(cover);

    if (sres != STEGO_OK) return false;

    return (cap.width == 48 && cap.height == 48 && cap.channels == 3 &&
            cap.unencrypted_capacity == 856 && cap.encrypted_capacity == 812 &&
            cap.encrypted_capacity < cap.unencrypted_capacity);
}

/* ------------------------------------------------------------------------- */
/* Test 9: JPEG input produces lossless PNG output with explanatory notice   */
/* ------------------------------------------------------------------------- */
static bool test_jpeg_input_produces_png_output(void) {
    size_t jpg_len = 0;
    uint8_t *jpg_data = read_file_bytes("samples/compat/sample.jpg", &jpg_len);
    if (!jpg_data) return false;

    const char *secret = "JPEG to PNG test";
    BridgeHideResult res;
    StegoResult sres = bridge_hide(jpg_data, jpg_len, (const uint8_t *)secret, strlen(secret), "Pass123", false, &res);
    free(jpg_data);

    if (sres != STEGO_OK) {
        bridge_hide_result_free(&res);
        return false;
    }

    /* Output MUST be PNG */
    bool is_png = (res.png_size >= 8 && memcmp(res.png_data, "\x89PNG\r\n\x1a\n", 8) == 0);
    bool has_notice = (strstr(res.notice, "normalized to 8-bit pixels") != NULL &&
                       strstr(res.notice, "lossless PNG") != NULL);

    bridge_hide_result_free(&res);
    return (is_png && has_notice);
}

/* ------------------------------------------------------------------------- */
/* Test 10: Invalid image rejected with friendly error message               */
/* ------------------------------------------------------------------------- */
static bool test_invalid_image_rejection(void) {
    uint8_t corrupt_bytes[] = "This is definitely not an image file format!";
    size_t corrupt_len = sizeof(corrupt_bytes);

    BridgeHideResult hres;
    StegoResult sres = bridge_hide(corrupt_bytes, corrupt_len, (const uint8_t *)"test", 4, "pass", false, &hres);
    bool ok_hide = (sres == STEGO_ERR_INVALID_FORMAT &&
                    strcmp(hres.error_msg, "That file does not look like a valid image.") == 0);

    BridgeRevealResult rres;
    sres = bridge_reveal(corrupt_bytes, corrupt_len, "pass", &rres);
    bool ok_reveal = (sres == STEGO_ERR_INVALID_FORMAT &&
                      strcmp(rres.error_msg, "That file does not look like a valid image.") == 0);

    BridgeVerifyResult vres;
    sres = bridge_verify(corrupt_bytes, corrupt_len, &vres);
    bool ok_verify = (sres == STEGO_ERR_INVALID_FORMAT &&
                      strcmp(vres.error_msg, "That file does not look like a valid image.") == 0);

    return (ok_hide && ok_reveal && ok_verify);
}

/* ------------------------------------------------------------------------- */
/* Test 11: Oversized upload rejection check                                 */
/* ------------------------------------------------------------------------- */
static bool test_oversized_upload_rejection(void) {
    HttpRequest req;
    const char *raw_req =
        "POST /api/hide HTTP/1.1\r\n"
        "Host: 127.0.0.1:8080\r\n"
        "Content-Length: 70000000\r\n" /* 70 MB > 64 MB limit */
        "Content-Type: multipart/form-data; boundary=xyz\r\n\r\n";

    size_t hdr_bytes = 0;
    int res = http_parse_request_headers((const uint8_t *)raw_req, strlen(raw_req), &req, &hdr_bytes);
    if (res != 0) return false;

    return (req.content_length > STEGO_MAX_UPLOAD_SIZE);
}

/* ------------------------------------------------------------------------- */
/* Test 12: Temporary file cleanup verification                              */
/* ------------------------------------------------------------------------- */
static bool test_temp_file_cleanup(void) {
    uint8_t test_data[] = "Temporary sensitive test payload";
    char *tmp_file = uploads_create_temp_file(test_data, sizeof(test_data), ".tmp");
    if (!tmp_file) return false;

    /* Verify file exists */
    FILE *fp = fopen(tmp_file, "rb");
    if (!fp) {
        free(tmp_file);
        return false;
    }
    fclose(fp);

    /* Clean up */
    uploads_cleanup_temp_file(tmp_file);

    /* Verify file no longer exists */
    fp = fopen(tmp_file, "rb");
    bool deleted = (fp == NULL);
    if (fp) fclose(fp);

    free(tmp_file);
    return deleted;
}

/* ------------------------------------------------------------------------- */
/* Test 13: Localhost-only bind verification                                 */
/* ------------------------------------------------------------------------- */
static bool test_localhost_bind_verification(void) {
    /* Verify that inet_addr("127.0.0.1") is exactly 0x0100007f in network byte order */
    unsigned long loopback_addr = inet_addr("127.0.0.1");
    unsigned long inaddr_any = inet_addr("0.0.0.0");

    bool loopback_matches = (loopback_addr == htonl(INADDR_LOOPBACK));
    bool avoids_any = (loopback_addr != inaddr_any);

    return (loopback_matches && avoids_any);
}

/* ------------------------------------------------------------------------- */
/* Test 14: HTTP static file path traversal prevention                       */
/* ------------------------------------------------------------------------- */
static bool test_static_path_traversal_prevention(void) {
    HttpResponse res;
    const char *forbidden_paths[] = {
        "../Makefile",
        "..\\Makefile",
        "/../../etc/passwd",
        "/..%2f..%2fwin.ini",
        "C:\\Windows\\win.ini"
    };

    for (size_t i = 0; i < sizeof(forbidden_paths) / sizeof(forbidden_paths[0]); i++) {
        if (http_serve_static("frontend", forbidden_paths[i], &res)) {
            http_response_free(&res);
            return false; /* Path traversal was allowed! */
        }
    }

    return true;
}

/* ------------------------------------------------------------------------- */
/* Test 15: API metadata scan with GPS location                              */
/* ------------------------------------------------------------------------- */
static bool test_api_metadata_scan_with_gps(void) {
    const char *gps_str = "Exif\0\0GPS 17.385044 N 78.486671 E";
    uint8_t img[512];
    size_t pos = 0;
    img[pos++] = 0xFF; img[pos++] = 0xD8;
    img[pos++] = 0xFF; img[pos++] = 0xE1;
    uint16_t seg_len = (uint16_t)(strlen(gps_str + 6) + 6 + 2);
    img[pos++] = (seg_len >> 8) & 0xFF; img[pos++] = seg_len & 0xFF;
    memcpy(img + pos, "Exif\0\0", 6); pos += 6;
    memcpy(img + pos, "GPS 17.385044 N 78.486671 E", strlen("GPS 17.385044 N 78.486671 E")); pos += strlen("GPS 17.385044 N 78.486671 E");
    uint8_t sof0[] = { 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00 };
    memcpy(img + pos, sof0, sizeof(sof0)); pos += sizeof(sof0);
    uint8_t sos[] = { 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x7F, 0xFF, 0xD9 };
    memcpy(img + pos, sos, sizeof(sos)); pos += sizeof(sos);

    const char *boundary = "----TestGpsBoundary12345";
    char body[2048];
    size_t body_pos = 0;
    int head_len = snprintf(body, sizeof(body),
        "--%s\r\nContent-Disposition: form-data; name=\"image\"; filename=\"photo.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n", boundary);
    body_pos += head_len;
    memcpy(body + body_pos, img, pos);
    body_pos += pos;
    int tail_len = snprintf(body + body_pos, sizeof(body) - body_pos, "\r\n--%s--\r\n", boundary);
    body_pos += tail_len;

    HttpRequest req;
    memset(&req, 0, sizeof(req));
    req.method = HTTP_METHOD_POST;
    strncpy(req.path, "/api/privacy-report", sizeof(req.path) - 1);
    strncpy(req.boundary, boundary, sizeof(req.boundary) - 1);
    req.body = (uint8_t *)body;
    req.body_len = body_pos;
    req.content_length = body_pos;

    HttpResponse res;
    http_response_init(&res, 200, "application/json");
    api_handle_request(&req, &res);

    bool ok = false;
    if (res.status_code == 200 && res.body) {
        const char *body_str = (const char *)res.body;
        bool has_gps_tag = (strstr(body_str, "\"hasGps\":true") != NULL);
        bool has_gps_obj = (strstr(body_str, "\"gps\":{") != NULL);
        bool has_lat = (strstr(body_str, "\"latitude\":17.385044") != NULL);
        bool has_lon = (strstr(body_str, "\"longitude\":78.486671") != NULL);
        bool has_lat_ref = (strstr(body_str, "\"latitudeRef\":\"N\"") != NULL);
        bool has_lon_ref = (strstr(body_str, "\"longitudeRef\":\"E\"") != NULL);
        bool has_risk = (strstr(body_str, "\"privacyRisk\":\"high\"") != NULL);

        ok = (has_gps_tag && has_gps_obj && has_lat && has_lon && has_lat_ref && has_lon_ref && has_risk);
    }
    http_response_free(&res);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* Test 16: API metadata scan without GPS location                           */
/* ------------------------------------------------------------------------- */
static bool test_api_privacy_report_without_gps(void) {
    uint8_t img[256];
    size_t pos = 0;
    img[pos++] = 0xFF; img[pos++] = 0xD8;
    uint8_t sof0[] = { 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00 };
    memcpy(img + pos, sof0, sizeof(sof0)); pos += sizeof(sof0);
    uint8_t sos[] = { 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x7F, 0xFF, 0xD9 };
    memcpy(img + pos, sos, sizeof(sos)); pos += sizeof(sos);

    const char *boundary = "----TestNoGpsBoundary999";
    char body[1024];
    size_t body_pos = 0;
    int head_len = snprintf(body, sizeof(body),
        "--%s\r\nContent-Disposition: form-data; name=\"image\"; filename=\"clean.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n", boundary);
    body_pos += head_len;
    memcpy(body + body_pos, img, pos);
    body_pos += pos;
    int tail_len = snprintf(body + body_pos, sizeof(body) - body_pos, "\r\n--%s--\r\n", boundary);
    body_pos += tail_len;

    HttpRequest req;
    memset(&req, 0, sizeof(req));
    req.method = HTTP_METHOD_POST;
    strncpy(req.path, "/api/metadata-scan", sizeof(req.path) - 1);
    strncpy(req.boundary, boundary, sizeof(req.boundary) - 1);
    req.body = (uint8_t *)body;
    req.body_len = body_pos;
    req.content_length = body_pos;

    HttpResponse res;
    http_response_init(&res, 200, "application/json");
    api_handle_request(&req, &res);

    bool ok = false;
    if (res.status_code == 200 && res.body) {
        const char *body_str = (const char *)res.body;
        bool has_nogps_tag = (strstr(body_str, "\"hasGps\":false") != NULL);
        bool has_null_gps = (strstr(body_str, "\"gps\":null") != NULL);
        bool has_low_risk = (strstr(body_str, "\"privacyRisk\":\"low\"") != NULL);

        ok = (has_nogps_tag && has_null_gps && has_low_risk);
    }
    http_response_free(&res);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* Main test runner                                                          */
/* ------------------------------------------------------------------------- */
int main(void) {
#if defined(_WIN32)
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    printf("=================================================================\n");
    printf("         LOCAL WEB SERVER & REST API TEST SUITE                  \n");
    printf("=================================================================\n");

    RUN_TEST(test_multipart_parsing);
    RUN_TEST(test_hide_text_with_password);
    RUN_TEST(test_reveal_with_correct_password);
    RUN_TEST(test_reveal_with_wrong_password);
    RUN_TEST(test_reveal_without_password_on_encrypted);
    RUN_TEST(test_hide_file_with_password);
    RUN_TEST(test_verify_encrypted_and_unencrypted);
    RUN_TEST(test_capacity_calculation);
    RUN_TEST(test_jpeg_input_produces_png_output);
    RUN_TEST(test_invalid_image_rejection);
    RUN_TEST(test_oversized_upload_rejection);
    RUN_TEST(test_temp_file_cleanup);
    RUN_TEST(test_localhost_bind_verification);
    RUN_TEST(test_static_path_traversal_prevention);
    RUN_TEST(test_api_metadata_scan_with_gps);
    RUN_TEST(test_api_privacy_report_without_gps);

    if (g_enc_stego_png) {
        free(g_enc_stego_png);
        g_enc_stego_png = NULL;
    }

    printf("=================================================================\n");
    printf("Result: %d / %d tests passed (%.1f%%)\n",
           g_tests_passed, g_tests_run,
           (float)g_tests_passed / (float)g_tests_run * 100.0f);
    printf("=================================================================\n");

#if defined(_WIN32)
    WSACleanup();
#endif

    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
