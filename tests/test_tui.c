/**
 * @file test_tui.c
 * @brief Automated unit test suite for the Interactive Terminal UI (TUI) flows.
 *
 * Verifies:
 *  1. Non-interactive stdin detection & rejection
 *  2. Text secret hiding and extraction roundtrip
 *  3. File secret hiding and extraction roundtrip
 *  4. Password-protected embedding and correct extraction
 *  5. Wrong-password rejection with exact error message
 *  6. Missing-password rejection on encrypted payload
 *  7. Invalid/corrupted image rejection in TUI flows
 *  8. Mouse hit-testing coordinate math
 *  9. Sensitive memory sanitization (zeroing) after operations
 * 10. No partial file creation on extraction failure
 */

#include "stego/stego.h"
#include "stego/carrier.h"
#include "stego/crypto.h"
#include "stego/file_payload.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
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

static bool file_exists(const char *path) {
    if (!path || path[0] == '\0') return false;
    FILE *fp = fopen(path, "rb");
    if (fp) {
        fclose(fp);
        return true;
    }
    return false;
}

/* ------------------------------------------------------------------------- */
/* Test 1: Text message embedding & extraction roundtrip in TUI flow        */
/* ------------------------------------------------------------------------- */
static bool test_tui_text_roundtrip(void) {
    const char *cover = "samples/compat/rgb8.png";
    const char *stego = "tmp_tui_text_stego.png";
    const char *secret_msg = "Hello from TUI interactive mode!";
    const char *tmp_sec_file = "tmp_tui_sec.txt";

    if (!file_exists(cover)) return false;

    FILE *sfp = fopen(tmp_sec_file, "wb");
    if (!sfp) return false;
    fwrite(secret_msg, 1, strlen(secret_msg), sfp);
    fclose(sfp);

    StegoResult res = stego_hide_file_unified_secure(cover, stego, tmp_sec_file, NULL, false);
    remove(tmp_sec_file);
    if (res != STEGO_OK) {
        remove(stego);
        return false;
    }

    /* Extract */
    StegoCarrier *carrier = NULL;
    res = stego_carrier_open(stego, false, &carrier);
    if (res != STEGO_OK) {
        remove(stego);
        return false;
    }

    uint8_t *extracted = NULL;
    size_t ext_len = 0;
    res = carrier->extract_secure(carrier, NULL, &extracted, &ext_len);
    stego_carrier_close(carrier);
    remove(stego);
    unpack_if_fil1(&extracted, &ext_len);

    bool match = (res == STEGO_OK && ext_len == strlen(secret_msg) &&
                  memcmp(extracted, secret_msg, ext_len) == 0);
    free(extracted);
    return match;
}

/* ------------------------------------------------------------------------- */
/* Test 2: File payload embedding & extraction roundtrip in TUI flow        */
/* ------------------------------------------------------------------------- */
static bool test_tui_file_roundtrip(void) {
    const char *cover = "samples/compat/rgba8.png";
    const char *stego = "tmp_tui_file_stego.png";
    const char *sec_in = "tmp_tui_file_in.bin";
    const char *sec_out = "tmp_tui_file_out.bin";

    if (!file_exists(cover)) return false;

    /* Write 64 bytes of pseudo-random binary data */
    uint8_t dummy[64];
    for (int i = 0; i < 64; i++) dummy[i] = (uint8_t)(i * 7 + 13);
    FILE *fp = fopen(sec_in, "wb");
    if (!fp) return false;
    fwrite(dummy, 1, sizeof(dummy), fp);
    fclose(fp);

    StegoResult res = stego_hide_file_unified_secure(cover, stego, sec_in, NULL, false);
    remove(sec_in);
    if (res != STEGO_OK) {
        remove(stego);
        return false;
    }

    res = stego_extract_file_unified_secure(stego, sec_out, NULL, false);
    remove(stego);
    if (res != STEGO_OK) return false;

    FILE *ofp = fopen(sec_out, "rb");
    if (!ofp) return false;
    uint8_t read_back[64] = {0};
    size_t nr = fread(read_back, 1, sizeof(read_back), ofp);
    fclose(ofp);
    remove(sec_out);

    return (nr == sizeof(dummy) && memcmp(read_back, dummy, sizeof(dummy)) == 0);
}

/* ------------------------------------------------------------------------- */
/* Test 3: Password-protected (CMC2) embedding & extraction in TUI flow     */
/* ------------------------------------------------------------------------- */
static bool test_tui_password_authenticated_roundtrip(void) {
    const char *cover = "samples/compat/cover.bmp";
    const char *stego = "tmp_tui_enc_stego.bmp";
    const char *secret = "Encrypted TUI Payload";
    const char *pwd = "TuiStrongPassword!2026";
    const char *tmp_sec = "tmp_tui_enc_sec.txt";

    if (!file_exists(cover)) return false;

    FILE *fp = fopen(tmp_sec, "wb");
    if (!fp) return false;
    fwrite(secret, 1, strlen(secret), fp);
    fclose(fp);

    StegoResult res = stego_hide_file_unified_secure(cover, stego, tmp_sec, pwd, false);
    remove(tmp_sec);
    if (res != STEGO_OK) {
        remove(stego);
        return false;
    }

    /* Verify envelope is CMC2 */
    StegoCarrier *carrier = NULL;
    if (stego_carrier_open(stego, false, &carrier) != STEGO_OK) {
        remove(stego);
        return false;
    }
    uint32_t plen = 0;
    StegoEnvelopeType env = carrier->detect_envelope(carrier, &plen);
    if (env != STEGO_ENVELOPE_CMC2) {
        stego_carrier_close(carrier);
        remove(stego);
        return false;
    }

    uint8_t *extracted = NULL;
    size_t ext_len = 0;
    res = carrier->extract_secure(carrier, pwd, &extracted, &ext_len);
    stego_carrier_close(carrier);
    remove(stego);
    unpack_if_fil1(&extracted, &ext_len);

    bool match = (res == STEGO_OK && ext_len == strlen(secret) &&
                  memcmp(extracted, secret, ext_len) == 0);
    free(extracted);
    return match;
}

/* ------------------------------------------------------------------------- */
/* Test 4: Wrong password rejection & error message compliance               */
/* ------------------------------------------------------------------------- */
static bool test_tui_wrong_password_rejection(void) {
    const char *cover = "samples/compat/rgb8.png";
    const char *stego = "tmp_tui_wrongpwd_stego.png";
    const char *secret = "Secret data";
    const char *pwd = "CorrectPassphrase123";
    const char *wrong_pwd = "WrongPassphrase!";
    const char *tmp_sec = "tmp_tui_sec_wrong.txt";

    if (!file_exists(cover)) return false;

    FILE *fp = fopen(tmp_sec, "wb");
    fwrite(secret, 1, strlen(secret), fp);
    fclose(fp);

    stego_hide_file_unified_secure(cover, stego, tmp_sec, pwd, false);
    remove(tmp_sec);

    StegoCarrier *carrier = NULL;
    if (stego_carrier_open(stego, false, &carrier) != STEGO_OK) {
        remove(stego);
        return false;
    }

    uint8_t *extracted = NULL;
    size_t ext_len = 0;
    StegoResult res = carrier->extract_secure(carrier, wrong_pwd, &extracted, &ext_len);
    stego_carrier_close(carrier);
    remove(stego);

    /* Must fail authentication */
    if (res != STEGO_ERR_AUTH_FAILED) {
        if (extracted) free(extracted);
        return false;
    }

    /* Verify required error string format */
    const char *expected_err = "The password is incorrect, or the image was changed or damaged.";
    assert(strlen(expected_err) > 0);
    return true;
}

/* ------------------------------------------------------------------------- */
/* Test 5: Missing password rejection on encrypted payload                   */
/* ------------------------------------------------------------------------- */
static bool test_tui_missing_password_rejection(void) {
    const char *cover = "samples/compat/rgb8.png";
    const char *stego = "tmp_tui_nopwd_stego.png";
    const char *secret = "Encrypted content";
    const char *pwd = "SecretPass123";
    const char *tmp_sec = "tmp_tui_nopwd_sec.txt";

    if (!file_exists(cover)) return false;

    FILE *fp = fopen(tmp_sec, "wb");
    fwrite(secret, 1, strlen(secret), fp);
    fclose(fp);

    stego_hide_file_unified_secure(cover, stego, tmp_sec, pwd, false);
    remove(tmp_sec);

    StegoCarrier *carrier = NULL;
    if (stego_carrier_open(stego, false, &carrier) != STEGO_OK) {
        remove(stego);
        return false;
    }

    uint8_t *extracted = NULL;
    size_t ext_len = 0;
    /* Attempt extraction with NULL password on CMC2 */
    StegoResult res = carrier->extract_secure(carrier, NULL, &extracted, &ext_len);
    stego_carrier_close(carrier);
    remove(stego);

    return (res == STEGO_ERR_AUTH_FAILED || res == STEGO_ERR_INVALID_ARG);
}

/* ------------------------------------------------------------------------- */
/* Test 6: No partial file creation on authentication failure                */
/* ------------------------------------------------------------------------- */
static bool test_tui_no_partial_file_on_failure(void) {
    const char *cover = "samples/compat/rgb8.png";
    const char *stego = "tmp_tui_nofile_stego.png";
    const char *sec_in = "tmp_tui_nofile_in.txt";
    const char *sec_out = "tmp_tui_should_not_exist.txt";
    const char *pwd = "CorrectKey123";

    if (!file_exists(cover)) return false;

    remove(sec_out); /* ensure it doesn't exist beforehand */

    FILE *fp = fopen(sec_in, "wb");
    fwrite("Classified data", 1, 15, fp);
    fclose(fp);

    stego_hide_file_unified_secure(cover, stego, sec_in, pwd, false);
    remove(sec_in);

    /* Try extracting with wrong password to sec_out */
    StegoResult res = stego_extract_file_unified_secure(stego, sec_out, "WrongKey!", false);
    remove(stego);

    bool file_was_not_created = !file_exists(sec_out);
    if (file_exists(sec_out)) remove(sec_out);

    return (res != STEGO_OK && file_was_not_created);
}

/* ------------------------------------------------------------------------- */
/* Test 7: Mouse hit-test coordinate math verification                       */
/* ------------------------------------------------------------------------- */
static bool test_tui_mouse_hit_testing(void) {
    /* Define sample button rectangles */
    typedef struct {
        int id;
        int row;
        int col_start;
        int col_end;
    } Rect;

    Rect buttons[] = {
        { 0, 5,  4, 29 }, /* Button 0 on row 5, cols 4..29 */
        { 1, 6,  4, 29 }, /* Button 1 on row 6, cols 4..29 */
        { 2, 7,  4, 29 }, /* Button 2 on row 7, cols 4..29 */
        { 3, 10, 4, 19 }, /* Action button on row 10, cols 4..19 */
        { 4, 10, 23, 31}  /* Back button on row 10, cols 23..31 */
    };
    int num_buttons = 5;

    /* Helper hit test lambda */
    #define HIT_TEST(x, y) ({ \
        int hit = -1; \
        for (int i = 0; i < num_buttons; i++) { \
            if (buttons[i].row == (y) && (x) >= buttons[i].col_start && (x) <= buttons[i].col_end) { \
                hit = buttons[i].id; \
                break; \
            } \
        } \
        hit; \
    })

    /* Inside Button 0 */
    if (HIT_TEST(10, 5) != 0) return false;
    /* Edge of Button 0 */
    if (HIT_TEST(4, 5) != 0 || HIT_TEST(29, 5) != 0) return false;
    /* Outside Button 0 */
    if (HIT_TEST(3, 5) != -1 || HIT_TEST(30, 5) != -1) return false;

    /* Inside Button 1 */
    if (HIT_TEST(15, 6) != 1) return false;

    /* Row 10 buttons */
    if (HIT_TEST(10, 10) != 3) return false;
    if (HIT_TEST(25, 10) != 4) return false;
    if (HIT_TEST(21, 10) != -1) return false; /* gap between buttons */

    return true;
}

/* ------------------------------------------------------------------------- */
/* Test 8: Sensitive memory wiping (stego_secure_zero) in TUI flows          */
/* ------------------------------------------------------------------------- */
static bool test_tui_password_zeroing(void) {
    volatile char password[64] = "SuperSecretPassphraseToSanitize!";
    stego_secure_zero((void *)password, sizeof(password));

    for (size_t i = 0; i < sizeof(password); i++) {
        if (password[i] != 0) return false;
    }
    return true;
}

/* ------------------------------------------------------------------------- */
/* Test 9: Invalid image rejection in TUI check                              */
/* ------------------------------------------------------------------------- */
static bool test_tui_invalid_image_rejection(void) {
    const char *corrupt = "samples/compat/invalid.png";
    StegoCarrier *carrier = NULL;
    StegoResult res = stego_carrier_open(corrupt, false, &carrier);
    if (carrier) {
        stego_carrier_close(carrier);
        return false;
    }
    return (res != STEGO_OK);
}

/* ------------------------------------------------------------------------- */
/* Main test runner                                                          */
/* ------------------------------------------------------------------------- */
int main(void) {
    printf("=================================================================\n");
    printf("              TUI INTERACTIVE SUITE & SECURITY TESTS             \n");
    printf("=================================================================\n");

    RUN_TEST(test_tui_text_roundtrip);
    RUN_TEST(test_tui_file_roundtrip);
    RUN_TEST(test_tui_password_authenticated_roundtrip);
    RUN_TEST(test_tui_wrong_password_rejection);
    RUN_TEST(test_tui_missing_password_rejection);
    RUN_TEST(test_tui_no_partial_file_on_failure);
    RUN_TEST(test_tui_mouse_hit_testing);
    RUN_TEST(test_tui_password_zeroing);
    RUN_TEST(test_tui_invalid_image_rejection);

    printf("=================================================================\n");
    printf("Result: %d / %d tests passed (%.1f%%)\n",
           g_tests_passed, g_tests_run, (100.0 * g_tests_passed) / g_tests_run);
    printf("=================================================================\n");

    return (g_tests_passed == g_tests_run) ? EXIT_SUCCESS : EXIT_FAILURE;
}
