/**
 * @file stego_bridge.c
 * @brief Bridge between HTTP request payloads and native C steganography engine.
 */

#include "stego_bridge.h"
#include "uploads.h"
#include "core/stego_core.h"
#include "stego/compress.h"
#include "stego/capacity.h"
#include "stego/split.h"
#include "stego/png_carrier.h"
#include "stego/file_payload.h"
#include "stego/metadata.h"
#include "stego/privacy.h"
#include "stego/random.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Base64 encoding table */
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *stego_base64_encode(const uint8_t *data, size_t input_length) {
    if (!data || input_length == 0) return strdup("");

    size_t output_length = 4 * ((input_length + 2) / 3);
    char *encoded = (char *)malloc(output_length + 1);
    if (!encoded) return NULL;

    size_t i = 0, j = 0;
    while (i < input_length) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        encoded[j++] = b64_table[(triple >> 18) & 0x3F];
        encoded[j++] = b64_table[(triple >> 12) & 0x3F];
        encoded[j++] = (i > input_length + 1) ? '=' : b64_table[(triple >> 6) & 0x3F];
        encoded[j++] = (i > input_length) ? '=' : b64_table[triple & 0x3F];
    }
    encoded[output_length] = '\0';
    return encoded;
}

uint8_t *stego_base64_decode(const char *data, size_t *out_len) {
    if (!data) return NULL;
    size_t input_length = strlen(data);
    if (input_length % 4 != 0) return NULL;

    size_t output_length = input_length / 4 * 3;
    if (input_length > 0) {
        if (data[input_length - 1] == '=') output_length--;
        if (data[input_length - 2] == '=') output_length--;
    }

    uint8_t *decoded = (uint8_t *)malloc(output_length + 1);
    if (!decoded) return NULL;

    int decoding_table[256];
    memset(decoding_table, -1, sizeof(decoding_table));
    for (int i = 0; i < 64; i++) {
        decoding_table[(unsigned char)b64_table[i]] = i;
    }

    size_t i = 0, j = 0;
    while (i < input_length) {
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)data[i++]];

        uint32_t triple = (sextet_a << 18) | (sextet_b << 12) | (sextet_c << 6) | sextet_d;

        if (j < output_length) decoded[j++] = (triple >> 16) & 0xFF;
        if (j < output_length) decoded[j++] = (triple >> 8) & 0xFF;
        if (j < output_length) decoded[j++] = triple & 0xFF;
    }

    decoded[output_length] = '\0';
    if (out_len) *out_len = output_length;
    return decoded;
}

static bool is_printable_utf8(const uint8_t *data, size_t len) {
    if (!data || len == 0) return true;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = data[i];
        if (b == 0) return false;
        if (b < 32 && b != '\n' && b != '\r' && b != '\t') {
            return false;
        }
    }
    return true;
}

StegoResult bridge_hide_advanced(const uint8_t *cover_bytes, size_t cover_len,
                                 const uint8_t *secret_bytes, size_t secret_len,
                                 const char *secret_filename,
                                 const char *passphrase, bool adaptive,
                                 bool compress, int bits_per_channel,
                                 BridgeHideResult *out) {
    if (!out) return STEGO_ERR_INVALID_ARG;
    memset(out, 0, sizeof(BridgeHideResult));

    if (!cover_bytes || cover_len < 8) {
        snprintf(out->error_msg, sizeof(out->error_msg), "That file does not look like a valid image.");
        return STEGO_ERR_INVALID_FORMAT;
    }

    StegoImageFormat fmt = STEGO_FORMAT_UNKNOWN;
    if (!uploads_is_valid_image(cover_bytes, cover_len, &fmt)) {
        snprintf(out->error_msg, sizeof(out->error_msg), "That file does not look like a valid image.");
        return STEGO_ERR_INVALID_FORMAT;
    }

    const char *ext = ".png";
    if (fmt == STEGO_FORMAT_BMP) ext = ".bmp";
    else if (fmt == STEGO_FORMAT_JPEG) ext = ".jpg";
    else if (fmt == STEGO_FORMAT_WEBP) ext = ".webp";
    else if (fmt == STEGO_FORMAT_GIF) ext = ".gif";

    char *tmp_cover = uploads_create_temp_file(cover_bytes, cover_len, ext);
    if (!tmp_cover) {
        snprintf(out->error_msg, sizeof(out->error_msg), "We could not save the file. Please try a different location.");
        return STEGO_ERR_FILE_WRITE;
    }

    char *tmp_secret = uploads_create_temp_file(secret_bytes, secret_len, ".dat");
    if (!tmp_secret) {
        uploads_cleanup_temp_file(tmp_cover);
        free(tmp_cover);
        snprintf(out->error_msg, sizeof(out->error_msg), "Failed to process secret payload.");
        return STEGO_ERR_FILE_WRITE;
    }

    char *tmp_out = uploads_create_temp_file(NULL, 0, ".png");
    if (!tmp_out) {
        uploads_cleanup_temp_file(tmp_cover);
        uploads_cleanup_temp_file(tmp_secret);
        free(tmp_cover);
        free(tmp_secret);
        snprintf(out->error_msg, sizeof(out->error_msg), "Failed to allocate output carrier.");
        return STEGO_ERR_FILE_WRITE;
    }

    /* Check capacity first by opening carrier */
    StegoCarrier *carrier = NULL;
    StegoResult res = stego_carrier_open(tmp_cover, adaptive, &carrier);
    if (res != STEGO_OK) {
        uploads_cleanup_temp_file(tmp_cover);
        uploads_cleanup_temp_file(tmp_secret);
        uploads_cleanup_temp_file(tmp_out);
        free(tmp_cover);
        free(tmp_secret);
        free(tmp_out);
        snprintf(out->error_msg, sizeof(out->error_msg), "That file does not look like a valid image.");
        return res;
    }

    out->width = carrier->image->width;
    out->height = carrier->image->height;

    /* Capacity check */
    StegoCapacityAssessment assess;
    stego_assess_capacity(carrier, secret_filename, secret_len, passphrase && passphrase[0] != '\0',
                          compress, bits_per_channel, &assess);

    if (!assess.fits) {
        out->capacity_exceeded = true;
        snprintf(out->secret_name, sizeof(out->secret_name), "%s", assess.secret_name);
        out->secret_size = assess.secret_size;
        out->available_capacity = assess.available_capacity;
        out->additional_required = assess.additional_required;
        out->rec_min_width = assess.rec_min_width;
        out->rec_min_height = assess.rec_min_height;
        out->rec_square_dim = assess.rec_square_dim;
        snprintf(out->error_msg, sizeof(out->error_msg), "%s", assess.error_summary);

        stego_carrier_close(carrier);
        uploads_cleanup_temp_file(tmp_cover);
        uploads_cleanup_temp_file(tmp_secret);
        uploads_cleanup_temp_file(tmp_out);
        free(tmp_cover);
        free(tmp_secret);
        free(tmp_out);
        return STEGO_ERR_CAPACITY_EXCEEDED;
    }

    if (carrier->image->was_converted || (fmt != STEGO_FORMAT_PNG && fmt != STEGO_FORMAT_BMP)) {
        snprintf(out->notice, sizeof(out->notice),
                 "Input format (%s) was normalized to 8-bit pixels; output is saved as lossless PNG because lossy compression destroys hidden data.",
                 stego_format_name(fmt));
    }

    stego_carrier_close(carrier);

    /* Embed secret using advanced high-level API */
    res = stego_hide_file_unified_advanced(tmp_cover, tmp_out, tmp_secret, passphrase, adaptive, compress, bits_per_channel);

    uploads_cleanup_temp_file(tmp_cover);
    uploads_cleanup_temp_file(tmp_secret);
    free(tmp_cover);
    free(tmp_secret);

    if (res != STEGO_OK) {
        uploads_cleanup_temp_file(tmp_out);
        free(tmp_out);
        snprintf(out->error_msg, sizeof(out->error_msg), "Embedding secret failed: %s", stego_strerror(res));
        return res;
    }

    /* Read generated PNG output into memory */
    FILE *ofp = fopen(tmp_out, "rb");
    if (!ofp) {
        uploads_cleanup_temp_file(tmp_out);
        free(tmp_out);
        snprintf(out->error_msg, sizeof(out->error_msg), "Failed to read generated protected image.");
        return STEGO_ERR_FILE_READ;
    }

    fseek(ofp, 0, SEEK_END);
    long out_size = ftell(ofp);
    fseek(ofp, 0, SEEK_SET);

    if (out_size <= 0) {
        fclose(ofp);
        uploads_cleanup_temp_file(tmp_out);
        free(tmp_out);
        snprintf(out->error_msg, sizeof(out->error_msg), "Generated image was empty.");
        return STEGO_ERR_FILE_READ;
    }

    out->png_data = (uint8_t *)malloc(out_size);
    if (!out->png_data) {
        fclose(ofp);
        uploads_cleanup_temp_file(tmp_out);
        free(tmp_out);
        snprintf(out->error_msg, sizeof(out->error_msg), "Memory allocation failed.");
        return STEGO_ERR_MEMORY;
    }

    fread(out->png_data, 1, out_size, ofp);
    fclose(ofp);
    out->png_size = (size_t)out_size;

    uploads_cleanup_temp_file(tmp_out);
    free(tmp_out);

    bool has_pass = (passphrase && passphrase[0] != '\0');
    out->is_protected = has_pass;
    out->is_compressed = compress;
    out->bits_per_channel = bits_per_channel;
    snprintf(out->envelope_name, sizeof(out->envelope_name), "%s", has_pass ? "CMC2 Encrypted" : "CMC1 Unencrypted");
    snprintf(out->protection_label, sizeof(out->protection_label), "%s", has_pass ? "Password protected" : "Not password protected");

    return STEGO_OK;
}

StegoResult bridge_hide(const uint8_t *cover_bytes, size_t cover_len,
                        const uint8_t *secret_bytes, size_t secret_len,
                        const char *passphrase, bool adaptive,
                        BridgeHideResult *out) {
    return bridge_hide_advanced(cover_bytes, cover_len, secret_bytes, secret_len,
                                "secret.dat", passphrase, adaptive, false, 1, out);
}

StegoResult bridge_split_hide(const uint8_t **cover_bytes_array, const size_t *cover_lens,
                              uint16_t num_covers,
                              const uint8_t *secret_bytes, size_t secret_len,
                              const char *secret_filename,
                              const char *passphrase, bool compress, int bits_per_channel,
                              BridgeSplitHideResult *out) {
    if (!out) return STEGO_ERR_INVALID_ARG;
    memset(out, 0, sizeof(BridgeSplitHideResult));

    if (!cover_bytes_array || !cover_lens || num_covers == 0 || !secret_bytes) {
        snprintf(out->error_msg, sizeof(out->error_msg), "Missing required inputs for split embedding.");
        return STEGO_ERR_INVALID_ARG;
    }

    char *tmp_secret = uploads_create_temp_file(secret_bytes, secret_len, ".dat");
    if (!tmp_secret) {
        snprintf(out->error_msg, sizeof(out->error_msg), "Failed to save secret file.");
        return STEGO_ERR_FILE_WRITE;
    }

    char *tmp_covers[STEGO_MAX_SPLIT_PARTS] = {0};
    for (uint16_t i = 0; i < num_covers; i++) {
        StegoImageFormat fmt = STEGO_FORMAT_PNG;
        uploads_is_valid_image(cover_bytes_array[i], cover_lens[i], &fmt);
        const char *ext = (fmt == STEGO_FORMAT_BMP) ? ".bmp" : ".png";
        tmp_covers[i] = uploads_create_temp_file(cover_bytes_array[i], cover_lens[i], ext);
    }

    char tmp_prefix[512];
    snprintf(tmp_prefix, sizeof(tmp_prefix), "%s_split", tmp_secret);

    StegoManifest manifest;
    char err_msg[512] = {0};
    StegoResult res = stego_split_embed(tmp_secret, (const char **)tmp_covers, num_covers,
                                        tmp_prefix, passphrase, compress, bits_per_channel,
                                        &manifest, err_msg, sizeof(err_msg));

    uploads_cleanup_temp_file(tmp_secret);
    free(tmp_secret);
    for (uint16_t i = 0; i < num_covers; i++) {
        if (tmp_covers[i]) {
            uploads_cleanup_temp_file(tmp_covers[i]);
            free(tmp_covers[i]);
        }
    }

    if (res != STEGO_OK) {
        snprintf(out->error_msg, sizeof(out->error_msg), "%s", err_msg[0] ? err_msg : "Split embedding failed.");
        return res;
    }

    out->total_parts = manifest.total_parts;

    for (uint16_t i = 0; i < manifest.total_parts; i++) {
        const char *part_path = manifest.parts[i].part_path;
        out->parts[i].part_num = manifest.parts[i].part_num;
        snprintf(out->parts[i].filename, sizeof(out->parts[i].filename), "%s_part%u_of_%u.png",
                 secret_filename ? secret_filename : "secret", i + 1, manifest.total_parts);

        FILE *fp = fopen(part_path, "rb");
        if (fp) {
            fseek(fp, 0, SEEK_END);
            long sz = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            if (sz > 0) {
                out->parts[i].png_data = (uint8_t *)malloc(sz);
                if (out->parts[i].png_data) {
                    fread(out->parts[i].png_data, 1, sz, fp);
                    out->parts[i].png_size = (size_t)sz;
                }
            }
            fclose(fp);
            remove(part_path);
        }
    }

    char manifest_path[512];
    snprintf(manifest_path, sizeof(manifest_path), "%s_manifest.json", tmp_prefix);
    FILE *mfp = fopen(manifest_path, "rb");
    if (mfp) {
        fread(out->manifest_json, 1, sizeof(out->manifest_json) - 1, mfp);
        fclose(mfp);
        remove(manifest_path);
    }

    return STEGO_OK;
}

StegoResult bridge_split_reveal(const uint8_t **stego_bytes_array, const size_t *stego_lens,
                                uint16_t num_stego_images,
                                const char *passphrase,
                                BridgeRevealResult *out) {
    if (!out) return STEGO_ERR_INVALID_ARG;
    memset(out, 0, sizeof(BridgeRevealResult));

    if (!stego_bytes_array || !stego_lens || num_stego_images == 0) {
        snprintf(out->error_msg, sizeof(out->error_msg), "No part images provided.");
        return STEGO_ERR_INVALID_ARG;
    }

    char *tmp_parts[STEGO_MAX_SPLIT_PARTS] = {0};
    for (uint16_t i = 0; i < num_stego_images; i++) {
        tmp_parts[i] = uploads_create_temp_file(stego_bytes_array[i], stego_lens[i], ".png");
    }

    char *tmp_out = uploads_create_temp_file(NULL, 0, ".dat");
    char err_msg[512] = {0};
    StegoResult res = stego_split_extract((const char **)tmp_parts, num_stego_images, tmp_out,
                                          passphrase, err_msg, sizeof(err_msg));

    for (uint16_t i = 0; i < num_stego_images; i++) {
        if (tmp_parts[i]) {
            uploads_cleanup_temp_file(tmp_parts[i]);
            free(tmp_parts[i]);
        }
    }

    if (res != STEGO_OK) {
        if (tmp_out) {
            uploads_cleanup_temp_file(tmp_out);
            free(tmp_out);
        }
        snprintf(out->error_msg, sizeof(out->error_msg), "%s", err_msg[0] ? err_msg : "Multi-part extraction failed.");
        return res;
    }

    FILE *ofp = fopen(tmp_out, "rb");
    if (!ofp) {
        uploads_cleanup_temp_file(tmp_out);
        free(tmp_out);
        snprintf(out->error_msg, sizeof(out->error_msg), "Failed to read recovered secret file.");
        return STEGO_ERR_FILE_READ;
    }

    fseek(ofp, 0, SEEK_END);
    long sz = ftell(ofp);
    fseek(ofp, 0, SEEK_SET);

    if (sz >= 0) {
        uint8_t *raw_buf = (uint8_t *)malloc(sz > 0 ? sz : 1);
        if (sz > 0) fread(raw_buf, 1, sz, ofp);
        fclose(ofp);
        uploads_cleanup_temp_file(tmp_out);
        free(tmp_out);

        if (stego_file_payload_is_fil1(raw_buf, (size_t)sz)) {
            StegoFileMetadata meta;
            memset(&meta, 0, sizeof(meta));
            uint8_t *restored_file = NULL;
            size_t restored_len = 0;
            res = stego_file_payload_unpack(raw_buf, (size_t)sz, &meta, &restored_file, &restored_len);
            stego_secure_zero(raw_buf, (size_t)sz);
            free(raw_buf);

            if (res != STEGO_OK) {
                snprintf(out->error_msg, sizeof(out->error_msg),
                         "File integrity verification failed: Cryptographic SHA-256 mismatch or file corruption.");
                return STEGO_ERR_CORRUPT_PAYLOAD;
            }

            out->payload_data = restored_file;
            out->payload_size = restored_len;
            out->is_text = is_printable_utf8(restored_file, restored_len);
            out->is_file = !out->is_text;
            snprintf(out->filename, sizeof(out->filename), "%s", meta.filename);
            snprintf(out->sha256_hex, sizeof(out->sha256_hex), "%s", meta.sha256_hex);
        } else {
            out->payload_data = raw_buf;
            out->payload_size = (size_t)sz;
            out->is_text = is_printable_utf8(raw_buf, (size_t)sz);
            out->is_file = !out->is_text;
            if (out->is_file) {
                snprintf(out->filename, sizeof(out->filename), "recovered_file.bin");
            } else {
                snprintf(out->filename, sizeof(out->filename), "recovered_secret.txt");
            }
            stego_sha256_hex(raw_buf, (size_t)sz, out->sha256_hex);
        }
    } else {
        fclose(ofp);
        uploads_cleanup_temp_file(tmp_out);
        free(tmp_out);
    }

    out->is_protected = (passphrase && passphrase[0] != '\0');
    snprintf(out->envelope_name, sizeof(out->envelope_name), "%s", out->is_protected ? "CMC4 Encrypted Multi-Part" : "CMC3 Unencrypted Multi-Part");
    snprintf(out->protection_label, sizeof(out->protection_label), "%s", out->is_protected ? "Password protected" : "Not password protected");

    return STEGO_OK;
}

StegoResult bridge_reveal(const uint8_t *stego_bytes, size_t stego_len,
                          const char *passphrase,
                          BridgeRevealResult *out) {
    if (!out) return STEGO_ERR_INVALID_ARG;
    memset(out, 0, sizeof(BridgeRevealResult));

    if (!stego_bytes || stego_len < 8) {
        snprintf(out->error_msg, sizeof(out->error_msg), "That file does not look like a valid image.");
        return STEGO_ERR_INVALID_FORMAT;
    }

    StegoImageFormat fmt = STEGO_FORMAT_UNKNOWN;
    if (!uploads_is_valid_image(stego_bytes, stego_len, &fmt)) {
        snprintf(out->error_msg, sizeof(out->error_msg), "That file does not look like a valid image.");
        return STEGO_ERR_INVALID_FORMAT;
    }

    const char *ext = ".png";
    if (fmt == STEGO_FORMAT_BMP) ext = ".bmp";
    char *tmp_stego = uploads_create_temp_file(stego_bytes, stego_len, ext);
    if (!tmp_stego) {
        snprintf(out->error_msg, sizeof(out->error_msg), "Failed to process image.");
        return STEGO_ERR_FILE_WRITE;
    }

    StegoCarrier *carrier = NULL;
    StegoResult res = stego_carrier_open(tmp_stego, false, &carrier);
    if (res != STEGO_OK) {
        uploads_cleanup_temp_file(tmp_stego);
        free(tmp_stego);
        snprintf(out->error_msg, sizeof(out->error_msg), "That file does not look like a valid image.");
        return res;
    }

    uint32_t detected_len = 0;
    bool det_adapt = false;
    int det_bpc = 1;
    StegoEnvelopeType env = png_detect_envelope_detailed(carrier->image, &det_adapt, &det_bpc, &detected_len);

    if (env == STEGO_ENVELOPE_NONE) {
        stego_carrier_close(carrier);
        uploads_cleanup_temp_file(tmp_stego);
        free(tmp_stego);
        snprintf(out->error_msg, sizeof(out->error_msg), "No hidden secret was found in this image.");
        return STEGO_ERR_NO_PAYLOAD;
    }

    if (env == STEGO_ENVELOPE_CMC3 || env == STEGO_ENVELOPE_CMC4) {
        uint8_t hdr[162];
        png_extract_raw_bits(carrier->image, hdr, (env == STEGO_ENVELOPE_CMC4) ? STEGO_CMC4_HEADER_SIZE : STEGO_CMC3_HEADER_SIZE, det_adapt, det_bpc);
        stego_carrier_close(carrier);
        uploads_cleanup_temp_file(tmp_stego);
        free(tmp_stego);

        uint16_t tot = ((uint16_t)hdr[4] << 8) | (uint16_t)hdr[5];
        uint16_t num = ((uint16_t)hdr[6] << 8) | (uint16_t)hdr[7];
        out->is_split_part = true;
        out->part_num = num;
        out->total_parts = tot;
        snprintf(out->error_msg, sizeof(out->error_msg),
                 "This image is Part %u of %u of a split secret. Please use Multi-Image Reveal to recombine all %u parts.",
                 num, tot, tot);
        return STEGO_ERR_INVALID_FORMAT;
    }

    bool has_pass = (passphrase && passphrase[0] != '\0');

    if (env == STEGO_ENVELOPE_CMC2) {
        out->is_protected = true;
        if (det_bpc > 1) {
            snprintf(out->envelope_name, sizeof(out->envelope_name), "CMC2 Encrypted (%d-bit)", det_bpc);
        } else {
            snprintf(out->envelope_name, sizeof(out->envelope_name), "CMC2 Encrypted");
        }
        snprintf(out->protection_label, sizeof(out->protection_label), "Password protected");

        if (!has_pass) {
            stego_carrier_close(carrier);
            uploads_cleanup_temp_file(tmp_stego);
            free(tmp_stego);
            snprintf(out->error_msg, sizeof(out->error_msg), "This image is password protected. Please enter the password.");
            return STEGO_ERR_AUTH_FAILED;
        }
    } else {
        out->is_protected = false;
        if (det_bpc > 1) {
            snprintf(out->envelope_name, sizeof(out->envelope_name), "CMC1 Unencrypted (%d-bit)", det_bpc);
        } else {
            snprintf(out->envelope_name, sizeof(out->envelope_name), "CMC1 Unencrypted");
        }
        snprintf(out->protection_label, sizeof(out->protection_label), "Not password protected");
    }

    uint8_t *payload = NULL;
    size_t payload_len = 0;
    res = carrier->extract_secure(carrier, has_pass ? passphrase : NULL, &payload, &payload_len);
    stego_carrier_close(carrier);
    uploads_cleanup_temp_file(tmp_stego);
    free(tmp_stego);

    if (res != STEGO_OK) {
        snprintf(out->error_msg, sizeof(out->error_msg), "The password is incorrect, or the image was changed or damaged.");
        return res;
    }

    /* Check decompression */
    uint8_t *decomp_payload = NULL;
    size_t decomp_len = 0;
    bool was_decomp = false;
    stego_decompress_payload_if_packed(payload, payload_len, &decomp_payload, &decomp_len, &was_decomp);

    uint8_t *working_payload = was_decomp ? decomp_payload : payload;
    size_t working_len = was_decomp ? decomp_len : payload_len;

    /* Check for FIL1 authenticated file container */
    if (stego_file_payload_is_fil1(working_payload, working_len)) {
        StegoFileMetadata meta;
        memset(&meta, 0, sizeof(meta));
        uint8_t *restored_file = NULL;
        size_t restored_len = 0;
        res = stego_file_payload_unpack(working_payload, working_len, &meta, &restored_file, &restored_len);
        if (res != STEGO_OK) {
            if (decomp_payload) {
                stego_secure_zero(decomp_payload, decomp_len);
                free(decomp_payload);
            }
            stego_secure_zero(payload, payload_len);
            free(payload);
            snprintf(out->error_msg, sizeof(out->error_msg),
                     "File integrity verification failed: Cryptographic SHA-256 mismatch or file corruption.");
            return STEGO_ERR_CORRUPT_PAYLOAD;
        }

        out->payload_data = restored_file;
        out->payload_size = restored_len;
        out->is_text = is_printable_utf8(restored_file, restored_len);
        out->is_file = !out->is_text;
        snprintf(out->filename, sizeof(out->filename), "%s", meta.filename);
        snprintf(out->sha256_hex, sizeof(out->sha256_hex), "%s", meta.sha256_hex);
    } else {
        out->payload_data = (uint8_t *)malloc(working_len > 0 ? working_len : 1);
        if (out->payload_data && working_len > 0) {
            memcpy(out->payload_data, working_payload, working_len);
        }
        out->payload_size = working_len;
        out->is_text = is_printable_utf8(working_payload, working_len);
        out->is_file = !out->is_text;
        if (out->is_file) {
            snprintf(out->filename, sizeof(out->filename), "recovered_file.bin");
        } else {
            snprintf(out->filename, sizeof(out->filename), "recovered_secret.txt");
        }
        stego_sha256_hex(working_payload, working_len, out->sha256_hex);
    }

    if (decomp_payload) {
        stego_secure_zero(decomp_payload, decomp_len);
        free(decomp_payload);
    }
    stego_secure_zero(payload, payload_len);
    free(payload);

    return STEGO_OK;
}

StegoResult bridge_verify(const uint8_t *img_bytes, size_t img_len,
                          BridgeVerifyResult *out) {
    if (!out) return STEGO_ERR_INVALID_ARG;
    memset(out, 0, sizeof(BridgeVerifyResult));

    if (!img_bytes || img_len < 8) {
        snprintf(out->error_msg, sizeof(out->error_msg), "That file does not look like a valid image.");
        return STEGO_ERR_INVALID_FORMAT;
    }

    StegoImageFormat fmt = STEGO_FORMAT_UNKNOWN;
    if (!uploads_is_valid_image(img_bytes, img_len, &fmt)) {
        snprintf(out->error_msg, sizeof(out->error_msg), "That file does not look like a valid image.");
        return STEGO_ERR_INVALID_FORMAT;
    }

    const char *ext = (fmt == STEGO_FORMAT_BMP) ? ".bmp" : ".png";
    char *tmp_img = uploads_create_temp_file(img_bytes, img_len, ext);
    if (!tmp_img) {
        snprintf(out->error_msg, sizeof(out->error_msg), "Failed to process image.");
        return STEGO_ERR_FILE_WRITE;
    }

    StegoCarrier *carrier = NULL;
    StegoResult res = stego_carrier_open(tmp_img, false, &carrier);
    if (res != STEGO_OK) {
        uploads_cleanup_temp_file(tmp_img);
        free(tmp_img);
        snprintf(out->error_msg, sizeof(out->error_msg), "That file does not look like a valid image.");
        return res;
    }

    uint32_t detected_len = 0;
    bool det_adapt = false;
    int det_bpc = 1;
    StegoEnvelopeType env = png_detect_envelope_detailed(carrier->image, &det_adapt, &det_bpc, &detected_len);

    stego_carrier_close(carrier);
    uploads_cleanup_temp_file(tmp_img);
    free(tmp_img);

    if (env == STEGO_ENVELOPE_CMC2) {
        out->has_payload = true;
        out->is_protected = true;
        out->payload_length = detected_len;
        if (det_bpc > 1) {
            snprintf(out->envelope_name, sizeof(out->envelope_name), "CMC2 Encrypted (%d-bit)", det_bpc);
        } else {
            snprintf(out->envelope_name, sizeof(out->envelope_name), "CMC2 Encrypted");
        }
        snprintf(out->protection_label, sizeof(out->protection_label), "Password protected");
    } else if (env == STEGO_ENVELOPE_CMC1) {
        out->has_payload = true;
        out->is_protected = false;
        out->payload_length = detected_len;
        if (det_bpc > 1) {
            snprintf(out->envelope_name, sizeof(out->envelope_name), "CMC1 Unencrypted (%d-bit)", det_bpc);
        } else {
            snprintf(out->envelope_name, sizeof(out->envelope_name), "CMC1 Unencrypted");
        }
        snprintf(out->protection_label, sizeof(out->protection_label), "Not password protected");
    } else if (env == STEGO_ENVELOPE_CMC4) {
        out->has_payload = true;
        out->is_protected = true;
        out->payload_length = detected_len;
        snprintf(out->envelope_name, sizeof(out->envelope_name), "CMC4 Encrypted Multi-Part");
        snprintf(out->protection_label, sizeof(out->protection_label), "Password protected (Split Part)");
    } else if (env == STEGO_ENVELOPE_CMC3) {
        out->has_payload = true;
        out->is_protected = false;
        out->payload_length = detected_len;
        snprintf(out->envelope_name, sizeof(out->envelope_name), "CMC3 Unencrypted Multi-Part");
        snprintf(out->protection_label, sizeof(out->protection_label), "Not password protected (Split Part)");
    } else {
        out->has_payload = false;
        out->is_protected = false;
        out->payload_length = 0;
        snprintf(out->envelope_name, sizeof(out->envelope_name), "None");
        snprintf(out->protection_label, sizeof(out->protection_label), "No hidden payload");
    }

    return STEGO_OK;
}

StegoResult bridge_capacity(const uint8_t *img_bytes, size_t img_len,
                            bool adaptive,
                            BridgeCapacityResult *out) {
    if (!out) return STEGO_ERR_INVALID_ARG;
    memset(out, 0, sizeof(BridgeCapacityResult));

    if (!img_bytes || img_len < 8) {
        snprintf(out->error_msg, sizeof(out->error_msg), "That file does not look like a valid image.");
        return STEGO_ERR_INVALID_FORMAT;
    }

    StegoImageFormat fmt = STEGO_FORMAT_UNKNOWN;
    if (!uploads_is_valid_image(img_bytes, img_len, &fmt)) {
        snprintf(out->error_msg, sizeof(out->error_msg), "That file does not look like a valid image.");
        return STEGO_ERR_INVALID_FORMAT;
    }

    const char *ext = (fmt == STEGO_FORMAT_BMP) ? ".bmp" : ".png";
    char *tmp_img = uploads_create_temp_file(img_bytes, img_len, ext);
    if (!tmp_img) {
        snprintf(out->error_msg, sizeof(out->error_msg), "Failed to process image.");
        return STEGO_ERR_FILE_WRITE;
    }

    StegoCarrier *carrier = NULL;
    StegoResult res = stego_carrier_open(tmp_img, adaptive, &carrier);
    if (res != STEGO_OK) {
        uploads_cleanup_temp_file(tmp_img);
        free(tmp_img);
        snprintf(out->error_msg, sizeof(out->error_msg), "That file does not look like a valid image.");
        return res;
    }

    snprintf(out->format, sizeof(out->format), "%s", stego_format_name(fmt));
    snprintf(out->original_mode, sizeof(out->original_mode), "%s (%d-bit)",
             carrier->image->orig_color_mode, carrier->image->orig_bit_depth);
    snprintf(out->normalized_mode, sizeof(out->normalized_mode), "8-bit %s",
             carrier->image->channels == 4 ? "RGBA" : "RGB");
    out->width = carrier->image->width;
    out->height = carrier->image->height;
    out->channels = carrier->image->channels;
    out->was_converted = carrier->image->was_converted;

    size_t raw_1bit = png_raw_capacity_bits(carrier->image, adaptive, 1);
    size_t raw_2bit = png_raw_capacity_bits(carrier->image, adaptive, 2);
    size_t raw_3bit = png_raw_capacity_bits(carrier->image, adaptive, 3);

    out->unencrypted_capacity = (raw_1bit > STEGO_CMC1_HEADER_SIZE) ? (raw_1bit - STEGO_CMC1_HEADER_SIZE) : 0;
    out->encrypted_capacity = (raw_1bit > STEGO_CMC2_HEADER_SIZE) ? (raw_1bit - STEGO_CMC2_HEADER_SIZE) : 0;
    out->capacity_2bit = (raw_2bit > STEGO_CMC2_HEADER_SIZE) ? (raw_2bit - STEGO_CMC2_HEADER_SIZE) : 0;
    out->capacity_3bit = (raw_3bit > STEGO_CMC2_HEADER_SIZE) ? (raw_3bit - STEGO_CMC2_HEADER_SIZE) : 0;

    uint32_t detected_len = 0;
    bool det_adapt = false;
    int det_bpc = 1;
    StegoEnvelopeType env = png_detect_envelope_detailed(carrier->image, &det_adapt, &det_bpc, &detected_len);

    out->has_payload = (env != STEGO_ENVELOPE_NONE);
    if (env == STEGO_ENVELOPE_CMC2) {
        snprintf(out->envelope_name, sizeof(out->envelope_name), "CMC2 Encrypted (%u bytes, %d-bit)", detected_len, det_bpc);
    } else if (env == STEGO_ENVELOPE_CMC1) {
        snprintf(out->envelope_name, sizeof(out->envelope_name), "CMC1 Unencrypted (%u bytes, %d-bit)", detected_len, det_bpc);
    } else if (env == STEGO_ENVELOPE_CMC4) {
        snprintf(out->envelope_name, sizeof(out->envelope_name), "CMC4 Encrypted Multi-Part");
    } else if (env == STEGO_ENVELOPE_CMC3) {
        snprintf(out->envelope_name, sizeof(out->envelope_name), "CMC3 Unencrypted Multi-Part");
    } else {
        snprintf(out->envelope_name, sizeof(out->envelope_name), "None");
    }

    if (carrier->image->was_converted || (fmt != STEGO_FORMAT_PNG && fmt != STEGO_FORMAT_BMP)) {
        snprintf(out->notice, sizeof(out->notice),
                 "Input format (%s) will be normalized to 8-bit RGB/RGBA; stego output is always saved as lossless PNG.",
                 stego_format_name(fmt));
    }

    stego_carrier_close(carrier);
    uploads_cleanup_temp_file(tmp_img);
    free(tmp_img);

    return STEGO_OK;
}

void bridge_hide_result_free(BridgeHideResult *res) {
    if (!res) return;
    if (res->png_data) {
        free(res->png_data);
        res->png_data = NULL;
    }
}

void bridge_split_hide_result_free(BridgeSplitHideResult *res) {
    if (!res) return;
    for (uint16_t i = 0; i < res->total_parts && i < STEGO_MAX_SPLIT_PARTS; i++) {
        if (res->parts[i].png_data) {
            free(res->parts[i].png_data);
            res->parts[i].png_data = NULL;
        }
    }
}

void bridge_reveal_result_free(BridgeRevealResult *res) {
    if (!res) return;
    if (res->payload_data) {
        stego_secure_zero(res->payload_data, res->payload_size);
        free(res->payload_data);
        res->payload_data = NULL;
    }
}

StegoResult bridge_metadata_scan(const uint8_t *img_bytes, size_t img_len,
                                 BridgeMetadataScanResult *out) {
    if (!out) return STEGO_ERR_INVALID_ARG;
    memset(out, 0, sizeof(BridgeMetadataScanResult));

    if (!img_bytes || img_len < 8) {
        snprintf(out->error_msg, sizeof(out->error_msg), "Invalid image data.");
        return STEGO_ERR_INVALID_FORMAT;
    }

    StegoImageFormat fmt = STEGO_FORMAT_UNKNOWN;
    if (!uploads_is_valid_image(img_bytes, img_len, &fmt)) {
        snprintf(out->error_msg, sizeof(out->error_msg), "Invalid image format.");
        return STEGO_ERR_INVALID_FORMAT;
    }

    const char *ext = ".jpg";
    if (fmt == STEGO_FORMAT_PNG) ext = ".png";
    else if (fmt == STEGO_FORMAT_BMP) ext = ".bmp";
    else if (fmt == STEGO_FORMAT_WEBP) ext = ".webp";

    char *tmp_path = uploads_create_temp_file(img_bytes, img_len, ext);
    if (!tmp_path) {
        snprintf(out->error_msg, sizeof(out->error_msg), "Failed to process image.");
        return STEGO_ERR_FILE_WRITE;
    }

    StegoMetadataInfo info;
    StegoResult res = stego_metadata_scan(tmp_path, &info);
    uploads_cleanup_temp_file(tmp_path);
    free(tmp_path);

    if (res != STEGO_OK) {
        snprintf(out->error_msg, sizeof(out->error_msg), "Failed to scan image metadata: %s", stego_strerror(res));
        return res;
    }

    out->has_exif = info.has_exif;
    out->has_gps = info.has_gps;
    out->has_camera_info = info.has_camera_info;
    snprintf(out->camera_make, sizeof(out->camera_make), "%s", info.camera_make);
    snprintf(out->camera_model, sizeof(out->camera_model), "%s", info.camera_model);
    snprintf(out->software, sizeof(out->software), "%s", info.software);
    snprintf(out->datetime, sizeof(out->datetime), "%s", info.datetime);
    out->latitude = info.latitude;
    out->longitude = info.longitude;
    snprintf(out->latitude_ref, sizeof(out->latitude_ref), "%s", info.latitude_ref);
    snprintf(out->longitude_ref, sizeof(out->longitude_ref), "%s", info.longitude_ref);
    out->altitude = info.altitude;
    out->has_altitude = info.has_altitude;
    snprintf(out->gps_timestamp, sizeof(out->gps_timestamp), "%s", info.gps_timestamp);
    out->has_timestamp = info.has_timestamp;
    snprintf(out->risk_level, sizeof(out->risk_level), "%s", info.risk_level[0] ? info.risk_level : "Low");
    snprintf(out->risk_reason, sizeof(out->risk_reason), "%s", info.risk_reason);
    out->metadata_bytes = info.metadata_bytes;

    return STEGO_OK;
}

StegoResult bridge_metadata_strip(const uint8_t *img_bytes, size_t img_len,
                                  const char *orig_filename,
                                  BridgeMetadataStripResult *out) {
    if (!out) return STEGO_ERR_INVALID_ARG;
    memset(out, 0, sizeof(BridgeMetadataStripResult));

    if (!img_bytes || img_len < 8) {
        snprintf(out->error_msg, sizeof(out->error_msg), "Invalid image data.");
        return STEGO_ERR_INVALID_FORMAT;
    }

    StegoImageFormat fmt = STEGO_FORMAT_UNKNOWN;
    if (!uploads_is_valid_image(img_bytes, img_len, &fmt)) {
        snprintf(out->error_msg, sizeof(out->error_msg), "Invalid image format.");
        return STEGO_ERR_INVALID_FORMAT;
    }

    const char *ext = ".jpg";
    if (fmt == STEGO_FORMAT_PNG) ext = ".png";
    else if (fmt == STEGO_FORMAT_BMP) ext = ".bmp";
    else if (fmt == STEGO_FORMAT_WEBP) ext = ".webp";

    char *tmp_in = uploads_create_temp_file(img_bytes, img_len, ext);
    if (!tmp_in) {
        snprintf(out->error_msg, sizeof(out->error_msg), "Failed to create temporary file.");
        return STEGO_ERR_FILE_WRITE;
    }

    char *tmp_out = uploads_create_temp_file(NULL, 0, ext);
    if (!tmp_out) {
        uploads_cleanup_temp_file(tmp_in);
        free(tmp_in);
        snprintf(out->error_msg, sizeof(out->error_msg), "Failed to create output file.");
        return STEGO_ERR_FILE_WRITE;
    }

    StegoResult res = stego_metadata_strip(tmp_in, tmp_out);
    uploads_cleanup_temp_file(tmp_in);
    free(tmp_in);

    if (res != STEGO_OK) {
        uploads_cleanup_temp_file(tmp_out);
        free(tmp_out);
        snprintf(out->error_msg, sizeof(out->error_msg), "Failed to strip metadata: %s", stego_strerror(res));
        return res;
    }

    FILE *fp = fopen(tmp_out, "rb");
    if (!fp) {
        uploads_cleanup_temp_file(tmp_out);
        free(tmp_out);
        snprintf(out->error_msg, sizeof(out->error_msg), "Failed to read stripped image.");
        return STEGO_ERR_FILE_READ;
    }

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (sz <= 0) {
        fclose(fp);
        uploads_cleanup_temp_file(tmp_out);
        free(tmp_out);
        snprintf(out->error_msg, sizeof(out->error_msg), "Stripped image is empty.");
        return STEGO_ERR_FILE_READ;
    }

    out->clean_image_data = (uint8_t *)malloc(sz);
    if (!out->clean_image_data) {
        fclose(fp);
        uploads_cleanup_temp_file(tmp_out);
        free(tmp_out);
        return STEGO_ERR_MEMORY;
    }

    fread(out->clean_image_data, 1, sz, fp);
    fclose(fp);
    out->clean_image_size = (size_t)sz;
    uploads_cleanup_temp_file(tmp_out);
    free(tmp_out);

    snprintf(out->format, sizeof(out->format), "%s", stego_format_name(fmt));
    if (orig_filename && orig_filename[0] != '\0') {
        const char *dot = strrchr(orig_filename, '.');
        if (dot) {
            size_t base_len = (size_t)(dot - orig_filename);
            snprintf(out->clean_filename, sizeof(out->clean_filename), "%.*s_clean%s", (int)base_len, orig_filename, dot);
        } else {
            snprintf(out->clean_filename, sizeof(out->clean_filename), "%s_clean%s", orig_filename, ext);
        }
    } else {
        snprintf(out->clean_filename, sizeof(out->clean_filename), "clean_image%s", ext);
    }

    if (img_len > out->clean_image_size) {
        out->bytes_removed = img_len - out->clean_image_size;
    } else {
        out->bytes_removed = 0;
    }

    return STEGO_OK;
}

void bridge_metadata_strip_result_free(BridgeMetadataStripResult *res) {
    if (!res) return;
    if (res->clean_image_data) {
        free(res->clean_image_data);
        res->clean_image_data = NULL;
    }
}
