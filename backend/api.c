/**
 * @file api.c
 * @brief JSON API routing and endpoint implementations.
 */

#include "api.h"
#include "uploads.h"
#include "stego_bridge.h"
#include "core/stego_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#endif

static void api_save_image(const char *dir, const char *filename, const uint8_t *data, size_t size) {
    if (!dir || !filename || !data || size == 0) return;
#if defined(_WIN32)
    _mkdir("images");
    _mkdir(dir);
#else
    mkdir("images", 0755);
    mkdir(dir, 0755);
#endif
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, filename);
    FILE *fp = fopen(path, "wb");
    if (fp) {
        fwrite(data, 1, size, fp);
        fclose(fp);
    }
}

/* Helper to escape strings for JSON */
static char *json_escape(const char *str) {
    if (!str) return strdup("");
    size_t len = strlen(str);
    size_t cap = len * 2 + 16;
    char *out = (char *)malloc(cap);
    if (!out) return strdup("");

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)str[i];
        if (j + 8 >= cap) {
            cap *= 2;
            char *new_out = (char *)realloc(out, cap);
            if (!new_out) {
                free(out);
                return strdup("");
            }
            out = new_out;
        }

        switch (c) {
            case '"':  out[j++] = '\\'; out[j++] = '"'; break;
            case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
            case '\b': out[j++] = '\\'; out[j++] = 'b'; break;
            case '\f': out[j++] = '\\'; out[j++] = 'f'; break;
            case '\n': out[j++] = '\\'; out[j++] = 'n'; break;
            case '\r': out[j++] = '\\'; out[j++] = 'r'; break;
            case '\t': out[j++] = '\\'; out[j++] = 't'; break;
            default:
                if (c < 32) {
                    j += snprintf(out + j, 7, "\\u%04x", c);
                } else {
                    out[j++] = c;
                }
                break;
        }
    }
    out[j] = '\0';
    return out;
}

static void api_respond_error(HttpResponse *res, int status_code, const char *msg) {
    char *esc = json_escape(msg);
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"success\":false,\"error\":\"%s\",\"code\":%d}",
             esc ? esc : "Unknown error", status_code);
    if (esc) free(esc);
    http_response_set_json(res, status_code, json);
}

static void handle_health(const HttpRequest *req, HttpResponse *res) {
    (void)req;
    http_response_set_json(res, 200,
        "{\"status\":\"healthy\",\"version\":\"1.0.0\","
        "\"app\":\"Hushframe\","
        "\"tagline\":\"Keep what matters out of sight.\","
        "\"engine\":\"Hushframe core (Argon2id + AES-256-GCM)\","
        "\"protection\":[\"Argon2id\",\"AES-256-GCM\",\"CMC1\",\"CMC2\",\"CMC3\",\"CMC4\"],"
        "\"server\":\"hushframe-server\",\"offline\":true}");
}

static void handle_hide(const HttpRequest *req, HttpResponse *res) {
    if (req->method != HTTP_METHOD_POST) {
        api_respond_error(res, 405, "Method not allowed. Use POST.");
        return;
    }

    if (req->boundary[0] == '\0') {
        api_respond_error(res, 400, "Invalid request. Expected multipart/form-data.");
        return;
    }

    MultipartForm *form = multipart_parse(req->body, req->body_len, req->boundary);
    if (!form) {
        api_respond_error(res, 400, "Failed to parse uploaded form data.");
        return;
    }

    const UploadPart *cover_part = multipart_get_part(form, "cover");
    if (!cover_part || !cover_part->data || cover_part->size == 0) {
        cover_part = multipart_get_part(form, "image");
    }
    if (!cover_part || !cover_part->data || cover_part->size == 0) {
        cover_part = multipart_get_part(form, "file");
    }

    if (!cover_part || !cover_part->data || cover_part->size == 0) {
        multipart_free(form);
        api_respond_error(res, 400, "The selected file is not a supported image format. Select a valid PNG, JPEG, BMP, WEBP, or GIF image.");
        return;
    }

    /* Secret payload */
    const char *secret_type = multipart_get_string(form, "secret_type");
    const uint8_t *secret_data = NULL;
    size_t secret_len = 0;

    const UploadPart *secret_file_part = multipart_get_part(form, "secret_file");
    const char *message_str = multipart_get_string(form, "message");

    if (secret_type && strcmp(secret_type, "file") == 0) {
        if (!secret_file_part || !secret_file_part->data || secret_file_part->size == 0) {
            multipart_free(form);
            api_respond_error(res, 400, "Select a file to protect.");
            return;
        }
        secret_data = secret_file_part->data;
        secret_len = secret_file_part->size;
    } else {
        if (!message_str || message_str[0] == '\0') {
            /* Try secret_file as fallback */
            if (secret_file_part && secret_file_part->data && secret_file_part->size > 0) {
                secret_data = secret_file_part->data;
                secret_len = secret_file_part->size;
            } else {
                multipart_free(form);
                api_respond_error(res, 400, "Enter a text message or select a file to protect.");
                return;
            }
        } else {
            secret_data = (const uint8_t *)message_str;
            secret_len = strlen(message_str);
        }
    }

    /* Passphrase */
    const char *passphrase = multipart_get_string(form, "password");
    if (!passphrase) passphrase = multipart_get_string(form, "passphrase");

    const char *confirm_unprot = multipart_get_string(form, "confirm_unprotected");
    bool unprot_confirmed = (confirm_unprot && (strcmp(confirm_unprot, "true") == 0 || strcmp(confirm_unprot, "1") == 0));

    if ((!passphrase || passphrase[0] == '\0') && !unprot_confirmed) {
        multipart_free(form);
        char json[512];
        snprintf(json, sizeof(json),
                 "{\"success\":false,\"requires_confirmation\":true,"
                 "\"error\":\"No password was provided. Anyone who opens this image will be able to recover the file.\"}");
        http_response_set_json(res, 400, json);
        return;
    }

    /* Adaptive mode */
    const char *adaptive_str = multipart_get_string(form, "adaptive");
    bool adaptive = (adaptive_str && (strcmp(adaptive_str, "true") == 0 || strcmp(adaptive_str, "1") == 0));

    /* Compression option */
    const char *compress_str = multipart_get_string(form, "compress");
    bool compress = (compress_str && (strcmp(compress_str, "true") == 0 || strcmp(compress_str, "1") == 0));

    /* Bit depth option (1, 2, or 3) */
    const char *bits_str = multipart_get_string(form, "bits");
    int bits = bits_str ? atoi(bits_str) : 1;
    if (bits < 1 || bits > 3) bits = 1;

    const char *secret_filename = "secret.bin";
    if (secret_type && strcmp(secret_type, "file") == 0 && secret_file_part && secret_file_part->filename) {
        secret_filename = secret_file_part->filename;
    } else if (!secret_type || strcmp(secret_type, "text") == 0) {
        secret_filename = "secret.txt";
    }

    const char *cover_fn = (cover_part->filename && cover_part->filename[0]) ? cover_part->filename : "cover.png";
    api_save_image("images/input", cover_fn, cover_part->data, cover_part->size);

    BridgeHideResult result;
    StegoResult sres = bridge_hide_advanced(cover_part->data, cover_part->size,
                                            secret_data, secret_len,
                                            secret_filename,
                                            (passphrase && passphrase[0] != '\0') ? passphrase : NULL,
                                            adaptive, compress, bits, &result);

    multipart_free(form);

    if (sres != STEGO_OK) {
        if (sres == STEGO_ERR_CAPACITY_EXCEEDED || result.capacity_exceeded) {
            char *esc_err = json_escape(result.error_msg[0] ? result.error_msg : "The selected file exceeds the available capacity of this image. Select a larger cover image or reduce the file size.");
            char *esc_name = json_escape(result.secret_name[0] ? result.secret_name : secret_filename);
            char cap_json[1024];
            snprintf(cap_json, sizeof(cap_json),
                     "{\"success\":false,\"capacity_exceeded\":true,"
                     "\"error\":\"%s\","
                     "\"secret_name\":\"%s\","
                     "\"secret_size\":%zu,"
                     "\"available_capacity\":%zu,"
                     "\"additional_required\":%zu,"
                     "\"rec_min_width\":%u,"
                     "\"rec_min_height\":%u,"
                     "\"rec_square_dim\":%u}",
                     esc_err ? esc_err : "The selected file exceeds the available capacity of this image. Select a larger cover image or reduce the file size.",
                     esc_name ? esc_name : "secret.bin",
                     result.secret_size,
                     result.available_capacity,
                     result.additional_required,
                     result.rec_min_width,
                     result.rec_min_height,
                     result.rec_square_dim);
            if (esc_err) free(esc_err);
            if (esc_name) free(esc_name);
            http_response_set_json(res, 400, cap_json);
        } else {
            int status = (sres == STEGO_ERR_INVALID_FORMAT) ? 400 : 500;
            api_respond_error(res, status, result.error_msg);
        }
        bridge_hide_result_free(&result);
        return;
    }

    /* Save created protected image to images/output/ */
    api_save_image("images/output", "protected_image.png", result.png_data, result.png_size);

    /* Base64 encode the output PNG */
    char *b64_img = stego_base64_encode(result.png_data, result.png_size);
    char *esc_notice = json_escape(result.notice);
    char *esc_label = json_escape(result.protection_label);
    char *esc_env = json_escape(result.envelope_name);

    size_t json_cap = (b64_img ? strlen(b64_img) : 0) + 2048;
    char *json = (char *)malloc(json_cap);
    if (json) {
        snprintf(json, json_cap,
                 "{\"success\":true,\"format\":\"PNG\",\"width\":%u,\"height\":%u,"
                 "\"is_protected\":%s,\"protection_label\":\"%s\",\"envelope\":\"%s\","
                 "\"notice\":\"%s\",\"file_size\":%zu,\"filename\":\"protected_image.png\","
                 "\"image_base64\":\"%s\"}",
                 result.width, result.height,
                 result.is_protected ? "true" : "false",
                 esc_label ? esc_label : "",
                 esc_env ? esc_env : "",
                 esc_notice ? esc_notice : "",
                 result.png_size,
                 b64_img ? b64_img : "");

        http_response_set_json(res, 200, json);
        free(json);
    } else {
        api_respond_error(res, 500, "Memory allocation error generating response.");
    }

    if (b64_img) free(b64_img);
    if (esc_notice) free(esc_notice);
    if (esc_label) free(esc_label);
    if (esc_env) free(esc_env);
    bridge_hide_result_free(&result);
}

static void handle_reveal(const HttpRequest *req, HttpResponse *res) {
    if (req->method != HTTP_METHOD_POST) {
        api_respond_error(res, 405, "Method not allowed. Use POST.");
        return;
    }

    if (req->boundary[0] == '\0') {
        api_respond_error(res, 400, "Invalid request. Expected multipart/form-data.");
        return;
    }

    MultipartForm *form = multipart_parse(req->body, req->body_len, req->boundary);
    if (!form) {
        api_respond_error(res, 400, "Failed to parse uploaded form data.");
        return;
    }

    const UploadPart *stego_part = multipart_get_part(form, "stego_image");
    if (!stego_part || !stego_part->data || stego_part->size == 0) {
        stego_part = multipart_get_part(form, "cover");
    }
    if (!stego_part || !stego_part->data || stego_part->size == 0) {
        stego_part = multipart_get_part(form, "image");
    }

    if (!stego_part || !stego_part->data || stego_part->size == 0) {
        multipart_free(form);
        api_respond_error(res, 400, "The selected file is not a supported image format. Select a valid PNG, JPEG, BMP, WEBP, or GIF image.");
        return;
    }

    const char *passphrase = multipart_get_string(form, "password");
    if (!passphrase) passphrase = multipart_get_string(form, "passphrase");

    BridgeRevealResult result;
    StegoResult sres = bridge_reveal(stego_part->data, stego_part->size, passphrase, &result);
    multipart_free(form);

    if (sres != STEGO_OK) {
        int status = (sres == STEGO_ERR_AUTH_FAILED) ? 401 :
                     (sres == STEGO_ERR_NO_PAYLOAD) ? 400 :
                     (sres == STEGO_ERR_INVALID_FORMAT) ? 400 : 400;
        api_respond_error(res, status, result.error_msg);
        bridge_reveal_result_free(&result);
        return;
    }

    char *esc_label = json_escape(result.protection_label);
    char *esc_env = json_escape(result.envelope_name);
    const char *final_fn = result.filename[0] ? result.filename : (result.is_text ? "recovered_secret.txt" : "recovered_secret.bin");
    api_save_image("images/output", final_fn, result.payload_data, result.payload_size);
    char *esc_fn = json_escape(final_fn);
    char *esc_sha = json_escape(result.sha256_hex);
    char *b64_file = stego_base64_encode(result.payload_data, result.payload_size);

    char *esc_text = NULL;
    if (result.is_text) {
        char *temp_str = (char *)malloc(result.payload_size + 1);
        if (temp_str) {
            memcpy(temp_str, result.payload_data, result.payload_size);
            temp_str[result.payload_size] = '\0';
            esc_text = json_escape(temp_str);
            stego_secure_zero(temp_str, result.payload_size);
            free(temp_str);
        }
    }

    size_t json_cap = (b64_file ? strlen(b64_file) : 0) + (esc_text ? strlen(esc_text) : 0) + 2048;
    char *json = (char *)malloc(json_cap);
    if (json) {
        snprintf(json, json_cap,
                 "{\"success\":true,\"is_file\":%s,\"is_text\":%s,\"payload_length\":%zu,"
                 "\"is_protected\":%s,\"protection_label\":\"%s\",\"envelope\":\"%s\","
                 "\"text\":\"%s\",\"filename\":\"%s\",\"sha256\":\"%s\",\"file_base64\":\"%s\"}",
                 result.is_file ? "true" : (result.is_text ? "false" : "true"),
                 result.is_text ? "true" : "false",
                 result.payload_size,
                 result.is_protected ? "true" : "false",
                 esc_label ? esc_label : "",
                 esc_env ? esc_env : "",
                 esc_text ? esc_text : "",
                 esc_fn ? esc_fn : "",
                 esc_sha ? esc_sha : "",
                 b64_file ? b64_file : "");

        http_response_set_json(res, 200, json);
        free(json);
    } else {
        api_respond_error(res, 500, "Memory allocation error generating response.");
    }

    if (b64_file) free(b64_file);
    if (esc_fn) free(esc_fn);
    if (esc_sha) free(esc_sha);
    if (esc_text) {
        stego_secure_zero(esc_text, strlen(esc_text));
        free(esc_text);
    }
    if (esc_label) free(esc_label);
    if (esc_env) free(esc_env);
    bridge_reveal_result_free(&result);
}

static void handle_verify(const HttpRequest *req, HttpResponse *res) {
    if (req->method != HTTP_METHOD_POST) {
        api_respond_error(res, 405, "Method not allowed. Use POST.");
        return;
    }

    if (req->boundary[0] == '\0') {
        api_respond_error(res, 400, "Invalid request. Expected multipart/form-data.");
        return;
    }

    MultipartForm *form = multipart_parse(req->body, req->body_len, req->boundary);
    if (!form) {
        api_respond_error(res, 400, "Failed to parse uploaded form data.");
        return;
    }

    const UploadPart *img_part = multipart_get_part(form, "image");
    if (!img_part || !img_part->data || img_part->size == 0) {
        img_part = multipart_get_part(form, "stego_image");
    }
    if (!img_part || !img_part->data || img_part->size == 0) {
        img_part = multipart_get_part(form, "cover");
    }

    if (!img_part || !img_part->data || img_part->size == 0) {
        multipart_free(form);
        api_respond_error(res, 400, "The selected file is not a supported image format. Select a valid PNG, JPEG, BMP, WEBP, or GIF image.");
        return;
    }

    BridgeVerifyResult result;
    StegoResult sres = bridge_verify(img_part->data, img_part->size, &result);
    multipart_free(form);

    if (sres != STEGO_OK) {
        api_respond_error(res, 400, result.error_msg);
        return;
    }

    char *esc_label = json_escape(result.protection_label);
    char *esc_env = json_escape(result.envelope_name);

    char json[1024];
    snprintf(json, sizeof(json),
             "{\"success\":true,\"has_payload\":%s,\"is_protected\":%s,"
             "\"protection_label\":\"%s\",\"envelope\":\"%s\",\"payload_length\":%u,"
             "\"message\":\"%s\"}",
             result.has_payload ? "true" : "false",
             result.is_protected ? "true" : "false",
             esc_label ? esc_label : "",
             esc_env ? esc_env : "",
             result.payload_length,
             result.has_payload ? (result.is_protected ? "Password-protected file detected." : "Unencrypted file detected.") : "No protected content was detected in this image.");

    http_response_set_json(res, 200, json);
    if (esc_label) free(esc_label);
    if (esc_env) free(esc_env);
}

static void handle_capacity(const HttpRequest *req, HttpResponse *res) {
    if (req->method != HTTP_METHOD_POST) {
        api_respond_error(res, 405, "Method not allowed. Use POST.");
        return;
    }

    if (req->boundary[0] == '\0') {
        api_respond_error(res, 400, "Invalid request. Expected multipart/form-data.");
        return;
    }

    MultipartForm *form = multipart_parse(req->body, req->body_len, req->boundary);
    if (!form) {
        api_respond_error(res, 400, "Failed to parse uploaded form data.");
        return;
    }

    const UploadPart *img_part = multipart_get_part(form, "image");
    if (!img_part || !img_part->data || img_part->size == 0) {
        img_part = multipart_get_part(form, "cover");
    }
    if (!img_part || !img_part->data || img_part->size == 0) {
        img_part = multipart_get_part(form, "file");
    }
    if (!img_part || !img_part->data || img_part->size == 0) {
        img_part = multipart_get_part(form, "stego_image");
    }
    if (!img_part || !img_part->data || img_part->size == 0) {
        for (size_t i = 0; i < form->count; i++) {
            if (form->parts[i].data && form->parts[i].size > 0) {
                img_part = &form->parts[i];
                break;
            }
        }
    }

    if (!img_part || !img_part->data || img_part->size == 0) {
        multipart_free(form);
        api_respond_error(res, 400, "The selected file is not a supported image format. Select a valid PNG, JPEG, BMP, WEBP, or GIF image.");
        return;
    }

    const char *adaptive_str = multipart_get_string(form, "adaptive");
    bool adaptive = (adaptive_str && (strcmp(adaptive_str, "true") == 0 || strcmp(adaptive_str, "1") == 0));

    BridgeCapacityResult result;
    StegoResult sres = bridge_capacity(img_part->data, img_part->size, adaptive, &result);
    multipart_free(form);

    if (sres != STEGO_OK) {
        api_respond_error(res, 400, result.error_msg);
        return;
    }

    char *esc_fmt = json_escape(result.format);
    char *esc_mime = json_escape(result.mime_type);
    char *esc_orig = json_escape(result.original_mode);
    char *esc_norm = json_escape(result.normalized_mode);
    char *esc_env = json_escape(result.envelope_name);
    char *esc_not = json_escape(result.notice);

    char json[2048];
    snprintf(json, sizeof(json),
             "{\"success\":true,\"format\":\"%s\",\"mime_type\":\"%s\",\"file_size\":%zu,"
             "\"original_mode\":\"%s\",\"normalized_mode\":\"%s\",\"width\":%u,\"height\":%u,\"channels\":%u,"
             "\"was_converted\":%s,\"output_format\":\"PNG\","
             "\"unencrypted_capacity\":%zu,\"encrypted_capacity\":%zu,"
             "\"capacity_2bit\":%zu,\"capacity_3bit\":%zu,"
             "\"has_payload\":%s,\"envelope\":\"%s\",\"notice\":\"%s\"}",
             esc_fmt ? esc_fmt : "",
             esc_mime ? esc_mime : "",
             result.file_size,
             esc_orig ? esc_orig : "",
             esc_norm ? esc_norm : "",
             result.width, result.height, result.channels,
             result.was_converted ? "true" : "false",
             result.unencrypted_capacity,
             result.encrypted_capacity,
             result.capacity_2bit,
             result.capacity_3bit,
             result.has_payload ? "true" : "false",
             esc_env ? esc_env : "",
             esc_not ? esc_not : "");

    http_response_set_json(res, 200, json);

    if (esc_fmt) free(esc_fmt);
    if (esc_mime) free(esc_mime);
    if (esc_orig) free(esc_orig);
    if (esc_norm) free(esc_norm);
    if (esc_env) free(esc_env);
    if (esc_not) free(esc_not);
}

static void handle_split_hide(const HttpRequest *req, HttpResponse *res) {
    if (req->method != HTTP_METHOD_POST) {
        api_respond_error(res, 405, "Method not allowed. Use POST.");
        return;
    }

    if (req->boundary[0] == '\0') {
        api_respond_error(res, 400, "Invalid request. Expected multipart/form-data.");
        return;
    }

    MultipartForm *form = multipart_parse(req->body, req->body_len, req->boundary);
    if (!form) {
        api_respond_error(res, 400, "Failed to parse uploaded form data.");
        return;
    }

    /* Collect all cover images */
    const uint8_t *cover_ptrs[STEGO_MAX_SPLIT_PARTS];
    size_t cover_lens[STEGO_MAX_SPLIT_PARTS];
    uint16_t num_covers = 0;

    for (size_t i = 0; i < form->count && num_covers < STEGO_MAX_SPLIT_PARTS; i++) {
        UploadPart *p = &form->parts[i];
        if (!p->data || p->size == 0) continue;
        if (strcmp(p->name, "secret_file") == 0 || strcmp(p->name, "message") == 0 ||
            strcmp(p->name, "password") == 0 || strcmp(p->name, "passphrase") == 0 ||
            strcmp(p->name, "compress") == 0 || strcmp(p->name, "bits") == 0 ||
            strcmp(p->name, "secret_type") == 0) {
            continue;
        }
        cover_ptrs[num_covers] = p->data;
        cover_lens[num_covers] = p->size;
        num_covers++;
    }

    if (num_covers < 2) {
        multipart_free(form);
        api_respond_error(res, 400, "Select two or more cover images to divide the content across.");
        return;
    }

    /* Secret payload */
    const char *secret_type = multipart_get_string(form, "secret_type");
    const uint8_t *secret_data = NULL;
    size_t secret_len = 0;
    const UploadPart *secret_file_part = multipart_get_part(form, "secret_file");
    const char *message_str = multipart_get_string(form, "message");

    const char *secret_filename = "secret.bin";
    if (secret_type && strcmp(secret_type, "file") == 0) {
        if (!secret_file_part || !secret_file_part->data || secret_file_part->size == 0) {
            multipart_free(form);
            api_respond_error(res, 400, "Select a file to protect.");
            return;
        }
        secret_data = secret_file_part->data;
        secret_len = secret_file_part->size;
        if (secret_file_part->filename) secret_filename = secret_file_part->filename;
    } else {
        if (!message_str || message_str[0] == '\0') {
            if (secret_file_part && secret_file_part->data && secret_file_part->size > 0) {
                secret_data = secret_file_part->data;
                secret_len = secret_file_part->size;
                if (secret_file_part->filename) secret_filename = secret_file_part->filename;
            } else {
                multipart_free(form);
                api_respond_error(res, 400, "Enter a text message or select a file to protect.");
                return;
            }
        } else {
            secret_data = (const uint8_t *)message_str;
            secret_len = strlen(message_str);
            secret_filename = "secret.txt";
        }
    }

    /* Passphrase */
    const char *passphrase = multipart_get_string(form, "password");
    if (!passphrase) passphrase = multipart_get_string(form, "passphrase");

    /* Options */
    const char *comp_str = multipart_get_string(form, "compress");
    bool compress = (comp_str && (strcmp(comp_str, "true") == 0 || strcmp(comp_str, "1") == 0));

    const char *bits_str = multipart_get_string(form, "bits");
    int bits = bits_str ? atoi(bits_str) : 1;
    if (bits < 1 || bits > 3) bits = 1;

    for (size_t i = 0; i < num_covers; i++) {
        char fn[64];
        snprintf(fn, sizeof(fn), "split_cover_%zu.png", i + 1);
        api_save_image("images/input", fn, cover_ptrs[i], cover_lens[i]);
    }

    BridgeSplitHideResult result;
    StegoResult sres = bridge_split_hide(cover_ptrs, cover_lens, num_covers,
                                         secret_data, secret_len, secret_filename,
                                         (passphrase && passphrase[0] != '\0') ? passphrase : NULL,
                                         compress, bits, &result);
    multipart_free(form);

    if (sres != STEGO_OK) {
        api_respond_error(res, 400, result.error_msg[0] ? result.error_msg : "Multi-image split embedding failed.");
        bridge_split_hide_result_free(&result);
        return;
    }

    /* Save each created split part image to images/output/ */
    for (uint16_t i = 0; i < result.total_parts; i++) {
        char part_fn[128];
        snprintf(part_fn, sizeof(part_fn), "secret_part%u_of_%u.png", i + 1, result.total_parts);
        api_save_image("images/output", part_fn, result.parts[i].png_data, result.parts[i].png_size);
    }
    if (result.manifest_json) {
        api_save_image("images/output", "manifest.json", (const uint8_t *)result.manifest_json, strlen(result.manifest_json));
    }

    /* Encode parts to base64 and generate JSON */
    size_t total_b64_est = 0;
    for (uint16_t i = 0; i < result.total_parts; i++) {
        total_b64_est += (result.parts[i].png_size * 4 / 3 + 4096);
    }
    size_t json_cap = total_b64_est + strlen(result.manifest_json) * 2 + 16384;
    char *json = (char *)malloc(json_cap);
    if (!json) {
        bridge_split_hide_result_free(&result);
        api_respond_error(res, 500, "Memory allocation failed generating split hide response.");
        return;
    }

    char *esc_manifest = json_escape(result.manifest_json);
    snprintf(json, json_cap,
             "{\"success\":true,\"total_parts\":%u,\"manifest\":\"%s\",\"parts\":[",
             result.total_parts, esc_manifest ? esc_manifest : "");
    if (esc_manifest) free(esc_manifest);

    for (uint16_t i = 0; i < result.total_parts; i++) {
        char *part_b64 = stego_base64_encode(result.parts[i].png_data, result.parts[i].png_size);
        char *esc_fn = json_escape(result.parts[i].filename);
        char part_buf[512];
        snprintf(part_buf, sizeof(part_buf),
                 "%s{\"part_num\":%u,\"filename\":\"%s\",\"file_size\":%zu,\"image_base64\":\"",
                 (i > 0 ? "," : ""), result.parts[i].part_num,
                 esc_fn ? esc_fn : "part.png", result.parts[i].png_size);
        if (esc_fn) free(esc_fn);

        size_t cur_len = strlen(json);
        strncat(json, part_buf, json_cap - cur_len - 1);
        if (part_b64) {
            cur_len = strlen(json);
            strncat(json, part_b64, json_cap - cur_len - 1);
            free(part_b64);
        }
        cur_len = strlen(json);
        strncat(json, "\"}", json_cap - cur_len - 1);
    }

    size_t cur_len = strlen(json);
    strncat(json, "]}", json_cap - cur_len - 1);

    http_response_set_json(res, 200, json);
    free(json);
    bridge_split_hide_result_free(&result);
}

static void handle_split_reveal(const HttpRequest *req, HttpResponse *res) {
    if (req->method != HTTP_METHOD_POST) {
        api_respond_error(res, 405, "Method not allowed. Use POST.");
        return;
    }

    if (req->boundary[0] == '\0') {
        api_respond_error(res, 400, "Invalid request. Expected multipart/form-data.");
        return;
    }

    MultipartForm *form = multipart_parse(req->body, req->body_len, req->boundary);
    if (!form) {
        api_respond_error(res, 400, "Failed to parse uploaded form data.");
        return;
    }

    /* Collect all stego part images */
    const uint8_t *stego_ptrs[STEGO_MAX_SPLIT_PARTS];
    size_t stego_lens[STEGO_MAX_SPLIT_PARTS];
    uint16_t num_parts = 0;

    for (size_t i = 0; i < form->count && num_parts < STEGO_MAX_SPLIT_PARTS; i++) {
        UploadPart *p = &form->parts[i];
        if (!p->data || p->size == 0) continue;
        if (strcmp(p->name, "password") == 0 || strcmp(p->name, "passphrase") == 0) {
            continue;
        }
        stego_ptrs[num_parts] = p->data;
        stego_lens[num_parts] = p->size;
        num_parts++;
    }

    if (num_parts < 2) {
        multipart_free(form);
        api_respond_error(res, 400, "Select two or more part images to recover the file.");
        return;
    }

    const char *passphrase = multipart_get_string(form, "password");
    if (!passphrase) passphrase = multipart_get_string(form, "passphrase");

    BridgeRevealResult result;
    StegoResult sres = bridge_split_reveal(stego_ptrs, stego_lens, num_parts, passphrase, &result);
    multipart_free(form);

    if (sres != STEGO_OK) {
        int status = (sres == STEGO_ERR_AUTH_FAILED) ? 401 : 400;
        api_respond_error(res, status, result.error_msg[0] ? result.error_msg : "The password is incorrect, or the protected image has been modified. The file could not be recovered.");
        bridge_reveal_result_free(&result);
        return;
    }

    char *esc_label = json_escape(result.protection_label);
    char *esc_env = json_escape(result.envelope_name);
    const char *final_fn = result.filename[0] ? result.filename : (result.is_text ? "recovered_secret.txt" : "recovered_secret.bin");
    api_save_image("images/output", final_fn, result.payload_data, result.payload_size);
    char *esc_fn = json_escape(final_fn);
    char *esc_sha = json_escape(result.sha256_hex);
    char *b64_file = stego_base64_encode(result.payload_data, result.payload_size);

    char *esc_text = NULL;
    if (result.is_text) {
        char *temp_str = (char *)malloc(result.payload_size + 1);
        if (temp_str) {
            memcpy(temp_str, result.payload_data, result.payload_size);
            temp_str[result.payload_size] = '\0';
            esc_text = json_escape(temp_str);
            stego_secure_zero(temp_str, result.payload_size);
            free(temp_str);
        }
    }

    size_t json_cap = (b64_file ? strlen(b64_file) : 0) + (esc_text ? strlen(esc_text) : 0) + 2048;
    char *json = (char *)malloc(json_cap);
    if (json) {
        snprintf(json, json_cap,
                 "{\"success\":true,\"is_file\":%s,\"is_text\":%s,\"payload_length\":%zu,"
                 "\"is_protected\":%s,\"protection_label\":\"%s\",\"envelope\":\"%s\","
                 "\"text\":\"%s\",\"filename\":\"%s\",\"sha256\":\"%s\",\"file_base64\":\"%s\"}",
                 result.is_file ? "true" : (result.is_text ? "false" : "true"),
                 result.is_text ? "true" : "false",
                 result.payload_size,
                 result.is_protected ? "true" : "false",
                 esc_label ? esc_label : "",
                 esc_env ? esc_env : "",
                 esc_text ? esc_text : "",
                 esc_fn ? esc_fn : "",
                 esc_sha ? esc_sha : "",
                 b64_file ? b64_file : "");

        http_response_set_json(res, 200, json);
        free(json);
    } else {
        api_respond_error(res, 500, "Memory allocation error generating response.");
    }

    if (b64_file) free(b64_file);
    if (esc_fn) free(esc_fn);
    if (esc_sha) free(esc_sha);
    if (esc_text) {
        stego_secure_zero(esc_text, strlen(esc_text));
        free(esc_text);
    }
    if (esc_label) free(esc_label);
    if (esc_env) free(esc_env);
    bridge_reveal_result_free(&result);
}

static void handle_metadata_scan(const HttpRequest *req, HttpResponse *res) {
    if (req->method != HTTP_METHOD_POST) {
        api_respond_error(res, 405, "Method not allowed. Use POST.");
        return;
    }
    if (req->boundary[0] == '\0') {
        api_respond_error(res, 400, "Invalid request. Expected multipart/form-data.");
        return;
    }

    MultipartForm *form = multipart_parse(req->body, req->body_len, req->boundary);
    if (!form) {
        api_respond_error(res, 400, "Failed to parse uploaded form data.");
        return;
    }

    const UploadPart *part = multipart_get_part(form, "image");
    if (!part || !part->data || part->size == 0) {
        part = multipart_get_part(form, "cover");
    }
    if (!part || !part->data || part->size == 0) {
        part = multipart_get_part(form, "file");
    }
    if (!part || !part->data || part->size == 0) {
        multipart_free(form);
        api_respond_error(res, 400, "No image uploaded for metadata scanning.");
        return;
    }

    BridgeMetadataScanResult result;
    StegoResult sres = bridge_metadata_scan(part->data, part->size, &result);
    multipart_free(form);

    if (sres != STEGO_OK) {
        api_respond_error(res, 400, result.error_msg[0] ? result.error_msg : "Failed to scan metadata.");
        return;
    }

    char *esc_make = json_escape(result.camera_make);
    char *esc_model = json_escape(result.camera_model);
    char *esc_sw = json_escape(result.software);
    char *esc_date = json_escape(result.datetime);
    char *esc_risk = json_escape(result.risk_level);
    char *esc_reason = json_escape(result.risk_reason);
    char *esc_time = json_escape(result.gps_timestamp);

    const char *privacy_risk_str = "low";
    if (result.has_gps) {
        privacy_risk_str = "high";
    } else if (result.has_camera_info || result.has_exif || result.datetime[0] != '\0' || result.software[0] != '\0') {
        privacy_risk_str = "medium";
    }

    char json[2048];
    if (result.has_gps) {
        char gps_obj[512];
        const char *lref = result.latitude_ref[0] ? result.latitude_ref : (result.latitude < 0 ? "S" : "N");
        const char *wref = result.longitude_ref[0] ? result.longitude_ref : (result.longitude < 0 ? "W" : "E");

        if (result.has_altitude && result.has_timestamp && esc_time && esc_time[0]) {
            snprintf(gps_obj, sizeof(gps_obj),
                     "{\"latitude\":%.6f,\"longitude\":%.6f,\"latitudeRef\":\"%s\",\"longitudeRef\":\"%s\",\"altitude\":%.1f,\"timestamp\":\"%s\"}",
                     result.latitude, result.longitude, lref, wref, result.altitude, esc_time);
        } else if (result.has_altitude) {
            snprintf(gps_obj, sizeof(gps_obj),
                     "{\"latitude\":%.6f,\"longitude\":%.6f,\"latitudeRef\":\"%s\",\"longitudeRef\":\"%s\",\"altitude\":%.1f,\"timestamp\":null}",
                     result.latitude, result.longitude, lref, wref, result.altitude);
        } else if (result.has_timestamp && esc_time && esc_time[0]) {
            snprintf(gps_obj, sizeof(gps_obj),
                     "{\"latitude\":%.6f,\"longitude\":%.6f,\"latitudeRef\":\"%s\",\"longitudeRef\":\"%s\",\"altitude\":null,\"timestamp\":\"%s\"}",
                     result.latitude, result.longitude, lref, wref, esc_time);
        } else {
            snprintf(gps_obj, sizeof(gps_obj),
                     "{\"latitude\":%.6f,\"longitude\":%.6f,\"latitudeRef\":\"%s\",\"longitudeRef\":\"%s\",\"altitude\":null,\"timestamp\":null}",
                     result.latitude, result.longitude, lref, wref);
        }

        snprintf(json, sizeof(json),
                 "{\"success\":true,\"hasGps\":true,\"gps\":%s,\"privacyRisk\":\"%s\","
                 "\"has_exif\":%s,\"has_gps\":true,\"has_camera_info\":%s,"
                 "\"camera_make\":\"%s\",\"camera_model\":\"%s\",\"software\":\"%s\","
                 "\"datetime\":\"%s\",\"latitude\":%.6f,\"longitude\":%.6f,"
                 "\"latitude_ref\":\"%s\",\"longitude_ref\":\"%s\",\"altitude\":%.1f,"
                 "\"risk_level\":\"High\",\"risk_reason\":\"%s\",\"metadata_bytes\":%zu}",
                 gps_obj, privacy_risk_str,
                 result.has_exif ? "true" : "false",
                 result.has_camera_info ? "true" : "false",
                 esc_make ? esc_make : "",
                 esc_model ? esc_model : "",
                 esc_sw ? esc_sw : "",
                 esc_date ? esc_date : "",
                 result.latitude,
                 result.longitude,
                 lref, wref,
                 result.has_altitude ? result.altitude : 0.0,
                 esc_reason ? esc_reason : "GPS location coordinates detected (reveals precise physical location).",
                 result.metadata_bytes);
    } else {
        snprintf(json, sizeof(json),
                 "{\"success\":true,\"hasGps\":false,\"gps\":null,\"privacyRisk\":\"%s\","
                 "\"has_exif\":%s,\"has_gps\":false,\"has_camera_info\":%s,"
                 "\"camera_make\":\"%s\",\"camera_model\":\"%s\",\"software\":\"%s\","
                 "\"datetime\":\"%s\",\"latitude\":0.0,\"longitude\":0.0,"
                 "\"latitude_ref\":\"\",\"longitude_ref\":\"\",\"altitude\":null,"
                 "\"risk_level\":\"%s\",\"risk_reason\":\"%s\",\"metadata_bytes\":%zu}",
                 privacy_risk_str,
                 result.has_exif ? "true" : "false",
                 result.has_camera_info ? "true" : "false",
                 esc_make ? esc_make : "",
                 esc_model ? esc_model : "",
                 esc_sw ? esc_sw : "",
                 esc_date ? esc_date : "",
                 esc_risk ? esc_risk : "Low",
                 esc_reason ? esc_reason : "",
                 result.metadata_bytes);
    }

    if (esc_make) free(esc_make);
    if (esc_model) free(esc_model);
    if (esc_sw) free(esc_sw);
    if (esc_date) free(esc_date);
    if (esc_risk) free(esc_risk);
    if (esc_reason) free(esc_reason);
    if (esc_time) free(esc_time);

    http_response_set_json(res, 200, json);
}

static void handle_metadata_strip(const HttpRequest *req, HttpResponse *res) {
    if (req->method != HTTP_METHOD_POST) {
        api_respond_error(res, 405, "Method not allowed. Use POST.");
        return;
    }
    if (req->boundary[0] == '\0') {
        api_respond_error(res, 400, "Invalid request. Expected multipart/form-data.");
        return;
    }

    MultipartForm *form = multipart_parse(req->body, req->body_len, req->boundary);
    if (!form) {
        api_respond_error(res, 400, "Failed to parse uploaded form data.");
        return;
    }

    const UploadPart *part = multipart_get_part(form, "image");
    if (!part || !part->data || part->size == 0) {
        part = multipart_get_part(form, "cover");
    }
    if (!part || !part->data || part->size == 0) {
        part = multipart_get_part(form, "file");
    }
    if (!part || !part->data || part->size == 0) {
        multipart_free(form);
        api_respond_error(res, 400, "No image uploaded for metadata stripping.");
        return;
    }

    const char *in_fn = (part->filename && part->filename[0]) ? part->filename : "photo_input.jpg";
    api_save_image("images/input", in_fn, part->data, part->size);

    BridgeMetadataStripResult result;
    StegoResult sres = bridge_metadata_strip(part->data, part->size, part->filename, &result);
    multipart_free(form);

    if (sres != STEGO_OK) {
        api_respond_error(res, 400, result.error_msg[0] ? result.error_msg : "Failed to strip metadata.");
        bridge_metadata_strip_result_free(&result);
        return;
    }

    /* Save created stripped image to images/output/ */
    const char *out_clean_fn = result.clean_filename[0] ? result.clean_filename : "clean_image.png";
    api_save_image("images/output", out_clean_fn, result.clean_image_data, result.clean_image_size);

    char *esc_fn = json_escape(result.clean_filename);
    char *esc_fmt = json_escape(result.format);
    char *b64_img = stego_base64_encode(result.clean_image_data, result.clean_image_size);

    size_t json_cap = (b64_img ? strlen(b64_img) : 0) + 1024;
    char *json = (char *)malloc(json_cap);
    if (json) {
        snprintf(json, json_cap,
                 "{\"success\":true,\"filename\":\"%s\",\"format\":\"%s\","
                 "\"clean_image_size\":%zu,\"bytes_removed\":%zu,\"image_base64\":\"%s\"}",
                 esc_fn ? esc_fn : "clean_image.png",
                 esc_fmt ? esc_fmt : "PNG",
                 result.clean_image_size,
                 result.bytes_removed,
                 b64_img ? b64_img : "");
        http_response_set_json(res, 200, json);
        free(json);
    } else {
        api_respond_error(res, 500, "Memory allocation failed generating response.");
    }

    if (esc_fn) free(esc_fn);
    if (esc_fmt) free(esc_fmt);
    if (b64_img) free(b64_img);
    bridge_metadata_strip_result_free(&result);
}

void api_handle_request(const HttpRequest *req, HttpResponse *res) {
    if (!req || !res) return;

    if (strcmp(req->path, "/api/health") == 0) {
        handle_health(req, res);
    } else if (strcmp(req->path, "/api/hide") == 0) {
        handle_hide(req, res);
    } else if (strcmp(req->path, "/api/reveal") == 0) {
        handle_reveal(req, res);
    } else if (strcmp(req->path, "/api/verify") == 0) {
        handle_verify(req, res);
    } else if (strcmp(req->path, "/api/capacity") == 0) {
        handle_capacity(req, res);
    } else if (strcmp(req->path, "/api/split-hide") == 0) {
        handle_split_hide(req, res);
    } else if (strcmp(req->path, "/api/split-reveal") == 0) {
        handle_split_reveal(req, res);
    } else if (strcmp(req->path, "/api/metadata-scan") == 0 ||
               strcmp(req->path, "/api/privacy-report") == 0) {
        handle_metadata_scan(req, res);
    } else if (strcmp(req->path, "/api/metadata-strip") == 0) {
        handle_metadata_strip(req, res);
    } else {
        api_respond_error(res, 404, "Endpoint not found.");
    }
}

