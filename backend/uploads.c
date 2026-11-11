/**
 * @file uploads.c
 * @brief Multipart upload parser, magic byte validation, and temporary file lifecycle.
 */

#include "uploads.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#endif

/* Binary search for byte sequence (memmem equivalent) */
static const uint8_t *bin_search(const uint8_t *haystack, size_t haystack_len,
                                 const uint8_t *needle, size_t needle_len) {
    if (!haystack || !needle || needle_len == 0 || haystack_len < needle_len) {
        return NULL;
    }
    const uint8_t *end = haystack + (haystack_len - needle_len);
    for (const uint8_t *p = haystack; p <= end; p++) {
        if (*p == *needle && memcmp(p, needle, needle_len) == 0) {
            return p;
        }
    }
    return NULL;
}

static char *extract_param(const char *header, const char *param_name) {
    if (!header || !param_name) return NULL;
    size_t plen = strlen(param_name);
    const char *p = header;

    while (*p) {
        if (*p == '"') {
            /* Skip quoted string so param names inside quotes are ignored */
            p++;
            while (*p && *p != '"') {
                if (*p == '\\' && *(p + 1)) p++;
                p++;
            }
            if (*p == '"') p++;
            continue;
        }

        /* Check for parameter name start preceded by boundary character */
        if ((p == header || *(p - 1) == ' ' || *(p - 1) == ';' || *(p - 1) == '\t') &&
            _strnicmp(p, param_name, plen) == 0) {
            const char *after = p + plen;
            while (*after == ' ' || *after == '\t') after++;
            if (*after == '=') {
                after++;
                while (*after == ' ' || *after == '\t') after++;
                if (*after == '"') {
                    after++;
                    const char *end = after;
                    while (*end && *end != '"') {
                        if (*end == '\\' && *(end + 1)) end++;
                        end++;
                    }
                    size_t val_len = (size_t)(end - after);
                    char *val = (char *)malloc(val_len + 1);
                    if (val) {
                        memcpy(val, after, val_len);
                        val[val_len] = '\0';
                        return val;
                    }
                } else {
                    const char *end = after;
                    while (*end && *end != ' ' && *end != ';' && *end != '\r' && *end != '\n' && *end != '\t') {
                        end++;
                    }
                    size_t val_len = (size_t)(end - after);
                    if (val_len > 0) {
                        char *val = (char *)malloc(val_len + 1);
                        if (val) {
                            memcpy(val, after, val_len);
                            val[val_len] = '\0';
                            return val;
                        }
                    }
                }
            }
        }
        p++;
    }
    return NULL;
}

MultipartForm *multipart_parse(const uint8_t *body, size_t body_len, const char *boundary) {
    if (!body || body_len == 0 || !boundary || boundary[0] == '\0') {
        return NULL;
    }

    /* Build boundary markers */
    char full_bnd[256];
    snprintf(full_bnd, sizeof(full_bnd), "--%s", boundary);
    size_t bnd_len = strlen(full_bnd);

    char delim[260];
    snprintf(delim, sizeof(delim), "\r\n--%s", boundary);
    size_t delim_len = strlen(delim);

    /* Locate the initial boundary */
    const uint8_t *cur = bin_search(body, body_len, (const uint8_t *)full_bnd, bnd_len);
    if (!cur) return NULL;
    cur += bnd_len;

    MultipartForm *form = (MultipartForm *)calloc(1, sizeof(MultipartForm));
    if (!form) return NULL;

    form->capacity = 8;
    form->parts = (UploadPart *)calloc(form->capacity, sizeof(UploadPart));
    if (!form->parts) {
        free(form);
        return NULL;
    }

    while (cur < body + body_len) {
        /* Check if we reached final boundary "--" */
        if (cur + 2 <= body + body_len && cur[0] == '-' && cur[1] == '-') {
            break;
        }

        /* Skip \r\n after boundary */
        if (cur + 2 <= body + body_len && cur[0] == '\r' && cur[1] == '\n') {
            cur += 2;
        } else if (cur < body + body_len && *cur == '\n') {
            cur++;
        }

        /* Find header terminator \r\n\r\n */
        size_t remaining = (body + body_len) - cur;
        const uint8_t *hdr_end = bin_search(cur, remaining, (const uint8_t *)"\r\n\r\n", 4);
        if (!hdr_end) {
            /* Try \n\n */
            hdr_end = bin_search(cur, remaining, (const uint8_t *)"\n\n", 2);
            if (!hdr_end) break;
        }

        size_t hdr_len = hdr_end - cur;
        char *hdr_str = (char *)malloc(hdr_len + 1);
        if (!hdr_str) break;
        memcpy(hdr_str, cur, hdr_len);
        hdr_str[hdr_len] = '\0';

        /* Advance past header terminator */
        if (hdr_end[0] == '\r') cur = hdr_end + 4;
        else cur = hdr_end + 2;

        /* Parse header information */
        char *name = extract_param(hdr_str, "name");
        char *filename = extract_param(hdr_str, "filename");
        char *content_type = NULL;

        const char *ct = strstr(hdr_str, "Content-Type:");
        if (!ct) ct = strstr(hdr_str, "content-type:");
        if (ct) {
            ct += 13;
            while (*ct == ' ') ct++;
            const char *ct_end = ct;
            while (*ct_end && *ct_end != '\r' && *ct_end != '\n' && *ct_end != ';') ct_end++;
            size_t ct_len = ct_end - ct;
            if (ct_len > 0) {
                content_type = (char *)malloc(ct_len + 1);
                if (content_type) {
                    memcpy(content_type, ct, ct_len);
                    content_type[ct_len] = '\0';
                }
            }
        }
        free(hdr_str);

        if (!name) {
            if (filename) free(filename);
            if (content_type) free(content_type);
            break;
        }

        /* Find next boundary marking end of part data */
        remaining = (body + body_len) - cur;
        const uint8_t *next_bnd = bin_search(cur, remaining, (const uint8_t *)delim, delim_len);
        size_t part_size = 0;
        size_t advance_len = delim_len;
        if (next_bnd) {
            part_size = next_bnd - cur;
            advance_len = delim_len;
        } else {
            /* Fallback to full_bnd */
            next_bnd = bin_search(cur, remaining, (const uint8_t *)full_bnd, bnd_len);
            if (next_bnd) {
                part_size = next_bnd - cur;
                if (part_size >= 2 && cur[part_size - 2] == '\r' && cur[part_size - 1] == '\n') {
                    part_size -= 2;
                }
                advance_len = bnd_len;
            } else {
                part_size = remaining;
                advance_len = remaining;
            }
        }

        /* Allocate and copy part data */
        uint8_t *part_data = NULL;
        if (part_size > 0) {
            part_data = (uint8_t *)malloc(part_size + 1);
            if (part_data) {
                memcpy(part_data, cur, part_size);
                part_data[part_size] = '\0'; /* Null-terminate for text ease */
            }
        } else {
            part_data = (uint8_t *)calloc(1, 1);
        }

        /* Expand array if needed */
        if (form->count >= form->capacity) {
            size_t new_cap = form->capacity * 2;
            UploadPart *new_parts = (UploadPart *)realloc(form->parts, new_cap * sizeof(UploadPart));
            if (!new_parts) {
                if (name) free(name);
                if (filename) free(filename);
                if (content_type) free(content_type);
                if (part_data) free(part_data);
                break;
            }
            form->parts = new_parts;
            form->capacity = new_cap;
        }

        UploadPart *part = &form->parts[form->count++];
        part->name = name;
        part->filename = filename;
        part->content_type = content_type;
        part->data = part_data;
        part->size = part_size;
        part->is_file = (filename != NULL);

        if (next_bnd) {
            cur = next_bnd + advance_len;
        } else {
            break;
        }
    }

    return form;
}

const UploadPart *multipart_get_part(const MultipartForm *form, const char *name) {
    if (!form || !name) return NULL;
    for (size_t i = 0; i < form->count; i++) {
        if (form->parts[i].name && strcmp(form->parts[i].name, name) == 0) {
            return &form->parts[i];
        }
    }
    return NULL;
}

const char *multipart_get_string(const MultipartForm *form, const char *name) {
    const UploadPart *part = multipart_get_part(form, name);
    if (!part || !part->data) return NULL;
    return (const char *)part->data;
}

void multipart_free(MultipartForm *form) {
    if (!form) return;
    for (size_t i = 0; i < form->count; i++) {
        UploadPart *part = &form->parts[i];
        if (part->name) {
            /* If this was a password field, wipe it */
            if (strstr(part->name, "pass") != NULL && part->data && part->size > 0) {
                stego_secure_zero(part->data, part->size);
            }
            free(part->name);
        }
        if (part->filename) free(part->filename);
        if (part->content_type) free(part->content_type);
        if (part->data) {
            free(part->data);
            part->data = NULL;
        }
    }
    free(form->parts);
    free(form);
}

bool uploads_is_valid_image(const uint8_t *data, size_t size, StegoImageFormat *out_fmt) {
    if (!data || size < 3) return false;
    StegoImageFormat fmt = stego_detect_format_buffer(data, size);
    if (out_fmt) *out_fmt = fmt;
    return (fmt != STEGO_FORMAT_UNKNOWN && fmt != STEGO_FORMAT_HEIC);
}

char *uploads_create_temp_file(const uint8_t *data, size_t size, const char *suffix) {
    char temp_dir[512] = ".";
#if defined(_WIN32)
    char sys_temp[MAX_PATH];
    DWORD len = GetTempPathA(sizeof(sys_temp), sys_temp);
    if (len > 0 && len < sizeof(sys_temp)) {
        snprintf(temp_dir, sizeof(temp_dir), "%s", sys_temp);
        /* Remove trailing slash */
        size_t l = strlen(temp_dir);
        if (l > 0 && (temp_dir[l - 1] == '\\' || temp_dir[l - 1] == '/')) {
            temp_dir[l - 1] = '\0';
        }
    }
#else
    const char *tmp = getenv("TMPDIR");
    if (!tmp) tmp = "/tmp";
    snprintf(temp_dir, sizeof(temp_dir), "%s", tmp);
#endif

    uint8_t rand_bytes[12];
    stego_random_bytes(rand_bytes, sizeof(rand_bytes));

    char filename[512];
    snprintf(filename, sizeof(filename), "%s/stego_tmp_%02x%02x%02x%02x%02x%02x%s",
             temp_dir,
             rand_bytes[0], rand_bytes[1], rand_bytes[2],
             rand_bytes[3], rand_bytes[4], rand_bytes[5],
             suffix ? suffix : ".tmp");

    FILE *fp = fopen(filename, "wb");
    if (!fp) return NULL;

    if (data && size > 0) {
        if (fwrite(data, 1, size, fp) != size) {
            fclose(fp);
            remove(filename);
            return NULL;
        }
    }
    fclose(fp);

    char *result = (char *)malloc(strlen(filename) + 1);
    if (result) {
        strcpy(result, filename);
    }
    return result;
}

char *uploads_create_temp_file_with_name(const uint8_t *data, size_t size, const char *original_name) {
    char temp_dir[512] = ".";
#if defined(_WIN32)
    char sys_temp[MAX_PATH];
    DWORD len = GetTempPathA(sizeof(sys_temp), sys_temp);
    if (len > 0 && len < sizeof(sys_temp)) {
        snprintf(temp_dir, sizeof(temp_dir), "%s", sys_temp);
        size_t l = strlen(temp_dir);
        if (l > 0 && (temp_dir[l - 1] == '\\' || temp_dir[l - 1] == '/')) {
            temp_dir[l - 1] = '\0';
        }
    }
#else
    const char *tmp = getenv("TMPDIR");
    if (!tmp) tmp = "/tmp";
    snprintf(temp_dir, sizeof(temp_dir), "%s", tmp);
#endif

    uint8_t rand_bytes[8];
    stego_random_bytes(rand_bytes, sizeof(rand_bytes));

    char subfolder[512];
    snprintf(subfolder, sizeof(subfolder), "%s/stego_dir_%02x%02x%02x%02x",
             temp_dir, rand_bytes[0], rand_bytes[1], rand_bytes[2], rand_bytes[3]);

#if defined(_WIN32)
    CreateDirectoryA(subfolder, NULL);
#else
    mkdir(subfolder, 0700);
#endif

    const char *base = original_name ? strrchr(original_name, '/') : NULL;
    if (!base && original_name) base = strrchr(original_name, '\\');
    base = base ? base + 1 : (original_name ? original_name : "secret.bin");
    if (base[0] == '\0') base = "secret.bin";

    char safe_name[256];
    size_t i = 0;
    for (; base[i] != '\0' && i < sizeof(safe_name) - 1; i++) {
        char c = base[i];
        if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') {
            safe_name[i] = '_';
        } else {
            safe_name[i] = c;
        }
    }
    safe_name[i] = '\0';

    char filename[512];
    snprintf(filename, sizeof(filename), "%s/%s", subfolder, safe_name);

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
#if defined(_WIN32)
        RemoveDirectoryA(subfolder);
#else
        rmdir(subfolder);
#endif
        return NULL;
    }

    if (data && size > 0) {
        if (fwrite(data, 1, size, fp) != size) {
            fclose(fp);
            remove(filename);
#if defined(_WIN32)
            RemoveDirectoryA(subfolder);
#else
            rmdir(subfolder);
#endif
            return NULL;
        }
    }
    fclose(fp);

    char *result = (char *)malloc(strlen(filename) + 1);
    if (result) {
        strcpy(result, filename);
    }
    return result;
}

void uploads_cleanup_temp_file(const char *path) {
    if (!path || path[0] == '\0') return;

    /* Securely overwrite before deletion */
    FILE *fp = fopen(path, "r+b");
    if (fp) {
        fseek(fp, 0, SEEK_END);
        long len = ftell(fp);
        if (len > 0) {
            fseek(fp, 0, SEEK_SET);
            uint8_t zero_buf[4096];
            memset(zero_buf, 0, sizeof(zero_buf));
            long remaining = len;
            while (remaining > 0) {
                size_t to_write = (remaining > (long)sizeof(zero_buf)) ? sizeof(zero_buf) : (size_t)remaining;
                fwrite(zero_buf, 1, to_write, fp);
                remaining -= to_write;
            }
            fflush(fp);
        }
        fclose(fp);
    }
    remove(path);

    /* Clean up parent folder if it was a temporary directory created for this file */
    const char *last_slash = strrchr(path, '/');
    if (!last_slash) last_slash = strrchr(path, '\\');
    if (last_slash) {
        char parent[512];
        size_t plen = (size_t)(last_slash - path);
        if (plen < sizeof(parent)) {
            memcpy(parent, path, plen);
            parent[plen] = '\0';
            if (strstr(parent, "stego_dir_") != NULL) {
#if defined(_WIN32)
                RemoveDirectoryA(parent);
#else
                rmdir(parent);
#endif
            }
        }
    }
}
