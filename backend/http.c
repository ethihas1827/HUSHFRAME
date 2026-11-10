/**
 * @file http.c
 * @brief HTTP request parsing, response formatting, and static file server implementation.
 */

#include "http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

static const char *get_status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 413: return "Payload Too Large";
        case 500: return "Internal Server Error";
        default:  return "Unknown";
    }
}

int http_parse_request_headers(const uint8_t *raw_buf, size_t raw_len, HttpRequest *req, size_t *out_header_bytes) {
    if (!raw_buf || raw_len == 0 || !req) return -1;
    memset(req, 0, sizeof(HttpRequest));

    /* Find end of headers \r\n\r\n or \n\n */
    const char *buf = (const char *)raw_buf;
    const char *hdr_end = strstr(buf, "\r\n\r\n");
    size_t term_len = 4;
    if (!hdr_end) {
        hdr_end = strstr(buf, "\n\n");
        term_len = 2;
        if (!hdr_end) return -1; /* Incomplete headers */
    }

    size_t hdr_len = (hdr_end - buf);
    if (out_header_bytes) {
        *out_header_bytes = hdr_len + term_len;
    }

    /* Parse request line: METHOD PATH VERSION */
    char method_str[16] = {0};
    char full_path[512] = {0};
    char version_str[32] = {0};

    if (sscanf(buf, "%15s %511s %31s", method_str, full_path, version_str) < 2) {
        return -1;
    }

    if (strcmp(method_str, "GET") == 0) req->method = HTTP_METHOD_GET;
    else if (strcmp(method_str, "POST") == 0) req->method = HTTP_METHOD_POST;
    else if (strcmp(method_str, "OPTIONS") == 0) req->method = HTTP_METHOD_OPTIONS;
    else req->method = HTTP_METHOD_UNKNOWN;

    /* Separate path and query string */
    char *qmark = strchr(full_path, '?');
    if (qmark) {
        *qmark = '\0';
        snprintf(req->query, sizeof(req->query), "%s", qmark + 1);
    }
    snprintf(req->path, sizeof(req->path), "%s", full_path);

    /* Security check on path: prevent traversal */
    if (strstr(req->path, "..") || strchr(req->path, '\\') || strstr(req->path, "%2e%2e") || strstr(req->path, "%2E%2E")) {
        return -1;
    }

    /* Parse headers line by line */
    const char *line = strstr(buf, "\n");
    if (line) line++;

    while (line && line < hdr_end) {
        const char *next_line = strstr(line, "\n");
        size_t line_len = next_line ? (size_t)(next_line - line) : (size_t)(hdr_end - line);
        if (line_len > 0 && line[line_len - 1] == '\r') line_len--;

        if (line_len > 0) {
            char hdr_line[1024];
            size_t copy_len = (line_len < sizeof(hdr_line) - 1) ? line_len : sizeof(hdr_line) - 1;
            memcpy(hdr_line, line, copy_len);
            hdr_line[copy_len] = '\0';

            char *colon = strchr(hdr_line, ':');
            if (colon) {
                *colon = '\0';
                char *name = hdr_line;
                char *val = colon + 1;
                while (*val == ' ') val++;

                if (_stricmp(name, "Content-Length") == 0) {
                    req->content_length = (size_t)strtoul(val, NULL, 10);
                } else if (_stricmp(name, "Content-Type") == 0) {
                    snprintf(req->content_type, sizeof(req->content_type), "%s", val);

                    /* Check for multipart boundary */
                    char *bnd = strstr(val, "boundary=");
                    if (bnd) {
                        bnd += 9;
                        if (*bnd == '"') bnd++;
                        char *bnd_end = bnd;
                        while (*bnd_end && *bnd_end != '"' && *bnd_end != ';' && *bnd_end != ' ' && *bnd_end != '\r' && *bnd_end != '\n') {
                            bnd_end++;
                        }
                        size_t blen = bnd_end - bnd;
                        if (blen < sizeof(req->boundary)) {
                            memcpy(req->boundary, bnd, blen);
                            req->boundary[blen] = '\0';
                        }
                    }
                }
            }
        }

        line = next_line ? next_line + 1 : NULL;
    }

    return 0;
}

void http_response_init(HttpResponse *res, int status_code, const char *content_type) {
    if (!res) return;
    memset(res, 0, sizeof(HttpResponse));
    res->status_code = status_code;
    snprintf(res->status_text, sizeof(res->status_text), "%s", get_status_text(status_code));
    snprintf(res->content_type, sizeof(res->content_type), "%s", content_type ? content_type : "text/plain");
}

void http_response_set_json(HttpResponse *res, int status_code, const char *json_str) {
    if (!res) return;
    http_response_init(res, status_code, "application/json; charset=utf-8");
    if (json_str) {
        size_t len = strlen(json_str);
        res->body = (uint8_t *)malloc(len + 1);
        if (res->body) {
            memcpy(res->body, json_str, len);
            res->body[len] = '\0';
            res->body_len = len;
            res->own_body = true;
        }
    }
}

void http_response_set_bytes(HttpResponse *res, int status_code, const char *content_type, const uint8_t *bytes, size_t len) {
    if (!res) return;
    http_response_init(res, status_code, content_type);
    if (bytes && len > 0) {
        res->body = (uint8_t *)malloc(len + 1);
        if (res->body) {
            memcpy(res->body, bytes, len);
            res->body[len] = '\0';
            res->body_len = len;
            res->own_body = true;
        }
    }
}

void http_response_add_header(HttpResponse *res, const char *name, const char *val) {
    if (!res || !name || !val) return;
    char line[256];
    snprintf(line, sizeof(line), "%s: %s\r\n", name, val);
    size_t cur = strlen(res->custom_headers);
    if (cur + strlen(line) < sizeof(res->custom_headers)) {
        strcat(res->custom_headers, line);
    }
}

void http_response_free(HttpResponse *res) {
    if (!res) return;
    if (res->own_body && res->body) {
        free(res->body);
        res->body = NULL;
    }
    res->body_len = 0;
}

int http_send_response(socket_t sock, const HttpResponse *res) {
    if (sock == INVALID_SOCKET || !res) return -1;

    char header_buf[2048];
    int hdr_len = snprintf(header_buf, sizeof(header_buf),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "Cache-Control: no-cache, no-store, must-revalidate\r\n"
        "%s"
        "\r\n",
        res->status_code, res->status_text,
        res->content_type,
        res->body_len,
        res->custom_headers);

    if (hdr_len <= 0) return -1;

    /* Send headers */
    const char *p = header_buf;
    int remaining = hdr_len;
    while (remaining > 0) {
        int sent = send(sock, p, remaining, 0);
        if (sent <= 0) return -1;
        p += sent;
        remaining -= sent;
    }

    /* Send body */
    if (res->body && res->body_len > 0) {
        const char *bp = (const char *)res->body;
        size_t b_rem = res->body_len;
        while (b_rem > 0) {
            int chunk = (b_rem > 65536) ? 65536 : (int)b_rem;
            int sent = send(sock, bp, chunk, 0);
            if (sent <= 0) return -1;
            bp += sent;
            b_rem -= sent;
        }
    }

    return 0;
}

static const char *get_mime_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";
    if (_stricmp(ext, ".html") == 0 || _stricmp(ext, ".htm") == 0) return "text/html; charset=utf-8";
    if (_stricmp(ext, ".css") == 0) return "text/css; charset=utf-8";
    if (_stricmp(ext, ".js") == 0) return "application/javascript; charset=utf-8";
    if (_stricmp(ext, ".png") == 0) return "image/png";
    if (_stricmp(ext, ".jpg") == 0 || _stricmp(ext, ".jpeg") == 0) return "image/jpeg";
    if (_stricmp(ext, ".svg") == 0) return "image/svg+xml";
    if (_stricmp(ext, ".json") == 0) return "application/json; charset=utf-8";
    if (_stricmp(ext, ".ico") == 0) return "image/x-icon";
    return "application/octet-stream";
}

bool http_serve_static(const char *frontend_dir, const char *req_path, HttpResponse *res) {
    if (!frontend_dir || !req_path || !res) return false;

    /* Normalize root to index.html */
    const char *subpath = req_path;
    if (strcmp(subpath, "/") == 0 || subpath[0] == '\0') {
        subpath = "/index.html";
    }
    if (subpath[0] == '/') subpath++;

    /* Disallow any directory climbing or backslashes */
    if (strstr(subpath, "..") || strchr(subpath, '\\') || strstr(subpath, ":")) {
        return false;
    }

    char file_path[1024];
    snprintf(file_path, sizeof(file_path), "%s/%s", frontend_dir, subpath);

    FILE *fp = fopen(file_path, "rb");
    if (!fp) {
        return false;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize < 0 || fsize > 20 * 1024 * 1024) { /* 20 MB max static asset */
        fclose(fp);
        return false;
    }

    size_t size = (size_t)fsize;
    uint8_t *data = (uint8_t *)malloc(size + 1);
    if (!data) {
        fclose(fp);
        return false;
    }

    if (size > 0 && fread(data, 1, size, fp) != size) {
        free(data);
        fclose(fp);
        return false;
    }
    fclose(fp);
    data[size] = '\0';

    const char *mime = get_mime_type(file_path);
    http_response_init(res, 200, mime);
    res->body = data;
    res->body_len = size;
    res->own_body = true;

    return true;
}

