/**
 * @file http.h
 * @brief Lightweight HTTP parser, response builder, and static file server.
 */

#ifndef STEGO_HTTP_H
#define STEGO_HTTP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#define CLOSE_SOCKET(s) closesocket(s)
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int socket_t;
#define CLOSE_SOCKET(s) close(s)
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_UNKNOWN
} HttpMethod;

typedef struct {
    HttpMethod method;
    char path[512];
    char query[512];
    char content_type[256];
    char boundary[256];
    size_t content_length;
    uint8_t *body;
    size_t body_len;
} HttpRequest;

typedef struct {
    int status_code;
    char status_text[64];
    char content_type[128];
    char custom_headers[1024];
    uint8_t *body;
    size_t body_len;
    bool own_body;
} HttpResponse;

/**
 * @brief Parse HTTP request line and headers.
 *
 * @param raw_buf Raw bytes read from client socket
 * @param raw_len Total bytes in raw_buf
 * @param req Destination HttpRequest struct
 * @param out_header_bytes Bytes consumed by request line and headers
 * @return 0 on success, -1 on malformed request
 */
int http_parse_request_headers(const uint8_t *raw_buf, size_t raw_len, HttpRequest *req, size_t *out_header_bytes);

/**
 * @brief Initialize a response with default status and content-type.
 */
void http_response_init(HttpResponse *res, int status_code, const char *content_type);

/**
 * @brief Set JSON response body.
 */
void http_response_set_json(HttpResponse *res, int status_code, const char *json_str);

/**
 * @brief Set binary or text response body.
 */
void http_response_set_bytes(HttpResponse *res, int status_code, const char *content_type, const uint8_t *bytes, size_t len);

/**
 * @brief Add a custom HTTP header (e.g. Content-Disposition).
 */
void http_response_add_header(HttpResponse *res, const char *name, const char *val);

/**
 * @brief Clean up any dynamically allocated memory in an HttpResponse.
 */
void http_response_free(HttpResponse *res);

/**
 * @brief Serialize and send an HttpResponse to a client socket.
 */
int http_send_response(socket_t sock, const HttpResponse *res);

/**
 * @brief Serve static files (HTML, CSS, JS) from the local frontend directory.
 *
 * Performs strict path canonicalization and rejects directory traversal.
 *
 * @param frontend_dir Base directory path for frontend assets
 * @param req_path Requested URI path
 * @param res Destination HttpResponse struct
 * @return true if file was found and served, false otherwise
 */
bool http_serve_static(const char *frontend_dir, const char *req_path, HttpResponse *res);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_HTTP_H */

