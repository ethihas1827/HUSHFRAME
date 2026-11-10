/**
 * @file server.c
 * @brief Privacy-first local HTTP server implementation for Hushframe.
 *
 * Binds strictly to 127.0.0.1 (loopback), serves the modern web frontend,
 * and routes API requests to the secure C steganography engine.
 */

#include "http.h"
#include "uploads.h"
#include "api.h"
#include "core/stego_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#endif

static volatile bool g_running = true;
static socket_t g_server_sock = INVALID_SOCKET;

static void handle_sigint(int sig) {
    (void)sig;
    g_running = false;
    if (g_server_sock != INVALID_SOCKET) {
        CLOSE_SOCKET(g_server_sock);
        g_server_sock = INVALID_SOCKET;
    }
}

#if defined(_WIN32)
static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT || ctrl_type == CTRL_CLOSE_EVENT) {
        handle_sigint(0);
        return TRUE;
    }
    return FALSE;
}
#endif

/* Rate limiter state */
#define RATE_LIMIT_WINDOW_SEC 2
#define RATE_LIMIT_MAX_REQS   60
static time_t g_window_start = 0;
static int g_req_count = 0;

static bool check_rate_limit(void) {
    time_t now = time(NULL);
    if (now - g_window_start >= RATE_LIMIT_WINDOW_SEC) {
        g_window_start = now;
        g_req_count = 1;
        return true;
    }
    g_req_count++;
    return (g_req_count <= RATE_LIMIT_MAX_REQS);
}

/* Locate frontend assets directory */
static bool file_exists_check(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (fp) {
        fclose(fp);
        return true;
    }
    return false;
}

static void find_frontend_dir(char *out_dir, size_t max_len) {
    const char *candidates[] = {
        "frontend",
        "./frontend",
        "../frontend",
        "hushframe/frontend",
        "../hushframe/frontend",
        "bmp-stego/frontend",
        "../bmp-stego/frontend"
    };

    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        char test_file[512];
        snprintf(test_file, sizeof(test_file), "%s/index.html", candidates[i]);
        if (file_exists_check(test_file)) {
            snprintf(out_dir, max_len, "%s", candidates[i]);
            return;
        }
    }

#if defined(_WIN32)
    char exe_path[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));
    if (len > 0) {
        char *last_slash = strrchr(exe_path, '\\');
        if (!last_slash) last_slash = strrchr(exe_path, '/');
        if (last_slash) {
            *last_slash = '\0';
            char test_file[MAX_PATH + 64];
            snprintf(test_file, sizeof(test_file), "%s/frontend/index.html", exe_path);
            if (file_exists_check(test_file)) {
                snprintf(out_dir, max_len, "%s/frontend", exe_path);
                return;
            }
        }
    }
#endif

    snprintf(out_dir, max_len, "frontend");
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

#if defined(_WIN32)
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[-] Fatal Error: Winsock initialization failed.\n");
        return 1;
    }
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
#endif
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    char frontend_dir[512];
    find_frontend_dir(frontend_dir, sizeof(frontend_dir));

    /* Create socket */
    socket_t listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        fprintf(stderr, "[-] Fatal Error: Failed to create TCP socket.\n");
#if defined(_WIN32)
        WSACleanup();
#endif
        return 1;
    }

    /* Reuse address */
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    /* Bind strictly to 127.0.0.1 (Loopback only) */
    int selected_port = 8080;
    bool bound = false;

    for (int port = 8080; port <= 8090; port++) {
        struct sockaddr_in saddr;
        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons((uint16_t)port);
        saddr.sin_addr.s_addr = inet_addr("127.0.0.1"); /* BIND ONLY TO 127.0.0.1 */

        if (bind(listen_sock, (struct sockaddr *)&saddr, sizeof(saddr)) == 0) {
            selected_port = port;
            bound = true;
            break;
        }
    }

    if (!bound) {
        fprintf(stderr, "[-] Error: Ports 8080-8090 are occupied on 127.0.0.1.\n");
        CLOSE_SOCKET(listen_sock);
#if defined(_WIN32)
        WSACleanup();
#endif
        return 1;
    }

    if (listen(listen_sock, 16) == SOCKET_ERROR) {
        fprintf(stderr, "[-] Error: Failed to listen on socket.\n");
        CLOSE_SOCKET(listen_sock);
#if defined(_WIN32)
        WSACleanup();
#endif
        return 1;
    }

    g_server_sock = listen_sock;

    printf("=================================================================\n");
    printf("  Hushframe — Keep what matters out of sight.\n");
    printf("  100%% Local Processing • No Cloud • Zero Telemetry\n");
    printf("  Engine: Argon2id (RFC 9106) + AES-256-GCM (NIST SP 800-38D)\n");
    printf("=================================================================\n");
    printf("Hushframe is running:\n");
    printf("http://127.0.0.1:%d\n", selected_port);
    printf("=================================================================\n");
    printf("Serving web interface from: %s\n", frontend_dir);
    printf("Press Ctrl+C to stop the server.\n\n");
    fflush(stdout);

    while (g_running) {
        struct sockaddr_in client_addr;
        int addr_len = sizeof(client_addr);
        socket_t client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);

        if (client_sock == INVALID_SOCKET) {
            if (!g_running) break;
            continue;
        }

        /* Check rate limiting */
        if (!check_rate_limit()) {
            HttpResponse res;
            http_response_set_json(&res, 429, "{\"success\":false,\"error\":\"Too many requests. Please slow down.\"}");
            http_send_response(client_sock, &res);
            http_response_free(&res);
            CLOSE_SOCKET(client_sock);
            continue;
        }

        /* Set socket timeouts (10 seconds) */
#if defined(_WIN32)
        DWORD timeout = 10000;
        setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
        setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
#else
        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
        setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#endif

        /* Read request line and headers */
        size_t initial_cap = 65536;
        uint8_t *raw_buf = (uint8_t *)malloc(initial_cap);
        if (!raw_buf) {
            CLOSE_SOCKET(client_sock);
            continue;
        }

        size_t bytes_read = 0;
        size_t header_bytes = 0;
        HttpRequest req;
        bool headers_parsed = false;

        while (bytes_read < initial_cap) {
            int n = recv(client_sock, (char *)raw_buf + bytes_read, (int)(initial_cap - bytes_read), 0);
            if (n <= 0) break;
            bytes_read += n;

            if (http_parse_request_headers(raw_buf, bytes_read, &req, &header_bytes) == 0) {
                headers_parsed = true;
                break;
            }
        }

        if (!headers_parsed) {
            HttpResponse res;
            http_response_set_json(&res, 400, "{\"success\":false,\"error\":\"Malformed HTTP request headers.\"}");
            http_send_response(client_sock, &res);
            http_response_free(&res);
            free(raw_buf);
            CLOSE_SOCKET(client_sock);
            continue;
        }

        /* Check Content-Length size limits */
        if (req.content_length > STEGO_MAX_UPLOAD_SIZE) {
            HttpResponse res;
            http_response_set_json(&res, 413, "{\"success\":false,\"error\":\"Upload exceeds maximum permitted size of 64 MB.\"}");
            http_send_response(client_sock, &res);
            http_response_free(&res);
            free(raw_buf);
            CLOSE_SOCKET(client_sock);
            continue;
        }

        /* Read full body if present */
        if (req.content_length > 0) {
            size_t body_already_read = bytes_read - header_bytes;
            size_t needed = req.content_length;

            uint8_t *full_body = (uint8_t *)malloc(needed + 1);
            if (!full_body) {
                HttpResponse res;
                http_response_set_json(&res, 500, "{\"success\":false,\"error\":\"Server out of memory allocating request body.\"}");
                http_send_response(client_sock, &res);
                http_response_free(&res);
                free(raw_buf);
                CLOSE_SOCKET(client_sock);
                continue;
            }

            size_t copy_amount = (body_already_read < needed) ? body_already_read : needed;
            if (copy_amount > 0) {
                memcpy(full_body, raw_buf + header_bytes, copy_amount);
            }

            size_t total_body_read = copy_amount;
            while (total_body_read < needed) {
                int to_read = (int)(needed - total_body_read);
                if (to_read > 65536) to_read = 65536;
                int n = recv(client_sock, (char *)full_body + total_body_read, to_read, 0);
                if (n <= 0) break;
                total_body_read += n;
            }

            full_body[total_body_read] = '\0';
            req.body = full_body;
            req.body_len = total_body_read;
        }

        /* Dispatch request */
        HttpResponse res;
        memset(&res, 0, sizeof(res));

        if (req.method == HTTP_METHOD_OPTIONS) {
            http_response_init(&res, 204, "text/plain");
        } else if (strncmp(req.path, "/api/", 5) == 0) {
            printf("[HTTP] %s %s - processing...\n",
                   req.method == HTTP_METHOD_POST ? "POST" : "GET", req.path);
            api_handle_request(&req, &res);
            printf("[HTTP] %s %s -> %d %s\n",
                   req.method == HTTP_METHOD_POST ? "POST" : "GET", req.path,
                   res.status_code, res.status_text);
            fflush(stdout);
        } else {
            /* Serve static files */
            if (!http_serve_static(frontend_dir, req.path, &res)) {
                http_response_set_json(&res, 404, "{\"success\":false,\"error\":\"Resource not found.\"}");
            }
            fflush(stdout);
        }

        http_send_response(client_sock, &res);
        http_response_free(&res);

        if (req.body) {
            free(req.body);
            req.body = NULL;
        }
        free(raw_buf);
        CLOSE_SOCKET(client_sock);
    }

    if (listen_sock != INVALID_SOCKET) {
        CLOSE_SOCKET(listen_sock);
    }
#if defined(_WIN32)
    WSACleanup();
#endif
    printf("\n[*] Hushframe server stopped cleanly.\n");
    return 0;
}

