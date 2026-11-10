/**
 * @file compress.c
 * @brief Lossless compression (DEFLATE / zlib) for steganographic payloads.
 */

#include "stego/compress.h"
#include "stb_image.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ========================================================================= */
/* Check for already-compressed formats                                      */
/* ========================================================================= */

bool stego_is_already_compressed_format(const char *filename) {
    if (!filename) return false;
    const char *dot = strrchr(filename, '.');
    if (!dot) return false;

    char ext[16] = {0};
    size_t i = 0;
    while (dot[i] && i < sizeof(ext) - 1) {
        ext[i] = (char)tolower((unsigned char)dot[i]);
        i++;
    }

    const char *known_compressed[] = {
        ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".zst",
        ".jpg", ".jpeg", ".webp", ".png", ".gif", ".avif", ".heic",
        ".mp3", ".mp4", ".m4a", ".aac", ".ogg", ".opus", ".flac",
        ".avi", ".mkv", ".mov", ".webm",
        ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
        ".jar", ".apk", ".ipa"
    };

    for (size_t k = 0; k < sizeof(known_compressed) / sizeof(known_compressed[0]); k++) {
        if (strcmp(ext, known_compressed[k]) == 0) {
            return true;
        }
    }
    return false;
}

/* ========================================================================= */
/* Adler-32 Checksum (RFC 1950)                                              */
/* ========================================================================= */

static uint32_t compute_adler32(const uint8_t *data, size_t len) {
    uint32_t a = 1, b = 0;
    const uint32_t MOD_ADLER = 65521;
    for (size_t i = 0; i < len; i++) {
        a = (a + data[i]) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    return (b << 16) | a;
}

/* ========================================================================= */
/* Bit Writer for DEFLATE Bitstreams                                         */
/* ========================================================================= */

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t byte_len;
    uint32_t bit_buf;
    int bit_cnt;
} BitWriter;

static void bw_init(BitWriter *bw, size_t initial_cap) {
    bw->cap = (initial_cap > 64) ? initial_cap : 64;
    bw->buf = (uint8_t *)malloc(bw->cap);
    bw->byte_len = 0;
    bw->bit_buf = 0;
    bw->bit_cnt = 0;
}

static void bw_ensure(BitWriter *bw, size_t needed) {
    if (bw->byte_len + needed + 8 >= bw->cap) {
        bw->cap = (bw->cap * 2) + needed + 128;
        bw->buf = (uint8_t *)realloc(bw->buf, bw->cap);
    }
}

static void bw_write_bits(BitWriter *bw, uint32_t bits, int num_bits) {
    bw->bit_buf |= (bits << bw->bit_cnt);
    bw->bit_cnt += num_bits;
    while (bw->bit_cnt >= 8) {
        bw_ensure(bw, 1);
        bw->buf[bw->byte_len++] = (uint8_t)(bw->bit_buf & 0xFF);
        bw->bit_buf >>= 8;
        bw->bit_cnt -= 8;
    }
}

static void bw_flush(BitWriter *bw) {
    if (bw->bit_cnt > 0) {
        bw_ensure(bw, 1);
        bw->buf[bw->byte_len++] = (uint8_t)(bw->bit_buf & 0xFF);
        bw->bit_buf = 0;
        bw->bit_cnt = 0;
    }
}

/* Reverse bits helper for Huffman codes */
static uint32_t rev_bits(uint32_t code, int len) {
    uint32_t res = 0;
    for (int i = 0; i < len; i++) {
        res = (res << 1) | ((code >> i) & 1);
    }
    return res;
}

/* ========================================================================= */
/* Fixed Huffman DEFLATE Tables (RFC 1951)                                   */
/* ========================================================================= */

static void write_fixed_literal(BitWriter *bw, int lit) {
    if (lit <= 143) {
        /* 0 - 143: 8 bits, 00110000 - 10111111 (0x30 + lit) */
        uint32_t code = 0x30 + lit;
        bw_write_bits(bw, rev_bits(code, 8), 8);
    } else if (lit <= 255) {
        /* 144 - 255: 9 bits, 110010000 - 111111111 (0x190 + (lit - 144)) */
        uint32_t code = 0x190 + (lit - 144);
        bw_write_bits(bw, rev_bits(code, 9), 9);
    } else if (lit <= 279) {
        /* 256 - 279: 7 bits, 0000000 - 0010111 (lit - 256) */
        uint32_t code = (uint32_t)(lit - 256);
        bw_write_bits(bw, rev_bits(code, 7), 7);
    } else {
        /* 280 - 287: 8 bits, 11000000 - 11000111 (0xC0 + (lit - 280)) */
        uint32_t code = 0xC0 + (lit - 280);
        bw_write_bits(bw, rev_bits(code, 8), 8);
    }
}

static const struct { uint16_t min_len; uint8_t extra_bits; uint16_t code; } kLenTable[] = {
    {3, 0, 257}, {4, 0, 258}, {5, 0, 259}, {6, 0, 260}, {7, 0, 261}, {8, 0, 262},
    {9, 0, 263}, {10, 0, 264}, {11, 1, 265}, {13, 1, 266}, {15, 1, 267}, {17, 1, 268},
    {19, 2, 269}, {23, 2, 270}, {27, 2, 271}, {31, 2, 272}, {35, 3, 273}, {43, 3, 274},
    {51, 3, 275}, {59, 3, 276}, {67, 4, 277}, {83, 4, 278}, {99, 4, 279}, {115, 4, 280},
    {131, 5, 281}, {163, 5, 282}, {195, 5, 283}, {227, 5, 284}, {258, 0, 285}
};

static void write_fixed_match(BitWriter *bw, int length, int dist) {
    /* Find length code */
    int len_idx = 0;
    while (len_idx < 28 && length >= kLenTable[len_idx + 1].min_len) {
        len_idx++;
    }
    write_fixed_literal(bw, kLenTable[len_idx].code);
    if (kLenTable[len_idx].extra_bits > 0) {
        int extra = length - kLenTable[len_idx].min_len;
        bw_write_bits(bw, (uint32_t)extra, kLenTable[len_idx].extra_bits);
    }

    /* Find distance code */
    static const struct { uint16_t min_dist; uint8_t extra_bits; } kDistTable[] = {
        {1, 0}, {2, 0}, {3, 0}, {4, 0}, {5, 1}, {7, 1}, {9, 2}, {13, 2},
        {17, 3}, {25, 3}, {33, 4}, {49, 4}, {65, 5}, {97, 5}, {129, 6}, {193, 6},
        {257, 7}, {385, 7}, {513, 8}, {769, 8}, {1025, 9}, {1537, 9}, {2049, 10}, {3073, 10},
        {4097, 11}, {6145, 11}, {8193, 12}, {12289, 12}, {16385, 13}, {24577, 13}
    };
    int dist_idx = 0;
    while (dist_idx < 29 && dist >= kDistTable[dist_idx + 1].min_dist) {
        dist_idx++;
    }
    /* Fixed distance codes are 5 bits, MSB first reversed */
    bw_write_bits(bw, rev_bits((uint32_t)dist_idx, 5), 5);
    if (kDistTable[dist_idx].extra_bits > 0) {
        int extra = dist - kDistTable[dist_idx].min_dist;
        bw_write_bits(bw, (uint32_t)extra, kDistTable[dist_idx].extra_bits);
    }
}

/* ========================================================================= */
/* LZ77 DEFLATE Compression Engine                                           */
/* ========================================================================= */

#define HASH_BITS 13
#define HASH_SIZE (1 << HASH_BITS)
#define WINDOW_SIZE 32768
#define MAX_MATCH 258
#define MIN_MATCH 3

static uint16_t hash3(const uint8_t *p) {
    return (uint16_t)(((p[0] << 8) ^ (p[1] << 4) ^ p[2]) & (HASH_SIZE - 1));
}

StegoResult stego_compress(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    if (!out || !out_len) return STEGO_ERR_INVALID_ARG;
    *out = NULL;
    *out_len = 0;

    if (!in || in_len == 0) {
        /* Empty buffer compresses to minimal zlib empty stream */
        uint8_t *empty_zlib = (uint8_t *)malloc(8);
        if (!empty_zlib) return STEGO_ERR_MEMORY;
        empty_zlib[0] = 0x78; empty_zlib[1] = 0x01; /* zlib header */
        empty_zlib[2] = 0x01; empty_zlib[3] = 0x00; empty_zlib[4] = 0x00; /* BFINAL=1, BTYPE=00, LEN=0 */
        empty_zlib[5] = 0xFF; empty_zlib[6] = 0xFF;
        empty_zlib[7] = 0x01; /* adler-32 */
        *out = empty_zlib;
        *out_len = 8;
        return STEGO_OK;
    }

    BitWriter bw;
    bw_init(&bw, in_len / 2 + 128);

    /* 1. Write zlib header: CM=8 (Deflate), CINFO=7 (32K window), FLG default check */
    bw.buf[bw.byte_len++] = 0x78;
    bw.buf[bw.byte_len++] = 0x9C; /* Default compression flag, satisfies (0x789C % 31 == 0) */

    /* 2. Write Deflate block header: BFINAL=1 (last block), BTYPE=01 (fixed Huffman) */
    bw_write_bits(&bw, 1, 1); /* BFINAL = 1 */
    bw_write_bits(&bw, 1, 2); /* BTYPE = 01 (fixed) */

    /* Hash table for LZ77 matching */
    int32_t *head = (int32_t *)malloc(HASH_SIZE * sizeof(int32_t));
    int32_t *prev = (int32_t *)malloc(WINDOW_SIZE * sizeof(int32_t));
    if (!head || !prev) {
        if (head) free(head);
        if (prev) free(prev);
        free(bw.buf);
        return STEGO_ERR_MEMORY;
    }
    for (int i = 0; i < HASH_SIZE; i++) head[i] = -1;

    size_t pos = 0;
    while (pos < in_len) {
        int best_len = 0;
        int best_dist = 0;

        if (pos + MIN_MATCH <= in_len) {
            uint16_t h = hash3(in + pos);
            int32_t match_pos = head[h];
            head[h] = (int32_t)pos;
            prev[pos & (WINDOW_SIZE - 1)] = match_pos;

            int chain_len = 32; /* Limit match search for speed */
            while (match_pos >= 0 && (int32_t)pos - match_pos < WINDOW_SIZE && chain_len-- > 0) {
                int match_len = 0;
                while (pos + match_len < in_len && match_len < MAX_MATCH &&
                       in[pos + match_len] == in[match_pos + match_len]) {
                    match_len++;
                }
                if (match_len > best_len) {
                    best_len = match_len;
                    best_dist = (int)(pos - match_pos);
                    if (best_len >= MAX_MATCH) break;
                }
                match_pos = prev[match_pos & (WINDOW_SIZE - 1)];
            }
        }

        if (best_len >= MIN_MATCH) {
            write_fixed_match(&bw, best_len, best_dist);
            /* Insert skipped bytes into hash chain */
            for (size_t k = 1; k < (size_t)best_len && pos + k + MIN_MATCH <= in_len; k++) {
                uint16_t h = hash3(in + pos + k);
                prev[(pos + k) & (WINDOW_SIZE - 1)] = head[h];
                head[h] = (int32_t)(pos + k);
            }
            pos += best_len;
        } else {
            write_fixed_literal(&bw, in[pos]);
            pos++;
        }
    }

    free(head);
    free(prev);

    /* 3. Write end-of-block literal 256 */
    write_fixed_literal(&bw, 256);
    bw_flush(&bw);

    /* 4. Write 4-byte big-endian Adler-32 */
    uint32_t adler = compute_adler32(in, in_len);
    bw_ensure(&bw, 4);
    bw.buf[bw.byte_len++] = (uint8_t)((adler >> 24) & 0xFF);
    bw.buf[bw.byte_len++] = (uint8_t)((adler >> 16) & 0xFF);
    bw.buf[bw.byte_len++] = (uint8_t)((adler >> 8)  & 0xFF);
    bw.buf[bw.byte_len++] = (uint8_t)(adler         & 0xFF);

    *out = bw.buf;
    *out_len = bw.byte_len;
    return STEGO_OK;
}

/* ========================================================================= */
/* DEFLATE Decompression Engine                                              */
/* ========================================================================= */

StegoResult stego_decompress(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    if (!out || !out_len) return STEGO_ERR_INVALID_ARG;
    *out = NULL;
    *out_len = 0;

    if (!in || in_len < 2) return STEGO_ERR_INVALID_ARG;

    int decoded_len = 0;
    char *decoded = stbi_zlib_decode_malloc((const char *)in, (int)in_len, &decoded_len);
    if (!decoded || decoded_len < 0) {
        return STEGO_ERR_CORRUPT_PAYLOAD;
    }

    *out = (uint8_t *)decoded;
    *out_len = (size_t)decoded_len;
    return STEGO_OK;
}

/* ========================================================================= */
/* CMP1 Envelope Framing (Pre-Encryption Lossless Compression)               */
/* ========================================================================= */

StegoResult stego_compress_payload_if_beneficial(const uint8_t *in, size_t in_len,
                                                uint8_t **out, size_t *out_len,
                                                bool *out_was_compressed) {
    if (!out || !out_len || !out_was_compressed) return STEGO_ERR_INVALID_ARG;
    *out = NULL;
    *out_len = 0;
    *out_was_compressed = false;

    if (!in || in_len == 0) {
        *out = (uint8_t *)malloc(1);
        if (!*out) return STEGO_ERR_MEMORY;
        (*out)[0] = '\0';
        *out_len = 0;
        return STEGO_OK;
    }

    /* Small payloads (< 64 bytes) don't gain from compression */
    if (in_len < 64) {
        uint8_t *copy = (uint8_t *)malloc(in_len);
        if (!copy) return STEGO_ERR_MEMORY;
        memcpy(copy, in, in_len);
        *out = copy;
        *out_len = in_len;
        return STEGO_OK;
    }

    uint8_t *comp = NULL;
    size_t comp_len = 0;
    StegoResult res = stego_compress(in, in_len, &comp, &comp_len);
    if (res != STEGO_OK) {
        /* Fallback to uncompressed copy */
        uint8_t *copy = (uint8_t *)malloc(in_len);
        if (!copy) return STEGO_ERR_MEMORY;
        memcpy(copy, in, in_len);
        *out = copy;
        *out_len = in_len;
        return STEGO_OK;
    }

    /* Check if compressed size + 8-byte CMP1 header is smaller than original */
    if (comp_len + STEGO_COMPRESS_HEADER_SIZE < in_len) {
        size_t total_len = STEGO_COMPRESS_HEADER_SIZE + comp_len;
        uint8_t *packed = (uint8_t *)malloc(total_len);
        if (!packed) {
            free(comp);
            return STEGO_ERR_MEMORY;
        }

        /* Magic CMP1 */
        packed[0] = STEGO_COMPRESS_MAGIC_BYTE0;
        packed[1] = STEGO_COMPRESS_MAGIC_BYTE1;
        packed[2] = STEGO_COMPRESS_MAGIC_BYTE2;
        packed[3] = STEGO_COMPRESS_MAGIC_BYTE3;

        /* Original length 4 bytes big-endian */
        packed[4] = (uint8_t)((in_len >> 24) & 0xFF);
        packed[5] = (uint8_t)((in_len >> 16) & 0xFF);
        packed[6] = (uint8_t)((in_len >> 8)  & 0xFF);
        packed[7] = (uint8_t)(in_len         & 0xFF);

        memcpy(packed + STEGO_COMPRESS_HEADER_SIZE, comp, comp_len);
        free(comp);

        *out = packed;
        *out_len = total_len;
        *out_was_compressed = true;
        return STEGO_OK;
    }

    /* Compression was not beneficial; use original */
    free(comp);
    uint8_t *copy = (uint8_t *)malloc(in_len);
    if (!copy) return STEGO_ERR_MEMORY;
    memcpy(copy, in, in_len);
    *out = copy;
    *out_len = in_len;
    *out_was_compressed = false;
    return STEGO_OK;
}

StegoResult stego_decompress_payload_if_packed(const uint8_t *in, size_t in_len,
                                              uint8_t **out, size_t *out_len,
                                              bool *out_was_decompressed) {
    if (!out || !out_len || !out_was_decompressed) return STEGO_ERR_INVALID_ARG;
    *out = NULL;
    *out_len = 0;
    *out_was_decompressed = false;

    if (!in || in_len == 0) {
        *out = (uint8_t *)malloc(1);
        if (!*out) return STEGO_ERR_MEMORY;
        (*out)[0] = '\0';
        *out_len = 0;
        return STEGO_OK;
    }

    /* Check for CMP1 header */
    if (in_len >= STEGO_COMPRESS_HEADER_SIZE &&
        in[0] == STEGO_COMPRESS_MAGIC_BYTE0 &&
        in[1] == STEGO_COMPRESS_MAGIC_BYTE1 &&
        in[2] == STEGO_COMPRESS_MAGIC_BYTE2 &&
        in[3] == STEGO_COMPRESS_MAGIC_BYTE3) {

        uint32_t expected_orig_len = ((uint32_t)in[4] << 24) |
                                     ((uint32_t)in[5] << 16) |
                                     ((uint32_t)in[6] << 8)  |
                                      (uint32_t)in[7];

        const uint8_t *comp_data = in + STEGO_COMPRESS_HEADER_SIZE;
        size_t comp_len = in_len - STEGO_COMPRESS_HEADER_SIZE;

        uint8_t *decomp = NULL;
        size_t decomp_len = 0;
        StegoResult res = stego_decompress(comp_data, comp_len, &decomp, &decomp_len);
        if (res == STEGO_OK && decomp_len == expected_orig_len) {
            *out = decomp;
            *out_len = decomp_len;
            *out_was_decompressed = true;
            return STEGO_OK;
        }

        if (decomp) free(decomp);
        return STEGO_ERR_CORRUPT_PAYLOAD;
    }

    /* Not packed with CMP1: return exact copy */
    uint8_t *copy = (uint8_t *)malloc(in_len);
    if (!copy) return STEGO_ERR_MEMORY;
    memcpy(copy, in, in_len);
    *out = copy;
    *out_len = in_len;
    *out_was_decompressed = false;
    return STEGO_OK;
}
