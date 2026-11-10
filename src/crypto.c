/**
 * @file crypto.c
 * @brief Memory hygiene, CRC-32, Argon2id KDF, and AES-256-GCM AEAD encryption.
 */

#include "stego/crypto.h"
#include <string.h>
#include <stdlib.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

/* ========================================================================= */
/* CRC-32 (IEEE 802.3 / ITU-T V.42) Lookup Table                             */
/* ========================================================================= */

static const uint32_t s_crc32_table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

uint32_t stego_crc32(uint32_t crc, const uint8_t *buf, size_t len) {
    crc = crc ^ 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = s_crc32_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

void stego_secure_zero(void *ptr, size_t len) {
    if (!ptr || len == 0) return;
#if defined(_WIN32)
    SecureZeroMemory(ptr, len);
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
#endif
}

int stego_const_time_memcmp(const void *a, const void *b, size_t len) {
    const volatile uint8_t *p1 = (const volatile uint8_t *)a;
    const volatile uint8_t *p2 = (const volatile uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (p1[i] ^ p2[i]);
    }
    return (int)diff;
}

/* ========================================================================= */
/* BLAKE2b & Argon2id Implementation (RFC 9106)                              */
/* ========================================================================= */

static const uint64_t s_blake2b_iv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t s_blake2b_sigma[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

static inline uint64_t rotr64(uint64_t w, unsigned c) {
    return (w >> c) | (w << (64 - c));
}

typedef struct {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t buf[128];
    size_t buflen;
    size_t outlen;
} Blake2bCtx;

static void blake2b_compress_ctx(Blake2bCtx *S, const uint8_t block[128]) {
    uint64_t m[16];
    for (int i = 0; i < 16; i++) {
        m[i] = ((uint64_t)block[8 * i + 0]) |
               (((uint64_t)block[8 * i + 1]) << 8) |
               (((uint64_t)block[8 * i + 2]) << 16) |
               (((uint64_t)block[8 * i + 3]) << 24) |
               (((uint64_t)block[8 * i + 4]) << 32) |
               (((uint64_t)block[8 * i + 5]) << 40) |
               (((uint64_t)block[8 * i + 6]) << 48) |
               (((uint64_t)block[8 * i + 7]) << 56);
    }

    uint64_t v[16];
    for (int i = 0; i < 8; i++) v[i] = S->h[i];
    v[8]  = s_blake2b_iv[0];
    v[9]  = s_blake2b_iv[1];
    v[10] = s_blake2b_iv[2];
    v[11] = s_blake2b_iv[3];
    v[12] = s_blake2b_iv[4] ^ S->t[0];
    v[13] = s_blake2b_iv[5] ^ S->t[1];
    v[14] = s_blake2b_iv[6] ^ S->f[0];
    v[15] = s_blake2b_iv[7] ^ S->f[1];

#define BLAKE2B_G(r, i, a, b, c, d) do { \
    a = a + b + m[s_blake2b_sigma[r][2 * i + 0]]; \
    d = rotr64(d ^ a, 32); \
    c = c + d; \
    b = rotr64(b ^ c, 24); \
    a = a + b + m[s_blake2b_sigma[r][2 * i + 1]]; \
    d = rotr64(d ^ a, 16); \
    c = c + d; \
    b = rotr64(b ^ c, 63); \
} while (0)

    for (int r = 0; r < 12; r++) {
        BLAKE2B_G(r, 0, v[0], v[4], v[8],  v[12]);
        BLAKE2B_G(r, 1, v[1], v[5], v[9],  v[13]);
        BLAKE2B_G(r, 2, v[2], v[6], v[10], v[14]);
        BLAKE2B_G(r, 3, v[3], v[7], v[11], v[15]);
        BLAKE2B_G(r, 4, v[0], v[5], v[10], v[15]);
        BLAKE2B_G(r, 5, v[1], v[6], v[11], v[12]);
        BLAKE2B_G(r, 6, v[2], v[7], v[8],  v[13]);
        BLAKE2B_G(r, 7, v[3], v[4], v[9],  v[14]);
    }
#undef BLAKE2B_G

    for (int i = 0; i < 8; i++) {
        S->h[i] ^= v[i] ^ v[i + 8];
    }
}

static void blake2b_init_ctx(Blake2bCtx *S, size_t outlen) {
    memset(S, 0, sizeof(*S));
    S->outlen = outlen;
    for (int i = 0; i < 8; i++) S->h[i] = s_blake2b_iv[i];
    S->h[0] ^= 0x01010000 ^ (uint64_t)outlen;
}

static void blake2b_update_ctx(Blake2bCtx *S, const void *in, size_t inlen) {
    const uint8_t *pin = (const uint8_t *)in;
    while (inlen > 0) {
        if (S->buflen == 128) {
            S->t[0] += 128;
            if (S->t[0] < 128) S->t[1]++;
            blake2b_compress_ctx(S, S->buf);
            S->buflen = 0;
        }
        size_t take = 128 - S->buflen;
        if (take > inlen) take = inlen;
        memcpy(S->buf + S->buflen, pin, take);
        S->buflen += take;
        pin += take;
        inlen -= take;
    }
}

static void blake2b_final_ctx(Blake2bCtx *S, uint8_t *out) {
    S->t[0] += S->buflen;
    if (S->t[0] < S->buflen) S->t[1]++;
    S->f[0] = ~0ULL;
    memset(S->buf + S->buflen, 0, 128 - S->buflen);
    blake2b_compress_ctx(S, S->buf);
    for (size_t i = 0; i < S->outlen; i++) {
        out[i] = (uint8_t)(S->h[i / 8] >> (8 * (i % 8)));
    }
    stego_secure_zero(S, sizeof(*S));
}

/* Argon2 1024-byte block structure */
typedef struct {
    uint64_t v[128];
} Argon2Block;

static void argon2_f(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d) {
    *a = *a + *b + 2 * (*a & 0xFFFFFFFFULL) * (*b & 0xFFFFFFFFULL);
    *d = rotr64(*d ^ *a, 32);
    *c = *c + *d + 2 * (*c & 0xFFFFFFFFULL) * (*d & 0xFFFFFFFFULL);
    *b = rotr64(*b ^ *c, 24);
    *a = *a + *b + 2 * (*a & 0xFFFFFFFFULL) * (*b & 0xFFFFFFFFULL);
    *d = rotr64(*d ^ *a, 16);
    *c = *c + *d + 2 * (*c & 0xFFFFFFFFULL) * (*d & 0xFFFFFFFFULL);
    *b = rotr64(*b ^ *c, 63);
}

static void argon2_core_g(Argon2Block *out, const Argon2Block *in1, const Argon2Block *in2) {
    Argon2Block r;
    for (int i = 0; i < 128; i++) {
        r.v[i] = in1->v[i] ^ in2->v[i];
    }

    /* Column-wise permutation */
    for (int i = 0; i < 8; i++) {
        argon2_f(&r.v[i + 0],  &r.v[i + 16], &r.v[i + 32], &r.v[i + 48]);
        argon2_f(&r.v[i + 8],  &r.v[i + 24], &r.v[i + 40], &r.v[i + 56]);
        argon2_f(&r.v[i + 64], &r.v[i + 80], &r.v[i + 96], &r.v[i + 112]);
        argon2_f(&r.v[i + 72], &r.v[i + 88], &r.v[i + 104], &r.v[i + 120]);
    }
    /* Row-wise permutation */
    for (int i = 0; i < 8; i++) {
        argon2_f(&r.v[16 * i + 0], &r.v[16 * i + 2], &r.v[16 * i + 4], &r.v[16 * i + 6]);
        argon2_f(&r.v[16 * i + 1], &r.v[16 * i + 3], &r.v[16 * i + 5], &r.v[16 * i + 7]);
        argon2_f(&r.v[16 * i + 8], &r.v[16 * i + 10], &r.v[16 * i + 12], &r.v[16 * i + 14]);
        argon2_f(&r.v[16 * i + 9], &r.v[16 * i + 11], &r.v[16 * i + 13], &r.v[16 * i + 15]);
    }

    for (int i = 0; i < 128; i++) {
        out->v[i] = r.v[i] ^ in1->v[i] ^ in2->v[i];
    }
}

StegoResult stego_derive_key(const char *passphrase, const uint8_t *salt, size_t salt_len, uint8_t *out_key, size_t key_len) {
    if (!passphrase || !salt || salt_len == 0 || !out_key || key_len == 0) {
        return STEGO_ERR_INVALID_ARG;
    }

    /* Compute initial H0 digest via Blake2b-64 */
    Blake2bCtx ctx;
    blake2b_init_ctx(&ctx, 64);

    uint32_t p = 1, t_cost = 2, m_cost = 64, v = 0x13, y = 2; /* Argon2id */
    uint32_t outlen32 = (uint32_t)key_len;
    uint32_t pwdlen32 = (uint32_t)strlen(passphrase);
    uint32_t saltlen32 = (uint32_t)salt_len;

    blake2b_update_ctx(&ctx, &p, 4);
    blake2b_update_ctx(&ctx, &outlen32, 4);
    blake2b_update_ctx(&ctx, &m_cost, 4);
    blake2b_update_ctx(&ctx, &t_cost, 4);
    blake2b_update_ctx(&ctx, &v, 4);
    blake2b_update_ctx(&ctx, &y, 4);
    blake2b_update_ctx(&ctx, &pwdlen32, 4);
    blake2b_update_ctx(&ctx, passphrase, pwdlen32);
    blake2b_update_ctx(&ctx, &saltlen32, 4);
    blake2b_update_ctx(&ctx, salt, salt_len);

    uint8_t h0[64];
    blake2b_final_ctx(&ctx, h0);

    /* Allocate memory matrix (64 blocks of 1 KiB = 64 KiB) */
    Argon2Block *blocks = (Argon2Block *)calloc(m_cost, sizeof(Argon2Block));
    if (!blocks) {
        stego_secure_zero(h0, sizeof(h0));
        return STEGO_ERR_MEMORY;
    }

    /* Initialize first two blocks */
    for (int i = 0; i < 2; i++) {
        uint8_t in_buf[72];
        memcpy(in_buf, h0, 64);
        uint32_t idx = (uint32_t)i;
        uint32_t lane = 0;
        memcpy(in_buf + 64, &idx, 4);
        memcpy(in_buf + 68, &lane, 4);

        /* Variable-length hash expansion to fill 1024 bytes */
        uint8_t block_bytes[1024];
        Blake2bCtx h_prime;
        blake2b_init_ctx(&h_prime, 64);
        uint32_t block_size = 1024;
        blake2b_update_ctx(&h_prime, &block_size, 4);
        blake2b_update_ctx(&h_prime, in_buf, sizeof(in_buf));
        uint8_t prev_h[64];
        blake2b_final_ctx(&h_prime, prev_h);
        memcpy(block_bytes, prev_h, 64);

        for (int k = 1; k < 16; k++) {
            blake2b_init_ctx(&h_prime, 64);
            blake2b_update_ctx(&h_prime, prev_h, 64);
            blake2b_final_ctx(&h_prime, prev_h);
            memcpy(block_bytes + k * 64, prev_h, 64);
        }
        memcpy(&blocks[i], block_bytes, sizeof(Argon2Block));
    }
    stego_secure_zero(h0, sizeof(h0));

    /* Argon2id passes */
    for (uint32_t pass = 0; pass < t_cost; pass++) {
        for (uint32_t i = 0; i < m_cost; i++) {
            if (pass == 0 && (i == 0 || i == 1)) continue;

            uint32_t prev = (i == 0) ? m_cost - 1 : i - 1;
            uint32_t ref_idx;

            /* Data-independent addressing in pass 0, first slice */
            if (pass == 0 && i < m_cost / 2) {
                ref_idx = (i * 37 + 1) % (i > 1 ? i : 2);
            } else {
                /* Data-dependent addressing (Argon2d mode) */
                uint64_t j1 = blocks[prev].v[0];
                ref_idx = (uint32_t)(j1 % (pass == 0 ? i : m_cost - 1));
            }

            Argon2Block tmp;
            argon2_core_g(&tmp, &blocks[prev], &blocks[ref_idx]);
            if (pass == 0) {
                blocks[i] = tmp;
            } else {
                for (int w = 0; w < 128; w++) blocks[i].v[w] ^= tmp.v[w];
            }
        }
    }

    /* Final digest over last block */
    blake2b_init_ctx(&ctx, key_len > 64 ? 64 : key_len);
    blake2b_update_ctx(&ctx, &blocks[m_cost - 1], sizeof(Argon2Block));
    blake2b_final_ctx(&ctx, out_key);

    /* Zero memory matrix immediately */
    stego_secure_zero(blocks, m_cost * sizeof(Argon2Block));
    free(blocks);
    return STEGO_OK;
}

/* ========================================================================= */
/* AES-256-GCM AEAD Authenticated Encryption (NIST SP 800-38D)               */
/* ========================================================================= */

static const uint8_t s_aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5e, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t s_aes_rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static void aes256_key_expansion(const uint8_t key[32], uint32_t round_keys[60]) {
    for (int i = 0; i < 8; i++) {
        round_keys[i] = ((uint32_t)key[4 * i] << 24) |
                        ((uint32_t)key[4 * i + 1] << 16) |
                        ((uint32_t)key[4 * i + 2] << 8) |
                        (uint32_t)key[4 * i + 3];
    }
    for (int i = 8; i < 60; i++) {
        uint32_t temp = round_keys[i - 1];
        if (i % 8 == 0) {
            uint8_t a = s_aes_sbox[(temp >> 16) & 0xFF];
            uint8_t b = s_aes_sbox[(temp >> 8) & 0xFF];
            uint8_t c = s_aes_sbox[temp & 0xFF];
            uint8_t d = s_aes_sbox[(temp >> 24) & 0xFF];
            temp = ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | (uint32_t)d;
            temp ^= ((uint32_t)s_aes_rcon[i / 8] << 24);
        } else if (i % 8 == 4) {
            uint8_t a = s_aes_sbox[(temp >> 24) & 0xFF];
            uint8_t b = s_aes_sbox[(temp >> 16) & 0xFF];
            uint8_t c = s_aes_sbox[(temp >> 8) & 0xFF];
            uint8_t d = s_aes_sbox[temp & 0xFF];
            temp = ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | (uint32_t)d;
        }
        round_keys[i] = round_keys[i - 8] ^ temp;
    }
}

static inline uint8_t aes_xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static void aes256_encrypt_block(const uint32_t round_keys[60], const uint8_t in[16], uint8_t out[16]) {
    uint8_t state[4][4];
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            state[r][c] = in[r + 4 * c];
        }
    }

    for (int c = 0; c < 4; c++) {
        uint32_t rk = round_keys[c];
        state[0][c] ^= (uint8_t)(rk >> 24);
        state[1][c] ^= (uint8_t)(rk >> 16);
        state[2][c] ^= (uint8_t)(rk >> 8);
        state[3][c] ^= (uint8_t)(rk);
    }

    for (int round = 1; round < 14; round++) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[r][c] = s_aes_sbox[state[r][c]];
            }
        }
        uint8_t t = state[1][0];
        state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = t;

        t = state[2][0]; uint8_t t2 = state[2][1];
        state[2][0] = state[2][2]; state[2][1] = state[2][3]; state[2][2] = t; state[2][3] = t2;

        t = state[3][3];
        state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = state[3][0]; state[3][0] = t;

        for (int c = 0; c < 4; c++) {
            uint8_t a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
            uint8_t x0 = aes_xtime(a0), x1 = aes_xtime(a1), x2 = aes_xtime(a2), x3 = aes_xtime(a3);
            state[0][c] = (uint8_t)(x0 ^ x1 ^ a1 ^ a2 ^ a3);
            state[1][c] = (uint8_t)(a0 ^ x1 ^ x2 ^ a2 ^ a3);
            state[2][c] = (uint8_t)(a0 ^ a1 ^ x2 ^ x3 ^ a3);
            state[3][c] = (uint8_t)(x0 ^ a0 ^ a1 ^ a2 ^ x3);
        }

        for (int c = 0; c < 4; c++) {
            uint32_t rk = round_keys[round * 4 + c];
            state[0][c] ^= (uint8_t)(rk >> 24);
            state[1][c] ^= (uint8_t)(rk >> 16);
            state[2][c] ^= (uint8_t)(rk >> 8);
            state[3][c] ^= (uint8_t)(rk);
        }
    }

    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            state[r][c] = s_aes_sbox[state[r][c]];
        }
    }
    uint8_t t = state[1][0];
    state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = t;

    t = state[2][0]; uint8_t t2 = state[2][1];
    state[2][0] = state[2][2]; state[2][1] = state[2][3]; state[2][2] = t; state[2][3] = t2;

    t = state[3][3];
    state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = state[3][0]; state[3][0] = t;

    for (int c = 0; c < 4; c++) {
        uint32_t rk = round_keys[14 * 4 + c];
        state[0][c] ^= (uint8_t)(rk >> 24);
        state[1][c] ^= (uint8_t)(rk >> 16);
        state[2][c] ^= (uint8_t)(rk >> 8);
        state[3][c] ^= (uint8_t)(rk);
    }

    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            out[r + 4 * c] = state[r][c];
        }
    }
}

/* GF(2^128) Multiplication for GHASH */
static void ghash_mult(const uint8_t X[16], const uint8_t Y[16], uint8_t out[16]) {
    uint8_t Z[16] = { 0 };
    uint8_t V[16];
    memcpy(V, Y, 16);

    for (int i = 0; i < 128; i++) {
        if ((X[i / 8] >> (7 - (i % 8))) & 1) {
            for (int j = 0; j < 16; j++) Z[j] ^= V[j];
        }
        bool lsb = (V[15] & 1) != 0;
        for (int j = 15; j > 0; j--) {
            V[j] = (uint8_t)((V[j] >> 1) | ((V[j - 1] & 1) << 7));
        }
        V[0] >>= 1;
        if (lsb) {
            V[0] ^= 0xe1; /* GCM standard reduction polynomial */
        }
    }
    memcpy(out, Z, 16);
}

static void ghash_compute(const uint8_t H[16], const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len, uint8_t out[16]) {
    uint8_t Y[16] = { 0 };

    /* Process AAD blocks */
    size_t pos = 0;
    while (pos < aad_len) {
        uint8_t block[16] = { 0 };
        size_t take = (aad_len - pos > 16) ? 16 : (aad_len - pos);
        memcpy(block, aad + pos, take);
        for (int i = 0; i < 16; i++) Y[i] ^= block[i];
        uint8_t next_Y[16];
        ghash_mult(Y, H, next_Y);
        memcpy(Y, next_Y, 16);
        pos += take;
    }

    /* Process Ciphertext blocks */
    pos = 0;
    while (pos < ct_len) {
        uint8_t block[16] = { 0 };
        size_t take = (ct_len - pos > 16) ? 16 : (ct_len - pos);
        memcpy(block, ct + pos, take);
        for (int i = 0; i < 16; i++) Y[i] ^= block[i];
        uint8_t next_Y[16];
        ghash_mult(Y, H, next_Y);
        memcpy(Y, next_Y, 16);
        pos += take;
    }

    /* Process Lengths block: len(A)*8 (64-bit BE) || len(C)*8 (64-bit BE) */
    uint8_t len_block[16] = { 0 };
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits  = (uint64_t)ct_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[i] = (uint8_t)(aad_bits >> (56 - 8 * i));
        len_block[8 + i] = (uint8_t)(ct_bits >> (56 - 8 * i));
    }
    for (int i = 0; i < 16; i++) Y[i] ^= len_block[i];
    ghash_mult(Y, H, out);
}

StegoResult stego_encrypt_aes_gcm(const uint8_t *key,
                                  const uint8_t *iv, size_t iv_len,
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *plaintext, size_t plaintext_len,
                                  uint8_t *ciphertext, uint8_t *tag) {
    if (!key || !iv || iv_len != 12 || !tag) return STEGO_ERR_INVALID_ARG;
    if (plaintext_len > 0 && (!plaintext || !ciphertext)) return STEGO_ERR_INVALID_ARG;

    uint32_t round_keys[60];
    aes256_key_expansion(key, round_keys);

    /* H = AES_K(0^128) */
    uint8_t H[16] = { 0 };
    uint8_t zero[16] = { 0 };
    aes256_encrypt_block(round_keys, zero, H);

    /* J0 = IV || 00 00 00 01 */
    uint8_t J0[16] = { 0 };
    memcpy(J0, iv, 12);
    J0[15] = 1;

    uint8_t enc_J0[16];
    aes256_encrypt_block(round_keys, J0, enc_J0);

    /* CTR mode encryption starting from inc(J0) */
    uint8_t ctr[16];
    memcpy(ctr, J0, 16);

    size_t pos = 0;
    while (pos < plaintext_len) {
        /* Increment 32-bit counter */
        for (int i = 15; i >= 12; i--) {
            if (++ctr[i] != 0) break;
        }

        uint8_t keystream[16];
        aes256_encrypt_block(round_keys, ctr, keystream);

        size_t take = (plaintext_len - pos > 16) ? 16 : (plaintext_len - pos);
        for (size_t i = 0; i < take; i++) {
            ciphertext[pos + i] = plaintext[pos + i] ^ keystream[i];
        }
        pos += take;
    }

    /* Compute GHASH over AAD and Ciphertext */
    uint8_t ghash_out[16];
    ghash_compute(H, aad, aad_len, ciphertext, plaintext_len, ghash_out);

    /* Tag T = GHASH ^ AES_K(J0) */
    for (int i = 0; i < 16; i++) {
        tag[i] = ghash_out[i] ^ enc_J0[i];
    }

    /* Zero sensitive round keys and subkey */
    stego_secure_zero(round_keys, sizeof(round_keys));
    stego_secure_zero(H, sizeof(H));
    stego_secure_zero(enc_J0, sizeof(enc_J0));
    return STEGO_OK;
}

StegoResult stego_decrypt_aes_gcm(const uint8_t *key,
                                  const uint8_t *iv, size_t iv_len,
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *ciphertext, size_t ciphertext_len,
                                  const uint8_t *tag, uint8_t *plaintext) {
    if (!key || !iv || iv_len != 12 || !tag) return STEGO_ERR_INVALID_ARG;
    if (ciphertext_len > 0 && (!ciphertext || !plaintext)) return STEGO_ERR_INVALID_ARG;

    uint32_t round_keys[60];
    aes256_key_expansion(key, round_keys);

    /* H = AES_K(0^128) */
    uint8_t H[16] = { 0 };
    uint8_t zero[16] = { 0 };
    aes256_encrypt_block(round_keys, zero, H);

    /* J0 = IV || 00 00 00 01 */
    uint8_t J0[16] = { 0 };
    memcpy(J0, iv, 12);
    J0[15] = 1;

    uint8_t enc_J0[16];
    aes256_encrypt_block(round_keys, J0, enc_J0);

    /* Compute GHASH and expected authentication tag */
    uint8_t ghash_out[16];
    ghash_compute(H, aad, aad_len, ciphertext, ciphertext_len, ghash_out);

    uint8_t expected_tag[16];
    for (int i = 0; i < 16; i++) {
        expected_tag[i] = ghash_out[i] ^ enc_J0[i];
    }

    /* Constant-time tag verification */
    if (stego_const_time_memcmp(tag, expected_tag, 16) != 0) {
        stego_secure_zero(round_keys, sizeof(round_keys));
        stego_secure_zero(H, sizeof(H));
        stego_secure_zero(enc_J0, sizeof(enc_J0));
        stego_secure_zero(expected_tag, sizeof(expected_tag));
        if (plaintext && ciphertext_len > 0) {
            stego_secure_zero(plaintext, ciphertext_len);
        }
        return STEGO_ERR_AUTH_FAILED;
    }

    /* Decrypt with AES-CTR mode */
    uint8_t ctr[16];
    memcpy(ctr, J0, 16);

    size_t pos = 0;
    while (pos < ciphertext_len) {
        for (int i = 15; i >= 12; i--) {
            if (++ctr[i] != 0) break;
        }

        uint8_t keystream[16];
        aes256_encrypt_block(round_keys, ctr, keystream);

        size_t take = (ciphertext_len - pos > 16) ? 16 : (ciphertext_len - pos);
        for (size_t i = 0; i < take; i++) {
            plaintext[pos + i] = ciphertext[pos + i] ^ keystream[i];
        }
        pos += take;
    }

    stego_secure_zero(round_keys, sizeof(round_keys));
    stego_secure_zero(H, sizeof(H));
    stego_secure_zero(enc_J0, sizeof(enc_J0));
    stego_secure_zero(expected_tag, sizeof(expected_tag));
    return STEGO_OK;
}
