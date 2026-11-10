/**
 * @file split.c
 * @brief Multi-image payload splitting, authenticated chunking, and recombination.
 */

#include "stego/split.h"
#include "stego/carrier.h"
#include "stego/png_carrier.h"
#include "stego/crypto.h"
#include "stego/random.h"
#include "stego/compress.h"
#include "stego/capacity.h"
#include "stego/image_writer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================= */
/* Self-Contained SHA-256 Implementation (FIPS 180-4)                        */
/* ========================================================================= */

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} Sha256Ctx;

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define EP1(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SIG0(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(Sha256Ctx *ctx, const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
    for (int i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
               ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (int i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + K256[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(Sha256Ctx *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static void sha256_update(Sha256Ctx *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->buffer[ctx->count % 64] = data[i];
        ctx->count++;
        if (ctx->count % 64 == 0) {
            sha256_transform(ctx, ctx->buffer);
        }
    }
}

static void sha256_final(Sha256Ctx *ctx, uint8_t out[32]) {
    uint64_t total_bits = ctx->count * 8;
    ctx->buffer[ctx->count % 64] = 0x80;
    ctx->count++;

    if (ctx->count % 64 > 56) {
        while (ctx->count % 64 != 0) {
            ctx->buffer[ctx->count % 64] = 0x00;
            ctx->count++;
        }
        sha256_transform(ctx, ctx->buffer);
    }
    while (ctx->count % 64 != 56) {
        ctx->buffer[ctx->count % 64] = 0x00;
        ctx->count++;
    }
    for (int i = 7; i >= 0; --i) {
        ctx->buffer[56 + (7 - i)] = (uint8_t)((total_bits >> (i * 8)) & 0xFF);
    }
    sha256_transform(ctx, ctx->buffer);

    for (int i = 0; i < 8; ++i) {
        out[i * 4]     = (uint8_t)((ctx->state[i] >> 24) & 0xFF);
        out[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xFF);
        out[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8)  & 0xFF);
        out[i * 4 + 3] = (uint8_t)(ctx->state[i]         & 0xFF);
    }
}

void stego_sha256(const uint8_t *data, size_t len, uint8_t out_hash[32]) {
    Sha256Ctx ctx;
    sha256_init(&ctx);
    if (data && len > 0) {
        sha256_update(&ctx, data, len);
    }
    sha256_final(&ctx, out_hash);
}

void stego_sha256_hex(const uint8_t *data, size_t len, char out_hex[65]) {
    uint8_t hash[32];
    stego_sha256(data, len, hash);
    for (int i = 0; i < 32; i++) {
        snprintf(out_hex + (i * 2), 3, "%02x", hash[i]);
    }
    out_hex[64] = '\0';
}

/* ========================================================================= */
/* Manifest JSON serialization                                               */
/* ========================================================================= */

StegoResult stego_save_manifest_json(const char *json_path, const StegoManifest *manifest) {
    if (!json_path || !manifest) return STEGO_ERR_INVALID_ARG;
    FILE *fp = fopen(json_path, "w");
    if (!fp) return STEGO_ERR_FILE_WRITE;

    fprintf(fp, "{\n");
    fprintf(fp, "  \"original_filename\": \"%s\",\n", manifest->original_filename);
    fprintf(fp, "  \"original_size\": %zu,\n", manifest->original_size);
    fprintf(fp, "  \"sha256\": \"%s\",\n", manifest->sha256_hex);
    fprintf(fp, "  \"total_parts\": %u,\n", manifest->total_parts);
    fprintf(fp, "  \"is_encrypted\": %s,\n", manifest->is_encrypted ? "true" : "false");
    fprintf(fp, "  \"is_compressed\": %s,\n", manifest->is_compressed ? "true" : "false");
    fprintf(fp, "  \"parts\": [\n");
    for (uint16_t i = 0; i < manifest->total_parts; i++) {
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"part_number\": %u,\n", manifest->parts[i].part_num);
        fprintf(fp, "      \"filename\": \"%s\",\n", manifest->parts[i].part_path);
        fprintf(fp, "      \"chunk_size\": %zu\n", manifest->parts[i].chunk_size);
        fprintf(fp, "    }%s\n", (i + 1 < manifest->total_parts) ? "," : "");
    }
    fprintf(fp, "  ],\n");
    fprintf(fp, "  \"warning\": \"All parts in correct order are required for extraction. Losing any part makes recovery impossible.\"\n");
    fprintf(fp, "}\n");
    fclose(fp);
    return STEGO_OK;
}

/* ========================================================================= */
/* Multi-Part Split Embedding                                                */
/* ========================================================================= */

StegoResult stego_split_embed(const char *secret_path,
                             const char **cover_paths,
                             uint16_t num_covers,
                             const char *output_prefix,
                             const char *passphrase,
                             bool compress,
                             int bits_per_channel,
                             StegoManifest *out_manifest,
                             char *out_error_msg,
                             size_t error_msg_len) {
    if (!secret_path || !cover_paths || num_covers == 0 || !output_prefix) {
        if (out_error_msg) snprintf(out_error_msg, error_msg_len, "Invalid arguments provided.");
        return STEGO_ERR_INVALID_ARG;
    }

    if (num_covers > STEGO_MAX_SPLIT_PARTS) {
        if (out_error_msg) snprintf(out_error_msg, error_msg_len, "Maximum supported split parts is %d.", STEGO_MAX_SPLIT_PARTS);
        return STEGO_ERR_INVALID_ARG;
    }

    /* 1. Read secret file */
    FILE *sfp = fopen(secret_path, "rb");
    if (!sfp) {
        if (out_error_msg) snprintf(out_error_msg, error_msg_len, "Secret file not found: %s", secret_path);
        return STEGO_ERR_FILE_NOT_FOUND;
    }
    fseek(sfp, 0, SEEK_END);
    long orig_fsize = ftell(sfp);
    fseek(sfp, 0, SEEK_SET);
    if (orig_fsize < 0) {
        fclose(sfp);
        return STEGO_ERR_FILE_READ;
    }

    size_t orig_len = (size_t)orig_fsize;
    uint8_t *raw_secret = (uint8_t *)malloc(orig_len > 0 ? orig_len : 1);
    if (!raw_secret) {
        fclose(sfp);
        return STEGO_ERR_MEMORY;
    }
    if (orig_len > 0 && fread(raw_secret, 1, orig_len, sfp) != orig_len) {
        fclose(sfp);
        stego_secure_zero(raw_secret, orig_len);
        free(raw_secret);
        return STEGO_ERR_FILE_READ;
    }
    fclose(sfp);

    /* 2. Compute original SHA-256 */
    uint8_t orig_sha[32];
    char orig_sha_hex[65];
    stego_sha256(raw_secret, orig_len, orig_sha);
    stego_sha256_hex(raw_secret, orig_len, orig_sha_hex);

    /* 3. Extract basename */
    const char *base_filename = strrchr(secret_path, '/');
    if (!base_filename) base_filename = strrchr(secret_path, '\\');
    base_filename = base_filename ? base_filename + 1 : secret_path;

    /* 4. Pre-encryption compression if requested */
    uint8_t *payload_to_split = raw_secret;
    size_t payload_len = orig_len;
    bool was_compressed = false;

    if (compress) {
        uint8_t *comp_buf = NULL;
        size_t comp_len = 0;
        stego_compress_payload_if_beneficial(raw_secret, orig_len, &comp_buf, &comp_len, &was_compressed);
        if (was_compressed) {
            stego_secure_zero(raw_secret, orig_len);
            free(raw_secret);
            payload_to_split = comp_buf;
            payload_len = comp_len;
        }
    }

    /* 5. Assess capacities of all cover images */
    bool is_enc = (passphrase && passphrase[0] != '\0');
    size_t overhead_per_part = is_enc ? STEGO_CMC4_HEADER_SIZE : STEGO_CMC3_HEADER_SIZE;

    StegoCarrier *carriers[STEGO_MAX_SPLIT_PARTS] = {0};
    size_t part_caps[STEGO_MAX_SPLIT_PARTS] = {0};
    size_t total_available_payload_space = 0;

    for (uint16_t i = 0; i < num_covers; i++) {
        StegoCarrier *c = NULL;
        StegoResult res = stego_carrier_open(cover_paths[i], false, &c);
        if (res != STEGO_OK) {
            for (uint16_t j = 0; j < i; j++) stego_carrier_close(carriers[j]);
            stego_secure_zero(payload_to_split, payload_len);
            free(payload_to_split);
            if (out_error_msg) snprintf(out_error_msg, error_msg_len, "Failed to open cover image '%s'", cover_paths[i]);
            return res;
        }
        carriers[i] = c;
        size_t raw_cap = png_raw_capacity_bits(c->image, false, bits_per_channel);
        if (raw_cap > overhead_per_part) {
            part_caps[i] = raw_cap - overhead_per_part;
        } else {
            part_caps[i] = 0;
        }
        total_available_payload_space += part_caps[i];
    }

    /* 6. Verify total capacity fits payload */
    if (payload_len > total_available_payload_space) {
        for (uint16_t i = 0; i < num_covers; i++) stego_carrier_close(carriers[i]);
        char sz_req[32], sz_avail[32], sz_add[32];
        stego_format_bytes(payload_len, sz_req, sizeof(sz_req));
        stego_format_bytes(total_available_payload_space, sz_avail, sizeof(sz_avail));
        stego_format_bytes(payload_len - total_available_payload_space, sz_add, sizeof(sz_add));

        if (out_error_msg) {
            snprintf(out_error_msg, error_msg_len,
                     "This image does not have enough space for the selected secret.\n"
                     "[-] Multi-image shortfall: %u covers provide %s, but secret requires %s (%s additional needed).",
                     num_covers, sz_avail, sz_req, sz_add);
        }
        stego_secure_zero(payload_to_split, payload_len);
        free(payload_to_split);
        return STEGO_ERR_CAPACITY_EXCEEDED;
    }

    /* 7. Determine chunk boundaries: distribute evenly across all covers */
    size_t chunk_sizes[STEGO_MAX_SPLIT_PARTS] = {0};
    size_t bytes_remaining = payload_len;

    for (uint16_t i = 0; i < num_covers; i++) {
        uint16_t remaining_covers = num_covers - i;
        size_t desired = (bytes_remaining + remaining_covers - 1) / remaining_covers;
        size_t take = (desired <= part_caps[i]) ? desired : part_caps[i];
        if (take > bytes_remaining) take = bytes_remaining;
        chunk_sizes[i] = take;
        bytes_remaining -= take;
    }
    for (uint16_t i = 0; i < num_covers && bytes_remaining > 0; i++) {
        size_t room = part_caps[i] - chunk_sizes[i];
        if (room > 0) {
            size_t take = (bytes_remaining <= room) ? bytes_remaining : room;
            chunk_sizes[i] += take;
            bytes_remaining -= take;
        }
    }

    uint16_t total_parts = num_covers;

    /* 8. Initialize Manifest */
    if (out_manifest) {
        memset(out_manifest, 0, sizeof(StegoManifest));
        snprintf(out_manifest->original_filename, sizeof(out_manifest->original_filename), "%s", base_filename);
        out_manifest->original_size = orig_len;
        memcpy(out_manifest->sha256, orig_sha, 32);
        snprintf(out_manifest->sha256_hex, sizeof(out_manifest->sha256_hex), "%s", orig_sha_hex);
        out_manifest->total_parts = total_parts;
        out_manifest->is_encrypted = is_enc;
        out_manifest->is_compressed = was_compressed;
    }

    /* 9. Embed each chunk */
    size_t current_offset = 0;
    StegoResult final_res = STEGO_OK;

    for (uint16_t i = 0; i < total_parts; i++) {
        uint16_t part_num = i + 1;
        size_t c_size = chunk_sizes[i];
        const uint8_t *chunk_data = payload_to_split + current_offset;
        current_offset += c_size;

        char out_filename[512];
        snprintf(out_filename, sizeof(out_filename), "%s_part%u_of_%u.png", output_prefix, part_num, total_parts);

        if (out_manifest) {
            out_manifest->parts[i].part_num = part_num;
            snprintf(out_manifest->parts[i].part_path, sizeof(out_manifest->parts[i].part_path), "%s", out_filename);
            out_manifest->parts[i].chunk_size = c_size;
        }

        /* Build multi-part envelope stream */
        size_t total_stream_len = overhead_per_part + c_size;
        uint8_t *stream = (uint8_t *)malloc(total_stream_len);
        if (!stream) {
            final_res = STEGO_ERR_MEMORY;
            break;
        }

        uint16_t flags = 0;
        if (was_compressed) flags |= 0x01;
        flags |= 0x02; /* is_file */

        if (!is_enc) {
            /* CMC3 Unencrypted Multi-Part Header */
            stream[0] = STEGO_MAGIC_CMC3_BYTE0;
            stream[1] = STEGO_MAGIC_CMC3_BYTE1;
            stream[2] = STEGO_MAGIC_CMC3_BYTE2;
            stream[3] = STEGO_MAGIC_CMC3_BYTE3;
            stream[4] = (uint8_t)((total_parts >> 8) & 0xFF);
            stream[5] = (uint8_t)(total_parts        & 0xFF);
            stream[6] = (uint8_t)((part_num >> 8)    & 0xFF);
            stream[7] = (uint8_t)(part_num           & 0xFF);
            stream[8] = (uint8_t)((c_size >> 24)     & 0xFF);
            stream[9] = (uint8_t)((c_size >> 16)     & 0xFF);
            stream[10] = (uint8_t)((c_size >> 8)     & 0xFF);
            stream[11] = (uint8_t)(c_size            & 0xFF);

            /* 8 bytes original size */
            uint64_t osz = (uint64_t)orig_len;
            for (int k = 0; k < 8; k++) {
                stream[12 + k] = (uint8_t)((osz >> (56 - k * 8)) & 0xFF);
            }
            /* 32 bytes SHA-256 */
            memcpy(stream + 20, orig_sha, 32);
            /* 2 bytes flags */
            stream[52] = (uint8_t)((flags >> 8) & 0xFF);
            stream[53] = (uint8_t)(flags        & 0xFF);
            memset(stream + 54, 0, 64);
            memcpy(stream + 54, base_filename, strlen(base_filename) < 63 ? strlen(base_filename) : 63);

            /* Append chunk plaintext */
            if (c_size > 0) {
                memcpy(stream + STEGO_CMC3_HEADER_SIZE, chunk_data, c_size);
            }

        } else {
            /* CMC4 Authenticated Encrypted Multi-Part Header */
            uint8_t salt[16], nonce[12], tag[16];
            stego_random_bytes(salt, sizeof(salt));
            stego_random_bytes(nonce, sizeof(nonce));

            /* Derive key with Argon2id */
            uint8_t key[32];
            stego_derive_key(passphrase, salt, sizeof(salt), key, sizeof(key));

            /* Build 146-byte AAD */
            uint8_t aad[146];
            aad[0] = STEGO_MAGIC_CMC4_BYTE0;
            aad[1] = STEGO_MAGIC_CMC4_BYTE1;
            aad[2] = STEGO_MAGIC_CMC4_BYTE2;
            aad[3] = STEGO_MAGIC_CMC4_BYTE3;
            aad[4] = (uint8_t)((total_parts >> 8) & 0xFF);
            aad[5] = (uint8_t)(total_parts        & 0xFF);
            aad[6] = (uint8_t)((part_num >> 8)    & 0xFF);
            aad[7] = (uint8_t)(part_num           & 0xFF);
            aad[8] = (uint8_t)((c_size >> 24)     & 0xFF);
            aad[9] = (uint8_t)((c_size >> 16)     & 0xFF);
            aad[10] = (uint8_t)((c_size >> 8)     & 0xFF);
            aad[11] = (uint8_t)(c_size            & 0xFF);

            uint64_t osz = (uint64_t)orig_len;
            for (int k = 0; k < 8; k++) {
                aad[12 + k] = (uint8_t)((osz >> (56 - k * 8)) & 0xFF);
            }
            memcpy(aad + 20, orig_sha, 32);
            aad[52] = (uint8_t)((flags >> 8) & 0xFF);
            aad[53] = (uint8_t)(flags        & 0xFF);
            memset(aad + 54, 0, 64);
            memcpy(aad + 54, base_filename, strlen(base_filename) < 63 ? strlen(base_filename) : 63);
            memcpy(aad + 118, salt, 16);
            memcpy(aad + 134, nonce, 12);

            /* Encrypt chunk */
            uint8_t *ciphertext = (uint8_t *)malloc(c_size > 0 ? c_size : 1);
            stego_encrypt_aes_gcm(key, nonce, sizeof(nonce), aad, sizeof(aad),
                                  chunk_data, c_size, ciphertext, tag);
            stego_secure_zero(key, sizeof(key));

            /* Pack CMC4 stream */
            memcpy(stream, aad, 146);
            memcpy(stream + 146, tag, 16); /* Header total = 162 */
            if (c_size > 0) {
                memcpy(stream + STEGO_CMC4_HEADER_SIZE, ciphertext, c_size);
            }
            stego_secure_zero(ciphertext, c_size);
            free(ciphertext);
            stego_secure_zero(salt, sizeof(salt));
            stego_secure_zero(nonce, sizeof(nonce));
            stego_secure_zero(aad, sizeof(aad));
            stego_secure_zero(tag, sizeof(tag));
        }

        /* Embed into cover carrier i */
        final_res = png_embed_raw_bits(carriers[i]->image, stream, total_stream_len, false, bits_per_channel);
        stego_secure_zero(stream, total_stream_len);
        free(stream);

        if (final_res != STEGO_OK) break;

        /* Save stego image */
        final_res = stego_image_save(out_filename, carriers[i]->image, STEGO_FORMAT_PNG);
        if (final_res != STEGO_OK) break;
    }

    /* Cleanup carriers */
    for (uint16_t i = 0; i < num_covers; i++) {
        stego_carrier_close(carriers[i]);
    }
    stego_secure_zero(payload_to_split, payload_len);
    free(payload_to_split);

    if (final_res == STEGO_OK && out_manifest) {
        char manifest_path[512];
        snprintf(manifest_path, sizeof(manifest_path), "%s_manifest.json", output_prefix);
        stego_save_manifest_json(manifest_path, out_manifest);
    }

    return final_res;
}

/* ========================================================================= */
/* Multi-Part Recombination and Extraction                                  */
/* ========================================================================= */

typedef struct {
    uint16_t total_parts;
    uint16_t part_num;
    uint32_t chunk_len;
    uint64_t orig_size;
    uint8_t orig_sha[32];
    uint16_t flags;
    char filename[65];
    bool is_encrypted;
    uint8_t salt[16];
    uint8_t nonce[12];
    uint8_t tag[16];
    uint8_t *ciphertext_or_data;
    int bits_per_channel;
    bool is_adaptive;
} ParsedPart;

StegoResult stego_split_extract(const char **stego_paths,
                               uint16_t num_stego_images,
                               const char *output_path,
                               const char *passphrase,
                               char *out_error_msg,
                               size_t error_msg_len) {
    if (!stego_paths || num_stego_images == 0) {
        if (out_error_msg) snprintf(out_error_msg, error_msg_len, "No input images provided for recombination.");
        return STEGO_ERR_INVALID_ARG;
    }

    ParsedPart parsed[STEGO_MAX_SPLIT_PARTS];
    memset(parsed, 0, sizeof(parsed));

    uint16_t expected_total_parts = 0;
    uint8_t session_sha[32] = {0};
    bool is_first = true;

    /* 1. Parse and validate each stego image */
    for (uint16_t i = 0; i < num_stego_images; i++) {
        StegoCarrier *c = NULL;
        StegoResult res = stego_carrier_open(stego_paths[i], false, &c);
        if (res != STEGO_OK) {
            if (out_error_msg) snprintf(out_error_msg, error_msg_len, "Failed to open part image '%s'", stego_paths[i]);
            return res;
        }

        bool adapt = false;
        int bpc = 1;
        uint32_t plen = 0;
        StegoEnvelopeType env = png_detect_envelope_detailed(c->image, &adapt, &bpc, &plen);
        if (env != STEGO_ENVELOPE_CMC3 && env != STEGO_ENVELOPE_CMC4) {
            stego_carrier_close(c);
            if (out_error_msg) snprintf(out_error_msg, error_msg_len, "Image '%s' is not a valid multi-image secret part.", stego_paths[i]);
            return STEGO_ERR_INVALID_FORMAT;
        }

        size_t hdr_len = (env == STEGO_ENVELOPE_CMC4) ? STEGO_CMC4_HEADER_SIZE : STEGO_CMC3_HEADER_SIZE;
        uint8_t hdr[162];
        png_extract_raw_bits(c->image, hdr, hdr_len, adapt, bpc);

        ParsedPart *p = &parsed[i];
        p->is_encrypted = (env == STEGO_ENVELOPE_CMC4);
        p->total_parts = ((uint16_t)hdr[4] << 8) | (uint16_t)hdr[5];
        p->part_num = ((uint16_t)hdr[6] << 8) | (uint16_t)hdr[7];
        p->chunk_len = ((uint32_t)hdr[8] << 24) | ((uint32_t)hdr[9] << 16) |
                       ((uint32_t)hdr[10] << 8) | (uint32_t)hdr[11];

        uint64_t osz = 0;
        for (int k = 0; k < 8; k++) {
            osz = (osz << 8) | (uint64_t)hdr[12 + k];
        }
        p->orig_size = osz;
        memcpy(p->orig_sha, hdr + 20, 32);
        p->flags = ((uint16_t)hdr[52] << 8) | (uint16_t)hdr[53];
        memcpy(p->filename, hdr + 54, 64);
        p->filename[64] = '\0';
        p->bits_per_channel = bpc;
        p->is_adaptive = adapt;

        if (p->is_encrypted) {
            memcpy(p->salt, hdr + 118, 16);
            memcpy(p->nonce, hdr + 134, 12);
            memcpy(p->tag, hdr + 146, 16);
        }

        /* Read chunk payload */
        size_t total_part_stream = hdr_len + p->chunk_len;
        uint8_t *stream = (uint8_t *)malloc(total_part_stream);
        if (!stream) {
            stego_carrier_close(c);
            return STEGO_ERR_MEMORY;
        }
        png_extract_raw_bits(c->image, stream, total_part_stream, adapt, bpc);
        stego_carrier_close(c);

        p->ciphertext_or_data = (uint8_t *)malloc(p->chunk_len > 0 ? p->chunk_len : 1);
        if (p->chunk_len > 0) {
            memcpy(p->ciphertext_or_data, stream + hdr_len, p->chunk_len);
        }
        stego_secure_zero(stream, total_part_stream);
        free(stream);

        /* Session consistency checks */
        if (is_first) {
            expected_total_parts = p->total_parts;
            memcpy(session_sha, p->orig_sha, 32);
            is_first = false;
        } else {
            if (p->total_parts != expected_total_parts || memcmp(p->orig_sha, session_sha, 32) != 0) {
                if (out_error_msg) snprintf(out_error_msg, error_msg_len, "Image '%s' belongs to a different secret session.", stego_paths[i]);
                for (uint16_t j = 0; j <= i; j++) free(parsed[j].ciphertext_or_data);
                return STEGO_ERR_INVALID_FORMAT;
            }
        }
    }

    /* 2. Check for missing or duplicate parts */
    if (num_stego_images < expected_total_parts) {
        if (out_error_msg) {
            snprintf(out_error_msg, error_msg_len,
                     "Incomplete set. Received %u of %u required parts. Losing any part makes recovery impossible.",
                     num_stego_images, expected_total_parts);
        }
        for (uint16_t j = 0; j < num_stego_images; j++) free(parsed[j].ciphertext_or_data);
        return STEGO_ERR_CORRUPT_PAYLOAD;
    }

    ParsedPart *ordered[STEGO_MAX_SPLIT_PARTS] = {0};
    for (uint16_t i = 0; i < num_stego_images; i++) {
        uint16_t num = parsed[i].part_num;
        if (num == 0 || num > expected_total_parts) {
            if (out_error_msg) snprintf(out_error_msg, error_msg_len, "Invalid part number %u detected.", num);
            for (uint16_t j = 0; j < num_stego_images; j++) free(parsed[j].ciphertext_or_data);
            return STEGO_ERR_CORRUPT_PAYLOAD;
        }
        if (ordered[num - 1] != NULL) {
            if (out_error_msg) snprintf(out_error_msg, error_msg_len, "Duplicate part %u detected.", num);
            for (uint16_t j = 0; j < num_stego_images; j++) free(parsed[j].ciphertext_or_data);
            return STEGO_ERR_CORRUPT_PAYLOAD;
        }
        ordered[num - 1] = &parsed[i];
    }

    for (uint16_t k = 0; k < expected_total_parts; k++) {
        if (ordered[k] == NULL) {
            if (out_error_msg) snprintf(out_error_msg, error_msg_len, "Missing part %u of %u.", k + 1, expected_total_parts);
            for (uint16_t j = 0; j < num_stego_images; j++) free(parsed[j].ciphertext_or_data);
            return STEGO_ERR_CORRUPT_PAYLOAD;
        }
    }

    /* 3. Decrypt and reassemble in order */
    size_t total_assembled_len = 0;
    for (uint16_t k = 0; k < expected_total_parts; k++) {
        total_assembled_len += ordered[k]->chunk_len;
    }

    uint8_t *assembled_buf = (uint8_t *)malloc(total_assembled_len > 0 ? total_assembled_len : 1);
    if (!assembled_buf) {
        for (uint16_t j = 0; j < num_stego_images; j++) free(parsed[j].ciphertext_or_data);
        return STEGO_ERR_MEMORY;
    }

    size_t write_pos = 0;
    StegoResult dec_res = STEGO_OK;

    for (uint16_t k = 0; k < expected_total_parts; k++) {
        ParsedPart *p = ordered[k];

        if (p->is_encrypted) {
            if (!passphrase || passphrase[0] == '\0') {
                if (out_error_msg) snprintf(out_error_msg, error_msg_len, "This secret is password protected. Please enter the password.");
                dec_res = STEGO_ERR_AUTH_FAILED;
                break;
            }

            uint8_t key[32];
            stego_derive_key(passphrase, p->salt, 16, key, 32);

            /* Reconstruct 146-byte AAD */
            uint8_t aad[146];
            aad[0] = STEGO_MAGIC_CMC4_BYTE0;
            aad[1] = STEGO_MAGIC_CMC4_BYTE1;
            aad[2] = STEGO_MAGIC_CMC4_BYTE2;
            aad[3] = STEGO_MAGIC_CMC4_BYTE3;
            aad[4] = (uint8_t)((p->total_parts >> 8) & 0xFF);
            aad[5] = (uint8_t)(p->total_parts        & 0xFF);
            aad[6] = (uint8_t)((p->part_num >> 8)    & 0xFF);
            aad[7] = (uint8_t)(p->part_num           & 0xFF);
            aad[8] = (uint8_t)((p->chunk_len >> 24)  & 0xFF);
            aad[9] = (uint8_t)((p->chunk_len >> 16)  & 0xFF);
            aad[10] = (uint8_t)((p->chunk_len >> 8)  & 0xFF);
            aad[11] = (uint8_t)(p->chunk_len         & 0xFF);

            uint64_t osz = p->orig_size;
            for (int b = 0; b < 8; b++) {
                aad[12 + b] = (uint8_t)((osz >> (56 - b * 8)) & 0xFF);
            }
            memcpy(aad + 20, p->orig_sha, 32);
            aad[52] = (uint8_t)((p->flags >> 8) & 0xFF);
            aad[53] = (uint8_t)(p->flags        & 0xFF);
            memset(aad + 54, 0, 64);
            memcpy(aad + 54, p->filename, strlen(p->filename) < 63 ? strlen(p->filename) : 63);
            memcpy(aad + 118, p->salt, 16);
            memcpy(aad + 134, p->nonce, 12);

            uint8_t *dec_chunk = (uint8_t *)malloc(p->chunk_len > 0 ? p->chunk_len : 1);
            StegoResult ares = stego_decrypt_aes_gcm(key, p->nonce, 12, aad, 146,
                                                     p->ciphertext_or_data, p->chunk_len,
                                                     p->tag, dec_chunk);
            stego_secure_zero(key, 32);

            if (ares != STEGO_OK) {
                if (dec_chunk) free(dec_chunk);
                if (out_error_msg) {
                    snprintf(out_error_msg, error_msg_len,
                             "Authentication failed on part %u: Incorrect password, corruption, or tampering detected.",
                             p->part_num);
                }
                dec_res = STEGO_ERR_AUTH_FAILED;
                break;
            }

            if (p->chunk_len > 0) {
                memcpy(assembled_buf + write_pos, dec_chunk, p->chunk_len);
            }
            write_pos += p->chunk_len;
            stego_secure_zero(dec_chunk, p->chunk_len);
            free(dec_chunk);

        } else {
            /* Unencrypted chunk */
            if (p->chunk_len > 0) {
                memcpy(assembled_buf + write_pos, p->ciphertext_or_data, p->chunk_len);
            }
            write_pos += p->chunk_len;
        }
    }

    for (uint16_t j = 0; j < num_stego_images; j++) {
        free(parsed[j].ciphertext_or_data);
    }

    if (dec_res != STEGO_OK) {
        stego_secure_zero(assembled_buf, total_assembled_len);
        free(assembled_buf);
        return dec_res;
    }

    /* 4. Decompression check if compressed */
    uint8_t *final_secret = assembled_buf;
    size_t final_len = total_assembled_len;
    bool was_decomp = false;

    if (ordered[0]->flags & 0x01) {
        uint8_t *decomp_buf = NULL;
        size_t decomp_len = 0;
        StegoResult zres = stego_decompress_payload_if_packed(assembled_buf, total_assembled_len,
                                                              &decomp_buf, &decomp_len, &was_decomp);
        stego_secure_zero(assembled_buf, total_assembled_len);
        free(assembled_buf);
        if (zres != STEGO_OK) {
            if (out_error_msg) snprintf(out_error_msg, error_msg_len, "Failed to decompress recombined secret payload.");
            return zres;
        }
        final_secret = decomp_buf;
        final_len = decomp_len;
    }

    /* 5. Cryptographic SHA-256 Checksum Verification */
    uint8_t computed_sha[32];
    stego_sha256(final_secret, final_len, computed_sha);
    if (memcmp(computed_sha, session_sha, 32) != 0 || final_len != (size_t)ordered[0]->orig_size) {
        stego_secure_zero(final_secret, final_len);
        free(final_secret);
        if (out_error_msg) {
            snprintf(out_error_msg, error_msg_len, "Cryptographic integrity failure: Reassembled data does not match original SHA-256.");
        }
        return STEGO_ERR_CORRUPT_PAYLOAD;
    }

    /* 6. Output handling */
    if (output_path) {
        FILE *ofp = fopen(output_path, "wb");
        if (!ofp) {
            stego_secure_zero(final_secret, final_len);
            free(final_secret);
            if (out_error_msg) snprintf(out_error_msg, error_msg_len, "Cannot write to output file '%s'", output_path);
            return STEGO_ERR_FILE_WRITE;
        }
        if (final_len > 0) {
            fwrite(final_secret, 1, final_len, ofp);
        }
        fclose(ofp);
    } else {
        printf("\n[+] Success! %u/%u parts verified and recombined.\n", expected_total_parts, expected_total_parts);
        printf("[+] Original file: '%s' (%zu bytes)\n", ordered[0]->filename, final_len);
        printf("----------------------------------------------------\n");
        fwrite(final_secret, 1, final_len, stdout);
        printf("\n----------------------------------------------------\n");
    }

    stego_secure_zero(final_secret, final_len);
    free(final_secret);
    return STEGO_OK;
}
