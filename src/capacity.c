/**
 * @file capacity.c
 * @brief Capacity estimation, shortfall analysis, and recommendation generation.
 */

#include "stego/capacity.h"
#include "stego/payload.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

void stego_format_bytes(size_t bytes, char *out, size_t out_len) {
    if (!out || out_len == 0) return;
    if (bytes < 1024) {
        snprintf(out, out_len, "%zu B", bytes);
    } else if (bytes < 1024 * 1024) {
        snprintf(out, out_len, "%.1f KB", (double)bytes / 1024.0);
    } else {
        snprintf(out, out_len, "%.2f MB", (double)bytes / (1024.0 * 1024.0));
    }
}

StegoResult stego_assess_capacity(const StegoCarrier *carrier,
                                  const char *secret_name,
                                  size_t secret_size,
                                  bool is_encrypted,
                                  bool is_compressed,
                                  int bits_per_channel,
                                  StegoCapacityAssessment *out) {
    if (!carrier || !carrier->image || !out) return STEGO_ERR_INVALID_ARG;
    memset(out, 0, sizeof(StegoCapacityAssessment));

    if (secret_name) {
        snprintf(out->secret_name, sizeof(out->secret_name), "%s", secret_name);
    } else {
        snprintf(out->secret_name, sizeof(out->secret_name), "secret_data.bin");
    }

    out->secret_size = secret_size;
    out->is_encrypted = is_encrypted;
    out->is_compressed = is_compressed;
    out->envelope_overhead = is_encrypted ? STEGO_CMC2_HEADER_SIZE : STEGO_CMC1_HEADER_SIZE;
    out->total_required = secret_size + out->envelope_overhead;

    if (bits_per_channel < 1) bits_per_channel = 1;
    if (bits_per_channel > 3) bits_per_channel = 3;
    out->bits_per_channel = bits_per_channel;

    out->cover_width = carrier->image->width;
    out->cover_height = carrier->image->height;

    /* Raw capacity calculation per bit depth */
    size_t total_pixels = (size_t)out->cover_width * out->cover_height;

    /* 1-bit LSB: 3 bits per pixel */
    size_t raw_1bit = (total_pixels * 3) / 8;
    out->capacity_1bit = (raw_1bit > out->envelope_overhead) ? (raw_1bit - out->envelope_overhead) : 0;

    /* 2-bit LSB: 6 bits per pixel */
    size_t raw_2bit = (total_pixels * 6) / 8;
    out->capacity_2bit = (raw_2bit > out->envelope_overhead) ? (raw_2bit - out->envelope_overhead) : 0;

    /* 3-bit LSB: 9 bits per pixel */
    size_t raw_3bit = (total_pixels * 9) / 8;
    out->capacity_3bit = (raw_3bit > out->envelope_overhead) ? (raw_3bit - out->envelope_overhead) : 0;

    if (bits_per_channel == 1) {
        out->available_capacity = out->capacity_1bit;
    } else if (bits_per_channel == 2) {
        out->available_capacity = out->capacity_2bit;
    } else {
        out->available_capacity = out->capacity_3bit;
    }

    out->fits = (secret_size <= out->available_capacity);
    if (!out->fits) {
        out->additional_required = secret_size - out->available_capacity;
    } else {
        out->additional_required = 0;
    }

    /* Calculate recommended minimum cover dimensions for 1-bit LSB */
    size_t total_bits_needed = out->total_required * 8;
    size_t pixels_needed = (total_bits_needed + 2) / 3;

    /* 4:3 aspect ratio recommendation: W = 4x, H = 3x -> 12x^2 = pixels */
    double x_dim = sqrt((double)pixels_needed / 12.0);
    out->rec_min_width = (uint32_t)ceil(x_dim * 4.0);
    out->rec_min_height = (uint32_t)ceil(x_dim * 3.0);
    /* Square recommendation */
    out->rec_square_dim = (uint32_t)ceil(sqrt((double)pixels_needed));

    snprintf(out->error_summary, sizeof(out->error_summary),
             "This image does not have enough space for the selected secret.");

    char sz_sec[32], sz_avail[32], sz_add[32];
    stego_format_bytes(out->secret_size, sz_sec, sizeof(sz_sec));
    stego_format_bytes(out->available_capacity, sz_avail, sizeof(sz_avail));
    stego_format_bytes(out->additional_required, sz_add, sizeof(sz_add));

    snprintf(out->formatted_details, sizeof(out->formatted_details),
             "[-] %s\n"
             "    Secret file         : %s\n"
             "    Secret file size    : %s\n"
             "    Available capacity  : %s (in current cover image %ux%u)\n"
             "    Additional space req: %s more needed\n"
             "    Recommended min size: %ux%u pixels (or %ux%u square)\n"
             "    Practical solutions:\n"
             "      1. Choose a larger cover image (at least %ux%u).\n"
             "      2. Compress the file before hiding (use --compress).\n"
             "      3. Split the secret across multiple images (use embed-split).\n"
             "      4. Enable 2-bit or 3-bit high-capacity LSB mode (--bits 2 or --bits 3).\n",
             out->error_summary,
             out->secret_name,
             sz_sec,
             sz_avail, out->cover_width, out->cover_height,
             sz_add,
             out->rec_min_width, out->rec_min_height, out->rec_square_dim, out->rec_square_dim,
             out->rec_min_width, out->rec_min_height);

    return STEGO_OK;
}
