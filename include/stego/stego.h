/**
 * @file stego.h
 * @brief Master header for privacy-focused multi-format steganography toolkit.
 */

#ifndef STEGO_MASTER_H
#define STEGO_MASTER_H

#include "stego/error.h"
#include "stego/buffer.h"
#include "stego/bitstream.h"
#include "stego/random.h"
#include "stego/crypto.h"
#include "stego/payload.h"
#include "stego/fec.h"
#include "stego/image_format.h"
#include "stego/image_loader.h"
#include "stego/image_writer.h"
#include "stego/carrier.h"
#include "stego/bmp_carrier.h"
#include "stego/png_carrier.h"
#include "stego/jpeg_carrier.h"
#include "stego/heic_carrier.h"
#include "stego/metadata.h"
#include "stego/privacy.h"
#include "stego/analysis.h"
#include "stego/cli.h"
#include "stego/compress.h"
#include "stego/capacity.h"
#include "stego/split.h"
#include "stego/file_payload.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STEGO_VERSION_MAJOR 1
#define STEGO_VERSION_MINOR 0
#define STEGO_VERSION_PATCH 0
#define STEGO_VERSION_STRING "1.0.0"

/**
 * High-level unified API for embedding into any supported lossless carrier (BMP, PNG).
 */
StegoResult stego_hide_file_unified(const char *cover_path, const char *stego_path, const char *secret_file_path, bool adaptive);
StegoResult stego_extract_file_unified(const char *stego_path, const char *output_path, bool adaptive);

/**
 * High-level unified API with Argon2id + AES-256-GCM authenticated encryption (CMC2).
 */
StegoResult stego_hide_file_unified_secure(const char *cover_path, const char *stego_path, const char *secret_file_path, const char *passphrase, bool adaptive);
StegoResult stego_extract_file_unified_secure(const char *stego_path, const char *output_path, const char *passphrase, bool adaptive);

/**
 * Advanced high-level unified API supporting pre-encryption compression and multi-bit LSB.
 */
StegoResult stego_hide_file_unified_advanced(const char *cover_path, const char *stego_path, const char *secret_file_path, const char *passphrase, bool adaptive, bool compress, int bits_per_channel);

StegoResult stego_hide_file_secure(const char *cover_path, const char *stego_path, const char *secret_file_path, const char *passphrase);
StegoResult stego_extract_file_secure(const char *stego_path, const char *output_path, const char *passphrase);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_MASTER_H */
