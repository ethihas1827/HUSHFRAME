/**
 * @file stego.h
 * @brief Master header for privacy-focused multi-format steganography toolkit.
 */

#ifndef STEGO_MASTER_H
#define STEGO_MASTER_H

/* Umbrella header exports: all sub-module interfaces are intentionally re-exported */
#include "stego/error.h"         // IWYU pragma: export
#include "stego/buffer.h"        // IWYU pragma: export
#include "stego/bitstream.h"     // IWYU pragma: export
#include "stego/random.h"        // IWYU pragma: export
#include "stego/crypto.h"        // IWYU pragma: export
#include "stego/payload.h"       // IWYU pragma: export
#include "stego/fec.h"           // IWYU pragma: export
#include "stego/image_format.h"  // IWYU pragma: export
#include "stego/image_loader.h"  // IWYU pragma: export
#include "stego/image_writer.h"  // IWYU pragma: export
#include "stego/carrier.h"       // IWYU pragma: export
#include "stego/bmp_carrier.h"   // IWYU pragma: export
#include "stego/png_carrier.h"   // IWYU pragma: export
#include "stego/jpeg_carrier.h"  // IWYU pragma: export
#include "stego/heic_carrier.h"  // IWYU pragma: export
#include "stego/metadata.h"      // IWYU pragma: export
#include "stego/privacy.h"       // IWYU pragma: export
#include "stego/analysis.h"      // IWYU pragma: export
#include "stego/cli.h"           // IWYU pragma: export
#include "stego/compress.h"      // IWYU pragma: export
#include "stego/capacity.h"      // IWYU pragma: export
#include "stego/split.h"         // IWYU pragma: export
#include "stego/file_payload.h"  // IWYU pragma: export

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
