/**
 * @file stego_core.h
 * @brief Unified interface connecting the web backend to the existing C steganography core.
 *
 * Exposes core steganography, carrier abstraction, envelope handling,
 * cryptographic primitives, and image loading/writing facilities.
 */

#ifndef STEGO_CORE_H
#define STEGO_CORE_H

#include "stego/stego.h"
#include "stego/carrier.h"
#include "stego/image_loader.h"
#include "stego/image_writer.h"
#include "stego/image_format.h"
#include "stego/crypto.h"
#include "stego/payload.h"
#include "stego/error.h"
#include "stego/metadata.h"
#include "stego/privacy.h"

#endif /* STEGO_CORE_H */

