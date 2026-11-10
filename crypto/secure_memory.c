/**
 * @file secure_memory.c
 * @brief Volatile memory scrubbing.
 */

#include "stego/crypto.h"

void crypto_wipe_memory(void *ptr, size_t len) {
    stego_secure_zero(ptr, len);
}

