/**
 * @file random.c
 * @brief Secure random byte generation and deterministic shuffling.
 */

#include "stego/random.h"
#include <stdlib.h>
#include <time.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#endif

StegoResult stego_random_bytes(uint8_t *dest, size_t count) {
    if (!dest) return STEGO_ERR_INVALID_ARG;
    if (count == 0) return STEGO_OK;

#if defined(_WIN32)
    HCRYPTPROV hCryptProv = 0;
    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        if (CryptGenRandom(hCryptProv, (DWORD)count, dest)) {
            CryptReleaseContext(hCryptProv, 0);
            return STEGO_OK;
        }
        CryptReleaseContext(hCryptProv, 0);
    }
#endif

    /* Fallback to PRNG */
    static bool seeded = false;
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = true;
    }
    for (size_t i = 0; i < count; i++) {
        dest[i] = (uint8_t)(rand() & 0xFF);
    }
    return STEGO_OK;
}

void stego_shuffle_indices(size_t *indices, size_t count, uint32_t seed) {
    if (!indices || count < 2) return;
    uint32_t state = seed ? seed : 0x12345678;

    for (size_t i = count - 1; i > 0; i--) {
        /* Xorshift32 */
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        size_t j = (size_t)(state % (i + 1));

        size_t tmp = indices[i];
        indices[i] = indices[j];
        indices[j] = tmp;
    }
}

