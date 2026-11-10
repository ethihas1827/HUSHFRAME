/**
 * @file secure_delete.c
 * @brief Secure file shredding implementation.
 */

#include "stego/privacy.h"

StegoResult privacy_shred_file(const char *filepath) {
    return stego_secure_delete_file(filepath);
}

