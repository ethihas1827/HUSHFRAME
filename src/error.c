/**
 * @file error.c
 * @brief Error code string mapping.
 */

#include "stego/error.h"

const char *stego_strerror(StegoResult result) {
    switch (result) {
        case STEGO_OK:
            return "Success";
        case STEGO_ERR_FILE_NOT_FOUND:
            return "File not found or cannot be opened";
        case STEGO_ERR_FILE_WRITE:
            return "Failed to write output file";
        case STEGO_ERR_FILE_READ:
            return "Failed to read input file";
        case STEGO_ERR_INVALID_BMP:
            return "Invalid or corrupted BMP file";
        case STEGO_ERR_INVALID_PNG:
            return "Invalid or corrupted PNG file";
        case STEGO_ERR_INVALID_FORMAT:
            return "Unrecognized image format (invalid magic bytes)";
        case STEGO_ERR_UNSUPPORTED_FORMAT:
            return "Unsupported image format";
        case STEGO_ERR_IMAGE_DECODE:
            return "Image could not be decoded";
        case STEGO_ERR_IMAGE_TOO_LARGE:
            return "Image is too large";
        case STEGO_ERR_IMAGE_INVALID_DATA:
            return "Image has invalid data";
        case STEGO_ERR_CAPACITY_EXCEEDED:
            return "Payload size exceeds available carrier capacity";
        case STEGO_ERR_NO_PAYLOAD:
            return "No steganographic payload detected (missing CMC1 magic signature)";
        case STEGO_ERR_CORRUPT_PAYLOAD:
            return "Corrupted payload or integrity check failed";
        case STEGO_ERR_AUTH_FAILED:
            return "Authentication failed (wrong passphrase or tampered payload)";
        case STEGO_ERR_MEMORY:
            return "Memory allocation failure";
        case STEGO_ERR_INVALID_ARG:
            return "Invalid argument passed to function";
        case STEGO_ERR_UNSAFE_CONVERSION:
            return "Unsafe format conversion: target format destroys steganographic payload";
        case STEGO_ERR_NOT_IMPLEMENTED:
            return "Feature scheduled for future release phase";
        default:
            return "Unknown error";
    }
}

