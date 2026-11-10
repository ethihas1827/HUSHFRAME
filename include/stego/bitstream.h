/**
 * @file bitstream.h
 * @brief Bitstream reader and writer for steganographic bit packing/unpacking.
 */

#ifndef STEGO_BITSTREAM_H
#define STEGO_BITSTREAM_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const uint8_t *data;
    size_t byte_count;
    size_t bit_pos;
} StegoBitReader;

typedef struct {
    uint8_t *data;
    size_t byte_count;
    size_t bit_pos;
} StegoBitWriter;

void stego_bit_reader_init(StegoBitReader *reader, const uint8_t *data, size_t byte_count);
bool stego_bit_reader_has_bits(const StegoBitReader *reader, size_t count);
uint8_t stego_bit_reader_read_bit(StegoBitReader *reader);
uint32_t stego_bit_reader_read_bits(StegoBitReader *reader, size_t count);

void stego_bit_writer_init(StegoBitWriter *writer, uint8_t *data, size_t byte_count);
bool stego_bit_writer_write_bit(StegoBitWriter *writer, uint8_t bit);
bool stego_bit_writer_write_bits(StegoBitWriter *writer, uint32_t value, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_BITSTREAM_H */

