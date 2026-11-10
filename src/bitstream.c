/**
 * @file bitstream.c
 * @brief Bitstream reader and writer implementation.
 */

#include "stego/bitstream.h"

void stego_bit_reader_init(StegoBitReader *reader, const uint8_t *data, size_t byte_count) {
    if (!reader) return;
    reader->data = data;
    reader->byte_count = byte_count;
    reader->bit_pos = 0;
}

bool stego_bit_reader_has_bits(const StegoBitReader *reader, size_t count) {
    if (!reader) return false;
    return (reader->bit_pos + count) <= (reader->byte_count * 8);
}

uint8_t stego_bit_reader_read_bit(StegoBitReader *reader) {
    if (!reader || !reader->data) return 0;
    if (reader->bit_pos >= reader->byte_count * 8) return 0;

    size_t byte_idx = reader->bit_pos / 8;
    size_t bit_idx = 7 - (reader->bit_pos % 8);
    reader->bit_pos++;

    return (uint8_t)((reader->data[byte_idx] >> bit_idx) & 1);
}

uint32_t stego_bit_reader_read_bits(StegoBitReader *reader, size_t count) {
    uint32_t val = 0;
    for (size_t i = 0; i < count; i++) {
        val = (val << 1) | stego_bit_reader_read_bit(reader);
    }
    return val;
}

void stego_bit_writer_init(StegoBitWriter *writer, uint8_t *data, size_t byte_count) {
    if (!writer) return;
    writer->data = data;
    writer->byte_count = byte_count;
    writer->bit_pos = 0;
}

bool stego_bit_writer_write_bit(StegoBitWriter *writer, uint8_t bit) {
    if (!writer || !writer->data) return false;
    if (writer->bit_pos >= writer->byte_count * 8) return false;

    size_t byte_idx = writer->bit_pos / 8;
    size_t bit_idx = 7 - (writer->bit_pos % 8);
    writer->bit_pos++;

    if (bit) {
        writer->data[byte_idx] |= (uint8_t)(1 << bit_idx);
    } else {
        writer->data[byte_idx] &= (uint8_t)(~(1 << bit_idx));
    }
    return true;
}

bool stego_bit_writer_write_bits(StegoBitWriter *writer, uint32_t value, size_t count) {
    for (size_t i = 0; i < count; i++) {
        size_t shift = count - 1 - i;
        uint8_t bit = (uint8_t)((value >> shift) & 1);
        if (!stego_bit_writer_write_bit(writer, bit)) return false;
    }
    return true;
}

