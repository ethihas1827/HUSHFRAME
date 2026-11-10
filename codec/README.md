# Codec & Framing

This directory handles framing and error correction:
- `crc32.c`: CRC-32 integrity computation.
- `reed_solomon.c`: Reed-Solomon forward error correction (Phase 6).
- `interleaver.c`: Bit interleaver for burst error distribution.
- `packet_framing.c`: Packet structure and versioned envelopes.

