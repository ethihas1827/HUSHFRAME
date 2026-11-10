cmake_minimum_required(VERSION 3.10)
project(bmp_stego C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories(include .)

# Core library sources
set(LIB_SRCS
    src/error.c
    src/buffer.c
    src/bitstream.c
    src/random.c
    src/crypto.c
    src/payload.c
    src/fec.c
    src/image_format.c
    src/image_loader.c
    src/image_writer.c
    src/metadata.c
    src/privacy.c
    src/carrier.c
    src/bmp_carrier.c
    src/png_carrier.c
    src/jpeg_carrier.c
    src/heic_carrier.c
    src/analysis.c
    src/stego.c
    src/cli.c
    src/ui_tui.c
    carriers/bmp_lsb/bmp_embed.c
    carriers/bmp_lsb/bmp_extract.c
    carriers/png_lsb/png_embed.c
    carriers/png_lsb/png_extract.c
    carriers/jpeg_dct/dct_utils.c
    carriers/jpeg_dct/jpeg_embed.c
    carriers/jpeg_dct/jpeg_extract.c
    carriers/heic_container/heic_metadata_embed.c
    carriers/heic_container/heic_metadata_extract.c
    privacy/metadata_scan.c
    privacy/metadata_strip.c
    privacy/gps_remover.c
    privacy/privacy_report.c
    privacy/safe_share.c
    privacy/secure_delete.c
    crypto/argon2id.c
    crypto/aes_gcm.c
    crypto/key_derivation.c
    crypto/secure_memory.c
    crypto/integrity.c
    codec/crc32.c
    codec/reed_solomon.c
    codec/interleaver.c
    codec/packet_framing.c
    analysis/psnr.c
    analysis/ssim.c
    analysis/histogram.c
    analysis/rs_analysis.c
    analysis/report.c
)

add_library(stego_core STATIC ${LIB_SRCS})

# CLI / TUI Executable
add_executable(bmp-stego src/main.c)
target_link_libraries(bmp-stego PRIVATE stego_core m)

# Web Server Executable
set(SERVER_SRCS
    backend/server.c
    backend/http.c
    backend/uploads.c
    backend/stego_bridge.c
    backend/api.c
)
add_executable(bmp-stego-server ${SERVER_SRCS})
if(WIN32)
    target_link_libraries(bmp-stego-server PRIVATE stego_core ws2_32 m)
else()
    target_link_libraries(bmp-stego-server PRIVATE stego_core m)
endif()

# Test Executables
add_executable(test_server tests/test_server.c backend/http.c backend/uploads.c backend/stego_bridge.c backend/api.c)
if(WIN32)
    target_link_libraries(test_server PRIVATE stego_core ws2_32 m)
else()
    target_link_libraries(test_server PRIVATE stego_core m)
endif()

