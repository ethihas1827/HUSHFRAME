# ==============================================================================
# Multi-Format Privacy Steganography Toolkit Makefile
# 64-bit GCC Toolchain Configuration
# ==============================================================================

ifeq ($(OS),Windows_NT)
  ifeq ($(wildcard C:/msys64/ucrt64/bin/gcc.exe),C:/msys64/ucrt64/bin/gcc.exe)
    TOOLCHAIN_BIN := C:/msys64/ucrt64/bin
    CC := C:/msys64/ucrt64/bin/gcc.exe
  else ifeq ($(wildcard C:/w64devkit/bin/gcc.exe),C:/w64devkit/bin/gcc.exe)
    TOOLCHAIN_BIN := C:/w64devkit/bin
    CC := C:/w64devkit/bin/gcc.exe
  endif

  ifdef TOOLCHAIN_BIN
    export PATH := $(TOOLCHAIN_BIN):$(PATH)
    TOOLCHAIN_FLAGS := -B$(TOOLCHAIN_BIN)/
    WINDRES := $(TOOLCHAIN_BIN)/windres.exe
  else
    WINDRES := windres
  endif

  BIN_EXT := .exe
  RM := rm -f
  MKDIR := mkdir -p
else
  CC ?= gcc
  WINDRES ?= windres
  BIN_EXT :=
  RM := rm -f
  MKDIR := mkdir -p
endif

CFLAGS ?= -Wall -Wextra -O2 -std=c99
ifdef TOOLCHAIN_FLAGS
  CFLAGS += $(TOOLCHAIN_FLAGS)
endif
INCLUDES := -Iinclude -I.

TARGET := hushframe$(BIN_EXT)
LEGACY_TARGET := bmp-stego$(BIN_EXT)
GUI_TARGET := hushframe-gui$(BIN_EXT)
LEGACY_GUI_TARGET := bmp-stego-gui$(BIN_EXT)
SERVER_TARGET := hushframe-server$(BIN_EXT)
LEGACY_SERVER_TARGET := bmp-stego-server$(BIN_EXT)
OBJ_DIR := obj

# Core Library Sources
LIB_SRCS := src/error.c src/buffer.c src/bitstream.c src/random.c \
            src/crypto.c src/payload.c src/fec.c src/image_format.c \
            src/image_loader.c src/image_writer.c src/metadata.c \
            src/privacy.c src/carrier.c src/bmp_carrier.c src/png_carrier.c \
            src/jpeg_carrier.c src/heic_carrier.c src/analysis.c \
            src/compress.c src/capacity.c src/split.c src/file_payload.c \
            src/stego.c src/cli.c src/ui_tui.c \
            carriers/bmp_lsb/bmp_embed.c carriers/bmp_lsb/bmp_extract.c \
            carriers/png_lsb/png_embed.c carriers/png_lsb/png_extract.c \
            carriers/jpeg_dct/dct_utils.c carriers/jpeg_dct/jpeg_embed.c carriers/jpeg_dct/jpeg_extract.c \
            carriers/heic_container/heic_metadata_embed.c carriers/heic_container/heic_metadata_extract.c \
            privacy/metadata_scan.c privacy/metadata_strip.c privacy/gps_remover.c \
            privacy/privacy_report.c privacy/safe_share.c privacy/secure_delete.c \
            crypto/argon2id.c crypto/aes_gcm.c crypto/key_derivation.c \
            crypto/secure_memory.c crypto/integrity.c \
            codec/crc32.c codec/reed_solomon.c codec/interleaver.c codec/packet_framing.c \
            analysis/psnr.c analysis/ssim.c analysis/histogram.c analysis/rs_analysis.c analysis/report.c

LIB_OBJS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(LIB_SRCS))
APP_OBJS := $(OBJ_DIR)/src/main.o $(LIB_OBJS)

GUI_RC := src/ui/gui_resources.rc
GUI_RES_OBJ := $(OBJ_DIR)/src/ui/gui_resources.o
GUI_OBJS := $(OBJ_DIR)/src/ui/gui_main.o $(GUI_RES_OBJ) $(LIB_OBJS)
GUI_LIBS := -mwindows -lcomctl32 -lcomdlg32 -lshell32 -lgdi32 -ladvapi32 -lm

# Web Backend Sources
SERVER_BACKEND_SRCS := backend/http.c backend/uploads.c backend/stego_bridge.c backend/api.c
SERVER_BACKEND_OBJS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(SERVER_BACKEND_SRCS))
SERVER_OBJS := $(OBJ_DIR)/backend/server.o $(SERVER_BACKEND_OBJS) $(LIB_OBJS)
SERVER_LIBS := -lws2_32 -lm

TEST_TARGETS := test_stego$(BIN_EXT) test_bmp$(BIN_EXT) test_png$(BIN_EXT) \
                test_jpeg$(BIN_EXT) test_heic$(BIN_EXT) test_crypto$(BIN_EXT) \
                test_payload$(BIN_EXT) test_metadata$(BIN_EXT) test_privacy$(BIN_EXT) \
                test_robustness$(BIN_EXT) test_compatibility$(BIN_EXT) test_tui$(BIN_EXT) \
                test_server$(BIN_EXT) test_capacity_split$(BIN_EXT) test_upgrades$(BIN_EXT)

.PHONY: all clean test sample help

all: $(TARGET) $(LEGACY_TARGET) $(GUI_TARGET) $(LEGACY_GUI_TARGET) $(SERVER_TARGET) $(LEGACY_SERVER_TARGET) $(TEST_TARGETS)

$(OBJ_DIR)/%.o: %.c
	@$(MKDIR) $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(GUI_RES_OBJ): $(GUI_RC) src/ui/gui_manifest.xml
	@$(MKDIR) $(dir $@)
	$(WINDRES) -Isrc/ui $< -o $@

$(TARGET): $(APP_OBJS)
	$(CC) $(CFLAGS) $^ -lm -o $@
	@echo "Built: $@"

$(LEGACY_TARGET): $(TARGET)
	@cp -f $(TARGET) $(LEGACY_TARGET)
	@echo "Built legacy alias: $@"

$(GUI_TARGET): $(GUI_OBJS)
	$(CC) $(CFLAGS) $^ $(GUI_LIBS) -o $@
	@echo "Built: $@"

$(LEGACY_GUI_TARGET): $(GUI_TARGET)
	@cp -f $(GUI_TARGET) $(LEGACY_GUI_TARGET)
	@echo "Built legacy alias: $@"

$(SERVER_TARGET): $(SERVER_OBJS)
	$(CC) $(CFLAGS) $^ $(SERVER_LIBS) -o $@
	@echo "Built: $@"

$(LEGACY_SERVER_TARGET): $(SERVER_TARGET)
	@cp -f $(SERVER_TARGET) $(LEGACY_SERVER_TARGET)
	@echo "Built legacy alias: $@"

test_stego$(BIN_EXT): $(OBJ_DIR)/tests/test_stego.o $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ -lm -o $@
	@echo "Built: $@"

test_bmp$(BIN_EXT): $(OBJ_DIR)/tests/test_bmp.o $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ -lm -o $@
	@echo "Built: $@"

test_png$(BIN_EXT): $(OBJ_DIR)/tests/test_png.o $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ -lm -o $@
	@echo "Built: $@"

test_jpeg$(BIN_EXT): $(OBJ_DIR)/tests/test_jpeg.o $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ -lm -o $@
	@echo "Built: $@"

test_heic$(BIN_EXT): $(OBJ_DIR)/tests/test_heic.o $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ -lm -o $@
	@echo "Built: $@"

test_crypto$(BIN_EXT): $(OBJ_DIR)/tests/test_crypto.o $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ -lm -o $@
	@echo "Built: $@"

test_payload$(BIN_EXT): $(OBJ_DIR)/tests/test_payload.o $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ -lm -o $@
	@echo "Built: $@"

test_metadata$(BIN_EXT): $(OBJ_DIR)/tests/test_metadata.o $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ -lm -o $@
	@echo "Built: $@"

test_privacy$(BIN_EXT): $(OBJ_DIR)/tests/test_privacy.o $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ -lm -o $@
	@echo "Built: $@"

test_robustness$(BIN_EXT): $(OBJ_DIR)/tests/test_robustness.o $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ -lm -o $@
	@echo "Built: $@"

test_compatibility$(BIN_EXT): $(OBJ_DIR)/tests/test_compatibility.o $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ -lm -o $@
	@echo "Built: $@"

test_tui$(BIN_EXT): $(OBJ_DIR)/tests/test_tui.o $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ -lm -o $@
	@echo "Built: $@"

test_server$(BIN_EXT): $(OBJ_DIR)/tests/test_server.o $(SERVER_BACKEND_OBJS) $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ $(SERVER_LIBS) -o $@
	@echo "Built: $@"

test_capacity_split$(BIN_EXT): $(OBJ_DIR)/tests/test_capacity_split.o $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ -lm -o $@
	@echo "Built: $@"

test_upgrades$(BIN_EXT): $(OBJ_DIR)/tests/test_upgrades.o $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ -lm -o $@
	@echo "Built: $@"

sample: samples/gen_samples$(BIN_EXT)
	./samples/gen_samples$(BIN_EXT)
	@$(RM) samples/gen_samples$(BIN_EXT)

samples/gen_samples$(BIN_EXT): $(OBJ_DIR)/samples/gen_samples.o $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ -lm -o $@

test: $(TEST_TARGETS)
	@echo ""
	@echo "===================================================="
	@echo "         RUNNING COMPREHENSIVE TEST SUITE           "
	@echo "===================================================="
	./test_stego$(BIN_EXT)
	@echo ""
	./test_bmp$(BIN_EXT)
	@echo ""
	./test_png$(BIN_EXT)
	@echo ""
	./test_jpeg$(BIN_EXT)
	@echo ""
	./test_heic$(BIN_EXT)
	@echo ""
	./test_crypto$(BIN_EXT)
	@echo ""
	./test_payload$(BIN_EXT)
	@echo ""
	./test_metadata$(BIN_EXT)
	@echo ""
	./test_privacy$(BIN_EXT)
	@echo ""
	./test_robustness$(BIN_EXT)
	@echo ""
	./test_compatibility$(BIN_EXT)
	@echo ""
	./test_tui$(BIN_EXT)
	@echo ""
	./test_server$(BIN_EXT)
	@echo ""
	./test_capacity_split$(BIN_EXT)
	@echo ""
	./test_upgrades$(BIN_EXT)
	@echo ""
	@echo "===================================================="
	@echo "           ALL TEST SUITES COMPLETED                "
	@echo "===================================================="

clean:
	$(RM) -r $(OBJ_DIR)
	$(RM) $(TARGET) $(LEGACY_TARGET) $(GUI_TARGET) $(LEGACY_GUI_TARGET) $(SERVER_TARGET) $(LEGACY_SERVER_TARGET) $(TEST_TARGETS) samples/gen_samples$(BIN_EXT) tmp_test_* output.bmp restored.txt
	@echo "Clean completed."

help:
	@echo "Toolkit build targets:"
	@echo "  make        - Compile main CLI and all test targets"
	@echo "  make test   - Run all test suites"
	@echo "  make sample - Programmatically generate sample covers (BMP, PNG, JPG, HEIC)"
	@echo "  make clean  - Remove object files, binaries, and temporary test artifacts"
