# Project Plan: Multi-Format Privacy Steganography Toolkit

## Overview & Vision
Transforming the single-carrier BMP steganography utility into an enterprise-grade privacy and protection research toolkit across multiple digital image formats.

---

## Phased Implementation Roadmap

### Phase 1: Core Multi-Format & Adaptive PNG (Active Release)
- [x] Multi-format file magic-byte detection (BMP, PNG, JPEG, HEIC).
- [x] Uncompressed 24-bit BMP carrier with scanline padding preservation.
- [x] Standalone PNG loader with RFC 1951 DEFLATE decompression and scanline unfiltering.
- [x] Standalone PNG writer with standard uncompressed DEFLATE chunks and Adler32/CRC32 generation.
- [x] Standard 1-bit LSB embedding for BMP and PNG.
- [x] Adaptive texture-aware LSB embedding using high-order color bits (7..2) for deterministic encoder/decoder sync.
- [x] Format conversion safety validation (protecting spatial LSB from lossy destruction).
- [x] 8-byte `CMC1` envelope framing (`"CMC1"` + 32-bit big-endian length).
- [x] Command-line interface (`embed`, `extract`, `capacity`, `verify`, `formats`, `metadata`, `strip-metadata`, `privacy-report`, `secure-delete`, `attack-test`).
- [x] Unit test suites for BMP, PNG, JPEG, HEIC, Crypto, Payload, Metadata, Privacy, Robustness.

### Phase 2: Metadata Sanitation & Privacy Shield (Completed)
- [x] Deep EXIF, IPTC, and XMP metadata chunk parsing.
- [x] Selective field stripping (preserving color profiles while purging camera/GPS data and thumbnails).
- [x] Comprehensive privacy risk scoring report.

### Phase 3: Cryptographic Protection Envelope (CMC2) (Completed)
- [x] Passphrase-based key derivation with Argon2id (RFC 9106).
- [x] Authenticated encryption with AES-256-GCM (NIST SP 800-38D, 256-bit key, 96-bit random nonce, 128-bit tag).
- [x] Per-operation random 16-byte salt and 12-byte nonce generation.
- [x] Envelope AAD binding (36-byte header authenticated against tampering).
- [x] Wrong-passphrase, corrupted payload, and tamper rejection.
- [x] Secure memory zeroing of keys, plaintext, and intermediate state buffers.

### Universal Image Compatibility & Normalization (Completed)
- [x] Multi-format magic-byte detection (PNG, BMP, JPEG, WebP, GIF, TGA).
- [x] Internal normalization to 8-bit RGB (3 channels) or RGBA (4 channels) pixel buffer.
- [x] PNG mode support: 1/2/4/8/16-bit Grayscale, 1/2/4/8-bit Indexed/Palette, 8/16-bit RGB, 8/16-bit RGBA.
- [x] Alpha channel preservation (channels 0, 1, 2 used for stego; channel 3 preserved untouched).
- [x] Lossless PNG output enforcement for lossy, paletted, or animation inputs (JPEG, WebP, GIF, TGA).
- [x] Prevention of output saving to lossy formats (JPEG, WebP, GIF) to protect spatial LSB bits.
- [x] Resource protection: <= 16384 dimension validation and <= 256 MB buffer limits.
- [x] Clear error messages: `"Unsupported image format"`, `"Image could not be decoded"`, `"Image is too large"`, `"Image has invalid data"`.
- [x] Capacity calculation based on 3 usable channels across RGB, RGBA, and converted grayscale.
- [x] Automated test suite (`test_compatibility.exe`) covering all 12 compatibility and error scenarios.

### Native Desktop GUI (Completed)
- [x] Native Win32 desktop application with Common Controls v6 and Per-Monitor DPI scaling (`bmp-stego-gui.exe`).
- [x] 100% offline, zero external runtime dependencies or DLLs.
- [x] Multi-threaded worker architecture (`CreateThread`) ensuring a responsive, non-blocking UI.
- [x] Embed Secret screen with text message & file pickers, CMC1/CMC2 selection, and quick actions.
- [x] Extract Secret screen with auto-detection of CMC1/CMC2, scrollable text viewer, and zero partial-file leakage on auth failure.
- [x] Verify Image screen with envelope and integrity diagnostics and unencrypted payload warnings.
- [x] Capacity / Info screen displaying carrier properties, overhead specifications, and detected payloads.
- [x] Secure passphrase handling with volatile memory zeroing and input clearing.

### Interactive Terminal User Interface (TUI) (Completed)
- [x] Zero-argument interactive launcher (`.\bmp-stego.exe`) with non-interactive pipeline detection.
- [x] Selectable button-style menus (`> [ Button Name ]`) with inverse/colored highlights.
- [x] Dual input system: Keyboard navigation (`↑`/`↓`/`←`/`→`/`Tab`/`Enter`/`Esc`/`Space`) and optional Mouse Left-Click support.
- [x] Clean terminal state preservation and signal handling (`SetConsoleCtrlHandler` / Ctrl+C clean exit).
- [x] Main menu with 6 primary options: Hide a Secret, Reveal a Secret, Check Image, Privacy Tools, Help, Exit.
- [x] Hide a Secret screen: sample picker dialog, text/file radio toggle, Argon2id + AES-256-GCM password protection with confirm & show/hide, animated progress bar, overwrite warnings, and password-protected vs unencrypted status reporting.
- [x] Reveal a Secret screen: stego image picker, password entry, on-screen text display or save-to-file path, and exact error message on wrong password/tampering/corruption: `"The password is incorrect, or the image was changed or damaged."`.
- [x] Check Image screen: Verify hidden secret, Check capacity, Inspect metadata, Remove metadata, and Create privacy report.
- [x] Privacy Tools screen: Safe-share copy, secure delete/shred with confirmation modal, and privacy risk reporting.
- [x] Help screen: Controls reference, plain-English concept explanations, and CLI equivalent examples.
- [x] Automated test suite (`test_tui.exe`, 9 / 9 tests passing) verifying keyboard, mouse hit-testing, roundtrip, wrong/missing password rejection, memory zeroing, and no partial files.

### Privacy-First Local Web Suite (`bmp-stego-server.exe`) (Completed)
- [x] Local HTTP server implemented in C (`backend/server.c`), binding strictly to `127.0.0.1` (never `0.0.0.0`).
- [x] Port auto-selection starting from 8080 through 8090 with exact URL reporting.
- [x] Streaming static asset server (`backend/http.c`) for HTML, CSS, JS, with directory traversal rejection.
- [x] Multipart/form-data parser (`backend/uploads.c`) with magic-byte validation and 64 MB upload cap.
- [x] Ephemeral storage & zero-overwrite deletion of temporary carriers and secrets (`uploads_cleanup_temp_file`).
- [x] Reusable bridge (`backend/stego_bridge.c`) connecting API requests directly to the native C steganography engine.
- [x] JSON REST API endpoints: `POST /api/hide`, `POST /api/reveal`, `POST /api/verify`, `POST /api/capacity`, `GET /api/health`.
- [x] Modern, responsive frontend (`frontend/index.html`, `frontend/styles.css`, `frontend/app.js`):
  - Numbered steps, drag & drop zones, live capacity preview.
  - Text and secret file payload selectors with password confirmation and Show/Hide toggle.
  - Unprotected secret confirmation modal warning users before creating unencrypted payloads.
  - Animated progress indicator during Argon2id key derivation and embedding.
  - One-click Download protected image and Download recovered file buttons.
  - Copy to clipboard for extracted text payloads.
  - Human-friendly error messages without exposed cryptographic jargon.
  - Collapsible Advanced / Technical details section.
- [x] Automated test suite (`test_server.exe`, 14 / 14 tests passing) covering multipart parsing, roundtrips, wrong/missing password rejection, JPEG->PNG normalization notice, capacity calculation, temp-file zeroing, localhost-only bind check, and directory traversal defense.

### Phase 4: JPEG DCT Frequency Steganography
- [ ] JPEG marker parsing (SOI, DQT, DHT, SOF0, SOS).
- [ ] Quantized DCT coefficient LSB modification in mid-frequency bands.
- [ ] Recompression attack simulation and robustness evaluation.

### Phase 5: HEIC Container Steganography
- [ ] ISO Base Media File Format (ISOBMFF) box parsing.
- [ ] Metadata container and item data (`idat`) embedding.

### Phase 6: Robustness & Forward Error Correction
- [ ] Reed-Solomon $(255, k)$ error correction implementation.
- [ ] Matrix bit-interleaving against burst errors.
- [ ] Automated steganalysis benchmarking suite (chi-square, RS steganalysis).
