# Hushframe — Protect sensitive files within ordinary images

[![Language](https://img.shields.io/badge/Language-C99-00599C?logo=c)](https://en.wikipedia.org/wiki/C99)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Encryption-AES--256--GCM-22c55e)](#security-architecture)
[![KDF](https://img.shields.io/badge/KDF-Argon2id-6366f1)](#security-architecture)
[![Local Only](https://img.shields.io/badge/Network-100%25%20Localhost-success)](http://127.0.0.1:8080)
[![Test Suite](https://img.shields.io/badge/Tests-15%20Suites%20%7C%20144%20Passing-brightgreen)](make-test)

Hushframe is an open-source, local-first steganography application written in C. It allows you to embed confidential files and messages inside ordinary images without visibly altering how the image looks.

Everything runs entirely on your local computer. There are no accounts, no cloud servers, and zero telemetry.

---

## What is Hushframe?

**Steganography** is the practice of concealing secret information within an everyday file so that outside observers cannot tell anything is hidden. 

While traditional encryption protects files by scrambling them into unreadable gibberish (which immediately draws attention), Hushframe hides your encrypted data inside the pixel values of regular images. An observer sees a standard photograph; a recipient with the passphrase recovers the original file with verified cryptographic integrity.

### Key Capabilities

- **Protect Files & Text**: Embed PDF documents, archives, spreadsheets, or private text inside PNG and BMP images.
- **Authenticated Encryption**: Derive 256-bit keys using **Argon2id** (RFC 9106) and encrypt payloads with **AES-256-GCM** (NIST SP 800-38D).
- **Preserve File Metadata (FIL1)**: Automatically restore the original filename, file extension, and MIME type upon recovery, verified with constant-time SHA-256 checksums.
- **Privacy & Metadata Cleaner**: Scan photos for sensitive GPS coordinates and camera fingerprints, and strip them before sharing.
- **Multi-Image Splitting**: Distribute large files across multiple smaller cover images when a single photo lacks sufficient capacity.
- **100% Device-Local**: The local server strictly binds to `127.0.0.1:8080` (loopback only) and makes no internet connections.

---

## Quick Start

### 1. Prerequisites

- **Windows**: [w64devkit](https://github.com/skeeto/w64devkit) or MSYS2 (GCC 64-bit and GNU Make).
- **macOS**: Xcode Command Line Tools (`xcode-select --install`).
- **Linux**: Standard build tools (`sudo apt install build-essential`).

### 2. Build the Project

Clone the repository and compile using `make`:

```bash
git clone https://github.com/ethihas1827/HUSHFRAME.git
cd HUSHFRAME
make
```

This compiles:
- `hushframe-server.exe` — Local web backend
- `hushframe.exe` — Interactive Terminal UI (TUI) and Command Line Interface (CLI)

### 3. Launch the Web Interface (Recommended)

Start the local server:
```powershell
.\hushframe-server.exe
```

Open your browser to:
```text
http://127.0.0.1:8080
```

---

## Step-by-Step Usage Guide

### Option A: Modern Web Interface

#### 1. Protecting a File or Text Message
1. Open [http://127.0.0.1:8080](http://127.0.0.1:8080) and click **"Protect a file"**.
2. Drag and drop or browse to choose a cover image (PNG, BMP, JPEG, WebP, or GIF).
3. Choose what to hide:
   - **Text message**: Enter your secret note directly.
   - **File**: Select any document, archive, or binary file.
4. *(Recommended)* Enter a strong passphrase to encrypt the content with Argon2id + AES-256-GCM.
5. Click **"Protect and save image"**.
6. Download your protected PNG image. Your session automatically resets so sensitive information does not remain on screen.

#### 2. Recovering Hidden Content
1. Click **"Recover a file"** from the navigation bar or home screen.
2. Select or drop the protected image.
3. If the image was password-protected, enter the passphrase.
4. Click **"Recover content"**.
5. Hushframe verifies the cryptographic tag and displays the recovered text or provides a download button for the original file with its original filename and extension intact.

#### 3. Privacy Tools (EXIF & GPS Geolocation Cleaning)
1. Navigate to the **"Privacy"** tab.
2. Select any photo taken by a smartphone or digital camera.
3. Review the detected metadata (GPS latitude/longitude, camera make, capture timestamp).
4. Click **"Remove All Metadata"** to produce a clean image with zero geolocation tags.

---

### Option B: Interactive Terminal UI (TUI)

If you prefer working inside a terminal without starting a browser:

```powershell
.\hushframe.exe
```

Running `hushframe.exe` with no arguments opens a text-based terminal interface:
- Navigate using **Arrow Keys** (or mouse click).
- Press **Enter** to select an action.
- Press **Esc** to return or exit.

---

### Option C: Command Line Interface (CLI)

For scripting and automation:

**Protect a document inside an image:**
```powershell
.\hushframe.exe embed --cover photo.png --secret report.pdf --output protected.png --password "YourPassphrase"
```

**Recover a file from a protected image:**
```powershell
.\hushframe.exe extract --stego protected.png --output restored/ --password "YourPassphrase"
```

**Split a large file across 3 photos:**
```powershell
.\hushframe.exe embed-split --cover img1.png --cover img2.png --cover img3.png --secret data.zip --output-prefix part --password "YourPassphrase"
```

**Recombine split parts:**
```powershell
.\hushframe.exe extract-split --stego part_1_of_3.png --stego part_2_of_3.png --stego part_3_of_3.png --output restored_data.zip --password "YourPassphrase"
```

**Scan a photo for privacy risks:**
```powershell
.\hushframe.exe meta-scan --input vacation.jpg
```

**Strip EXIF and GPS tags from a photo:**
```powershell
.\hushframe.exe meta-strip --input vacation.jpg --output vacation_clean.jpg
```

---

## Supported Image Formats

| Format | Detection Method | Processing & Output Policy |
|---|---|---|
| **PNG** (RGB, RGBA, Grayscale, Palette) | Magic bytes (`\x89PNG`) | Preserves color depth and alpha channels. Output is lossless **PNG**. |
| **BMP** (24-bit RGB) | Magic bytes (`BM`) | Preserves scanline row alignment. Output is lossless **BMP** or **PNG**. |
| **JPEG / JPG** | Magic bytes (`\xFF\xD8\xFF`) | Normalized to 8-bit pixels. **Saved as lossless PNG.** |
| **WebP** | Magic bytes (`RIFF....WEBP`) | Normalized to 8-bit pixels. **Saved as lossless PNG.** |
| **GIF** | Magic bytes (`GIF87a` / `GIF89a`) | Normalized to 8-bit pixels. **Saved as lossless PNG.** |
| **TGA** | Format signature footer | Normalized to 8-bit pixels. **Saved as lossless PNG.** |

### Why do lossy input images produce PNG output?
Formats like JPEG and lossy WebP discard subtle pixel variations every time they are compressed. If Hushframe saved steganographic data back into a JPEG file, the JPEG compression algorithm would overwrite the modified pixel bits and destroy the embedded payload. To guarantee data preservation, Hushframe automatically saves protected outputs as lossless PNG.

---

## Important Technical Limitations

Steganography operates under specific physical and mathematical constraints. Please keep the following in mind:

1. **Storage Capacity Depends on Image Size**:
   - Standard 1-bit Least Significant Bit (LSB) steganography stores 1 bit of secret payload per color channel.
   - A typical 24-bit RGB image provides roughly **1 byte of hidden payload capacity for every 8 bytes of raw uncompressed pixel data**.
   - Example: A 1920×1080 RGB image contains 2,073,600 pixels (6.22 MB raw), offering approximately **777 KB** of encrypted payload capacity.
   - If your file exceeds the cover image's capacity, use Hushframe's built-in **Multi-Image Splitting** feature or select a larger cover photo.

2. **Social Media & Messaging Apps Destroy Hidden Data**:
   - Messaging platforms (including WhatsApp, Discord, Telegram, Messenger, and Instagram) automatically compress and convert uploaded photos to reduce bandwidth.
   - This recompression discards the least significant pixel bits, permanently destroying any hidden steganographic payload.
   - **Best Practice:** When transmitting protected images, always share them as **uncompressed files or documents** (e.g. WhatsApp "Send as Document", Discord raw file upload, or inside a `.zip` archive) rather than as standard inline photos.

3. **Image Edits Invalidate Authentication**:
   - Resizing, cropping, rotating, applying color filters, or adjusting contrast alters pixel values.
   - Because Hushframe protects payloads with authenticated encryption (AES-256-GCM), modifying even a single pixel will cause authentication to fail cleanly rather than returning corrupt data.

---

## Security Architecture

Hushframe uses modern, standardized cryptographic algorithms rather than proprietary or obfuscated methods:

- **Key Derivation Function (KDF)**: **Argon2id** (RFC 9106) with memory-hard cost parameters and a unique 128-bit cryptographic salt generated via system entropy.
- **Authenticated Encryption (AEAD)**: **AES-256-GCM** (NIST SP 800-38D) with a 96-bit initialization vector (IV) and a 128-bit authentication tag.
- **Tamper Detection**: If the password is incorrect or the steganographic payload is altered, authentication fails with zero plaintext leakage.
- **Memory Hygiene**: Secret buffers, derived keys, and passphrases are wiped from volatile memory using secure zeroing immediately after use.
- **Strict Localhost Isolation**: The backend server binds exclusively to `127.0.0.1` and never listens on external network interfaces (`0.0.0.0`).

---

## Automated Test Suite

Hushframe includes **15 automated test suites** covering 144 unit, integration, and security checks:

```powershell
make test
```

The test suites verify:
- LSB embedding and extraction across 24-bit BMP and PNG images.
- Format normalization and lossy carrier safety checks (JPEG, WebP, GIF, TGA).
- Argon2id key derivation and AES-256-GCM encryption roundtrips.
- Tamper detection, wrong password rejection, and missing password rejection.
- FIL1 authenticated container packing, MIME detection, and SHA-256 integrity verification.
- Multi-image chunking, ordering, and atomic rollback on missing parts.
- EXIF/GPS scanning, privacy risk calculation, and non-destructive metadata stripping.
- Local REST API endpoints, localhost loopback binding, and path traversal prevention.
- TUI interactive navigation and mouse hit-testing.

---

## Troubleshooting

### "Failed to communicate with the local server" in the web UI
- Ensure the local server is running in a terminal window: `.\hushframe-server.exe`.
- Confirm your browser URL is `http://127.0.0.1:8080`.
- If port 8080 is in use by another program, Hushframe automatically binds to the next available port (e.g. 8081) and prints the active URL in your terminal.

### "The selected file exceeds the available capacity of this image"
- The secret file is too large for the selected cover image.
- Solutions:
  1. Select a higher-resolution cover image.
  2. Switch to the **"Capacity"** tab to calculate the exact dimensions required.
  3. Use the **"Split across images"** feature to distribute the payload across multiple photos.

### "The password is incorrect, or the protected image has been modified"
- Hushframe uses authenticated encryption. If a single character in the password is wrong, or if an image was recompressed or edited, decryption will fail.
- Double-check your passphrase; there are no backdoors or master keys.

---

## License & Security Policy

This project is licensed under the [MIT License](LICENSE).

For security policies, vulnerability reporting procedures, and supported versions, please refer to [SECURITY.md](SECURITY.md).
