# Hushframe • Protect sensitive files within ordinary images.

Protect confidential files and messages within ordinary images. Everything runs entirely on your own device—no cloud uploads, no accounts, and zero telemetry.

---

## What is Hushframe?

**Hushframe** is a lightweight, privacy-focused local steganography application. Steganography is the technique of embedding information within ordinary media so that an observer cannot detect that content is present.

With Hushframe, you can:
- **Protect sensitive files or text messages** within images without visibly altering the image.
- **Add password protection** using authenticated encryption (**Argon2id** key derivation and **AES-256-GCM**).
- **Inspect and remove location data and camera metadata** from photos before sharing them.
- **Split large files across multiple cover images** when a single image has insufficient capacity.
- **Preserve original file integrity** automatically with authenticated `FIL1` containers and cryptographic SHA-256 checksums that restore the original filename and extension upon recovery.

---

## Quick Start: Three Ways to Use

### Option 1: Modern Web Application (Recommended for Most Users)

Start the local server:
```powershell
.\hushframe-server.exe
```
*(Legacy alias `.\bmp-stego-server.exe` also works seamlessly).*

Then open your web browser to:
```text
http://127.0.0.1:8080
```
- Clean, minimal, human-designed interface.
- Automatic session reset after downloading your files so no sensitive details remain on screen.
- Built-in Privacy Tools, Capacity Helper, and Multi-Image Splitting.
- Strictly binds to `127.0.0.1` (localhost only)—it never connects to external networks.

### Option 2: Interactive Terminal Application (TUI)

If you prefer working in PowerShell or terminal without remembering command flags:
```powershell
.\hushframe.exe
```
*(Legacy alias `.\bmp-stego.exe` also works seamlessly).*

Running `hushframe.exe` with no arguments opens an interactive terminal interface with selectable buttons:
- Move with **Arrow Keys** (or click with your mouse).
- Press **Enter** to select an action.
- Press **Esc** to go back or exit.

### Option 3: Command Line (CLI)

For scripts and terminal power users:

**Protect a file within an image with a password:**
```powershell
.\hushframe.exe embed --cover photo.png --secret document.pdf --output protected.png --password "YourPassphrase"
```

**Recover a file from a protected image:**
```powershell
.\hushframe.exe extract --stego protected.png --output restored/ --password "YourPassphrase"
```

**Split a large file across 3 cover images:**
```powershell
.\hushframe.exe embed-split --cover img1.png --cover img2.png --cover img3.png --secret backup.zip --output-prefix part --password "YourPassword"
```

**Recombine split parts:**
```powershell
.\hushframe.exe extract-split --stego part_1_of_3.png --stego part_2_of_3.png --stego part_3_of_3.png --output restored_backup.zip --password "YourPassword"
```

**Scan photo metadata for privacy risks:**
```powershell
.\hushframe.exe meta-scan --input vacation.jpg
```

**Strip all EXIF and GPS tags from a photo:**
```powershell
.\hushframe.exe meta-strip --input vacation.jpg --output vacation_clean.jpg
```

---

## Supported Image Formats

| Input Format | Detection Method | Handling & Output Format |
|---|---|---|
| **PNG** (RGB / RGBA / Grayscale / Palette / 16-bit) | Real magic bytes (`\x89PNG`) | Preserves alpha channel. Saves as lossless **PNG**. |
| **BMP** (24-bit RGB) | Real magic bytes (`BM`) | Preserves scanline padding. Saves as lossless **BMP** or **PNG**. |
| **JPEG / JPG** | Real magic bytes (`\xFF\xD8\xFF`) | Decoded to 8-bit pixels. **Saved as lossless PNG.** |
| **WebP** | Real magic bytes (`RIFF....WEBP`) | Decoded to 8-bit pixels. **Saved as lossless PNG.** |
| **GIF** | Real magic bytes (`GIF87a`/`GIF89a`) | Decoded to 8-bit pixels. **Saved as lossless PNG.** |
| **TGA** | Magic footer bytes | Decoded to 8-bit pixels. **Saved as lossless PNG.** |

> **Why are lossy inputs saved as PNG?**  
> Formats like JPEG and WebP discard subtle pixel variations during compression. If we saved a protected image as a JPEG, the JPEG compressor would destroy the embedded data. Hushframe prevents this by safely outputting as lossless PNG.

---

## Key Features & Safety Tools

### 1. Capacity Helper & Pre-Flight Check
Before modifying any file, Hushframe calculates the available storage space in your cover image:
- Shows file size and available image capacity in KB or MB.
- If your file exceeds the image capacity, it clearly explains the issue and offers 4 practical solutions:
  1. Select a larger cover image.
  2. Enable pre-encryption compression.
  3. Split across multiple images.
  4. Enable 2-bit or 3-bit higher capacity mode.

### 2. File Integrity & Name Preservation (FIL1 Container)
When you protect a file, Hushframe wraps it in an authenticated `FIL1` container that stores:
- Original filename and extension (e.g. `financial_report.xlsx`).
- Standard MIME type (e.g. `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`).
- Exact byte length.
- Cryptographic SHA-256 checksum.

When you recover the file, Hushframe verifies the SHA-256 hash in constant time and automatically restores the original filename and extension.

### 3. Multi-Image Splitting
Need to protect a large file, but only have smaller cover images?
- Hushframe splits your encrypted payload across multiple cover images.
- Generates named parts: `secret_part1_of_4.png`, `secret_part2_of_4.png`, etc.
- Detects missing, out-of-order, or duplicate parts.
- Authenticated headers ensure all parts belong to the exact same protection session.

### 4. Privacy Tools (Metadata Inspection & Stripping)
Smartphones and digital cameras often embed sensitive information inside images:
- **Location data** (latitude and longitude showing exact physical locations).
- **Camera hardware** (device make, camera model, lens information).
- **Software fingerprints** (editor version, capture timestamps).

Privacy Tools scans any image, assigns a clear threat rating (**Low**, **Medium**, or **High**), and provides a one-click **"Remove All Metadata"** action that creates a clean image without altering your original photo.

### 5. Local Activity History
- Optional, private log stored **strictly inside your web browser local storage**.
- Records operational timestamps, file names, and whether password protection was enabled.
- **Passwords, encryption keys, and file contents are never stored.**
- Can be disabled or cleared at any time with one click.

---

## Security Notes

1. **Authenticated Encryption (AEAD):** When you choose a password, Hushframe derives a 256-bit key using **Argon2id** (RFC 9106) with random 128-bit salt and high memory cost. The payload is encrypted using **AES-256-GCM** (NIST SP 800-38D) with a unique nonce and 128-bit authentication tag.
2. **Tamper Detection & Resistance:** If anyone modifies the protected image, or if an incorrect password is provided, authentication fails cleanly without leaking partial plaintext.
3. **Volatile Memory Sanitization:** Sensitive cryptographic variables, expanded keys, passwords, and plaintext payloads are erased from memory with secure zeroing immediately after use.
4. **Strict Localhost Binding:** The web backend binds exclusively to `127.0.0.1`. It never listens on public interfaces (`0.0.0.0`) and makes no internet queries or telemetry calls.
5. **Backward Compatibility:** Existing `CMC1` (standard) and `CMC2` (encrypted) envelopes remain 100% supported and fully compatible across all versions.

---

## Troubleshooting

### "Failed to communicate with the local server" in the web UI
- Ensure the local server is running: `.\hushframe-server.exe`.
- Check that the browser URL matches `http://127.0.0.1:8080`.
- If port 8080 is in use by another service, Hushframe will automatically pick an alternative open port (e.g., 8081) and print the URL in the terminal.

### "The selected file exceeds the available capacity of this image"
- A standard 24-bit image can hold roughly 1 byte of payload for every 8 bytes of raw pixel data (using 1 LSB per channel).
- Solutions:
  - Select a cover image with higher resolution.
  - Enable the "Compress file before protecting" option in the Capacity Helper.
  - Switch to the "Split across images" tab to distribute the payload across 2 or more cover images.

### "Social media app removed the embedded data"
- Messaging platforms like WhatsApp, Instagram, Telegram, and Discord automatically recompress photos into lossy JPEGs/WebP, destroying the least-significant bits.
- **Solution:** Always share the carrier image as an uncompressed file attachment (or zip archive) rather than as an inline photo.

### "The password is incorrect, or the protected image has been modified"
- Hushframe uses AES-256-GCM authentication. If even a single bit of the encrypted payload is altered, or if a single character of the password is incorrect, recovery will fail.
- Double-check your passphrase; there is no master backdoor or recovery key.

---

## Building and Running Tests

### Prerequisites
- Windows, macOS, or Linux with a C99-compatible compiler (e.g., GCC or Clang).
- On Windows: `w64devkit` or MSYS2 GCC.

### Compiling
```powershell
make
```
This builds:
- `hushframe.exe` (Main CLI and interactive TUI)
- `hushframe-server.exe` (Local web backend)
- Backward-compatible aliases: `bmp-stego.exe` and `bmp-stego-server.exe`

### Running the Test Suite
Hushframe has **15 automated test suites** covering unit and integration tests:
```powershell
make test
```
All 15 suites verify:
- BMP and PNG LSB embedding/extraction
- JPEG, WebP, GIF, and TGA format normalization
- Argon2id key derivation and AES-256-GCM authenticated encryption
- FIL1 authenticated container packing and SHA-256 integrity verification
- Multi-image chunking, ordering, and atomic rollback on missing parts
- EXIF/GPS scanning, privacy risk calculation, and non-destructive stripping
- Local REST API endpoints, localhost-only binding, and path traversal prevention
- TUI button selection, arrow key navigation, and mouse hit-testing

---

## License & Security Policy

This software is designed for privacy protection, research, and defensive security evaluation. All processing is 100% offline and local to your machine. For security considerations and vulnerability reporting, see [SECURITY.md](file:///c:/Users/Ethihas%20Elughoti/OneDrive/Desktop/STEG_PROJ/SECURITY.md).