# Security Policy

## Overview

Hushframe is an offline-first steganography application designed to store and transfer files within ordinary images. All cryptographic processing occurs strictly on your local device. The application does not communicate with any external network, cloud service, or telemetry endpoint.

## Supported Versions

| Version | Supported | Security Notes |
|:---:|:---:|---|
| **1.0.x** | :white_check_mark: | Active support (Argon2id + AES-256-GCM + FIL1 containers) |
| < 1.0.0 | :x: | Legacy development prototypes |

## Threat Model & Core Assumptions

1. **Local-First Processing**: The local web server binds strictly to the loopback address (`127.0.0.1`). It does not listen on public interfaces (`0.0.0.0`) and cannot be accessed over external networks.
2. **Authenticated Encryption (AEAD)**: When passphrase protection is enabled, payloads are encrypted using **AES-256-GCM** (NIST SP 800-38D) derived via **Argon2id** (RFC 9106) with a 128-bit cryptographic salt and memory-hard parameters. 128-bit authentication tags verify that not a single bit of ciphertext or metadata has been tampered with.
3. **Lossless Preservation Requirement**: Carrier images containing embedded data must remain in a lossless format (**PNG** or **BMP**). Lossy recompression (such as automatic JPEG conversion applied by messaging platforms and social networks) overwrites the least significant bits and will destroy embedded data.
4. **Memory Hygiene**: Cryptographic keys, expanded round keys, passphrases, and sensitive plaintext buffers are erased from volatile memory using secure zeroing immediately after processing.

## Submitting Bug Reports & Vulnerabilities

### Important Safety Warning
> [!WARNING]
> **Never include real passwords, private keys, sensitive personal files, or un-sanitized carrier images in public GitHub issues, discussions, or pull requests.** Always reproduce issues using synthetic test data (such as the gradient samples provided in `samples/`).

### How to Report a Vulnerability

If you discover a security vulnerability, flaw, or unexpected behavior in Hushframe, please do not open a public issue.

Instead, report it responsibly via:
- **GitHub Private Vulnerability Reporting**: Navigate to the repository's **Security** tab, click **Advisories**, and select **Report a vulnerability**.
- **Alternative Contact**: If GitHub Private Vulnerability Reporting is unavailable, open a confidential security advisory through your GitHub maintainer channel or contact the maintainer via the profile contact options.

### Response Timeline
- **Initial acknowledgment**: Within 48 hours.
- **Vulnerability assessment & triage**: Within 5 business days.
- **Remediation release**: Coordinated disclosure with patch release.

