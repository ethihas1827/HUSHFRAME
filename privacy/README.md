# Privacy & Metadata Protection

This directory provides privacy analysis and metadata management tools:
- `metadata_scan.c`: Inspects image files for EXIF, GPS, camera model, and timestamp tags.
- `metadata_strip.c`: Removes non-image metadata to prevent information leakage.
- `gps_remover.c`: Specifically zeroes out geolocation tags.
- `privacy_report.c`: Generates human-readable risk assessments.
- `safe_share.c`: Creates cleaned copies without altering the original cover image.
- `secure_delete.c`: Implements cryptographic overwrite shredding before filesystem unlink.

