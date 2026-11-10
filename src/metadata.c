/**
 * @file metadata.c
 * @brief Metadata inspection and structure-aware stripping implementation.
 *
 * Implements non-destructive segment-level stripping of EXIF, GPS, XMP, IPTC,
 * comments, and embedded thumbnails (IFD1) from JPEG and PNG files, preserving
 * the original image data, visual fidelity, JFIF headers, and ICC color profiles
 * without re-encoding.
 */

#include "stego/metadata.h"
#include "stego/image_format.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static inline uint16_t exif_u16(const uint8_t *p, bool is_le) {
    if (is_le) return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static inline uint32_t exif_u32(const uint8_t *p, bool is_le) {
    if (is_le) {
        return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
               ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    }
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static bool exif_rational(const uint8_t *p, bool is_le, double *val) {
    uint32_t num = exif_u32(p, is_le);
    uint32_t den = exif_u32(p + 4, is_le);
    if (den == 0) return false;
    *val = (double)num / (double)den;
    return true;
}

static bool parse_tiff_exif(const uint8_t *tiff, size_t tiff_len, StegoMetadataInfo *info) {
    if (!tiff || tiff_len < 8 || !info) return false;

    bool is_le = false;
    if (tiff[0] == 'I' && tiff[1] == 'I') {
        is_le = true;
        if (exif_u16(tiff + 2, true) != 42) return false;
    } else if (tiff[0] == 'M' && tiff[1] == 'M') {
        is_le = false;
        if (exif_u16(tiff + 2, false) != 42) return false;
    } else {
        return false;
    }

    uint32_t ifd0_offset = exif_u32(tiff + 4, is_le);
    if (ifd0_offset < 8 || ifd0_offset + 2 > tiff_len) return false;

    info->has_exif = true;
    uint16_t num_entries = exif_u16(tiff + ifd0_offset, is_le);
    if (ifd0_offset + 2 + (size_t)num_entries * 12 > tiff_len) {
        num_entries = (uint16_t)((tiff_len - (ifd0_offset + 2)) / 12);
    }

    uint32_t gps_ifd_offset = 0;
    uint32_t exif_ifd_offset = 0;

    for (uint16_t i = 0; i < num_entries; i++) {
        const uint8_t *e = tiff + ifd0_offset + 2 + (size_t)i * 12;
        uint16_t tag = exif_u16(e, is_le);
        uint16_t type = exif_u16(e + 2, is_le);
        uint32_t count = exif_u32(e + 4, is_le);

        const uint8_t *val_ptr = (count <= 4 && type <= 4) ? (e + 8) : NULL;
        if (!val_ptr) {
            uint32_t off = exif_u32(e + 8, is_le);
            if (off < tiff_len) val_ptr = tiff + off;
        }

        if (tag == 0x010F && val_ptr && type == 2) { /* Camera Make */
            info->has_camera_info = true;
            size_t max_copy = count < sizeof(info->camera_make) ? count : (sizeof(info->camera_make) - 1);
            memcpy(info->camera_make, val_ptr, max_copy);
            info->camera_make[max_copy] = '\0';
        } else if (tag == 0x0110 && val_ptr && type == 2) { /* Camera Model */
            info->has_camera_info = true;
            size_t max_copy = count < sizeof(info->camera_model) ? count : (sizeof(info->camera_model) - 1);
            memcpy(info->camera_model, val_ptr, max_copy);
            info->camera_model[max_copy] = '\0';
        } else if (tag == 0x0131 && val_ptr && type == 2) { /* Software */
            size_t max_copy = count < sizeof(info->software) ? count : (sizeof(info->software) - 1);
            memcpy(info->software, val_ptr, max_copy);
            info->software[max_copy] = '\0';
        } else if (tag == 0x0132 && val_ptr && type == 2) { /* DateTime */
            size_t max_copy = count < sizeof(info->datetime) ? count : (sizeof(info->datetime) - 1);
            memcpy(info->datetime, val_ptr, max_copy);
            info->datetime[max_copy] = '\0';
        } else if (tag == 0x8825) { /* GPS IFD Pointer */
            gps_ifd_offset = exif_u32(e + 8, is_le);
        } else if (tag == 0x8769) { /* Exif IFD Pointer */
            exif_ifd_offset = exif_u32(e + 8, is_le);
        }
    }

    /* Check Exif IFD for DateTimeOriginal if datetime not yet set */
    if (exif_ifd_offset > 0 && exif_ifd_offset + 2 <= tiff_len && info->datetime[0] == '\0') {
        uint16_t exif_entries = exif_u16(tiff + exif_ifd_offset, is_le);
        if (exif_ifd_offset + 2 + (size_t)exif_entries * 12 > tiff_len) {
            exif_entries = (uint16_t)((tiff_len - (exif_ifd_offset + 2)) / 12);
        }
        for (uint16_t k = 0; k < exif_entries; k++) {
            const uint8_t *e = tiff + exif_ifd_offset + 2 + (size_t)k * 12;
            uint16_t tag = exif_u16(e, is_le);
            uint32_t count = exif_u32(e + 4, is_le);
            if (tag == 0x9003 || tag == 0x9004) { /* DateTimeOriginal / DateTimeDigitized */
                uint32_t off = exif_u32(e + 8, is_le);
                if (off < tiff_len) {
                    size_t max_copy = count < sizeof(info->datetime) ? count : (sizeof(info->datetime) - 1);
                    memcpy(info->datetime, tiff + off, max_copy);
                    info->datetime[max_copy] = '\0';
                    break;
                }
            }
        }
    }

    /* Parse GPS IFD */
    if (gps_ifd_offset > 0 && gps_ifd_offset + 2 <= tiff_len) {
        uint16_t gps_entries = exif_u16(tiff + gps_ifd_offset, is_le);
        if (gps_ifd_offset + 2 + (size_t)gps_entries * 12 > tiff_len) {
            gps_entries = (uint16_t)((tiff_len - (gps_ifd_offset + 2)) / 12);
        }

        bool has_lat = false, has_lon = false;
        char lat_ref = 'N', lon_ref = 'E';
        double raw_lat = 0.0, raw_lon = 0.0;
        double altitude = 0.0;
        bool has_alt = false;
        uint8_t alt_ref = 0;
        char gps_date[32] = {0};
        double gps_time[3] = {0};
        bool has_time = false;

        for (uint16_t j = 0; j < gps_entries; j++) {
            const uint8_t *e = tiff + gps_ifd_offset + 2 + (size_t)j * 12;
            uint16_t tag = exif_u16(e, is_le);
            uint16_t type = exif_u16(e + 2, is_le);
            uint32_t count = exif_u32(e + 4, is_le);

            if (tag == 0x0001) { /* GPSLatitudeRef */
                lat_ref = (char)e[8];
            } else if (tag == 0x0002) { /* GPSLatitude */
                if (type == 5 && count >= 3) {
                    uint32_t off = exif_u32(e + 8, is_le);
                    if (off + 24 <= tiff_len) {
                        double d = 0, m = 0, s = 0;
                        if (exif_rational(tiff + off, is_le, &d) &&
                            exif_rational(tiff + off + 8, is_le, &m) &&
                            exif_rational(tiff + off + 16, is_le, &s)) {
                            if (d >= 0.0 && m >= 0.0 && m < 60.0 && s >= 0.0 && s < 60.0) {
                                raw_lat = d + (m / 60.0) + (s / 3600.0);
                                has_lat = true;
                            }
                        }
                    }
                }
            } else if (tag == 0x0003) { /* GPSLongitudeRef */
                lon_ref = (char)e[8];
            } else if (tag == 0x0004) { /* GPSLongitude */
                if (type == 5 && count >= 3) {
                    uint32_t off = exif_u32(e + 8, is_le);
                    if (off + 24 <= tiff_len) {
                        double d = 0, m = 0, s = 0;
                        if (exif_rational(tiff + off, is_le, &d) &&
                            exif_rational(tiff + off + 8, is_le, &m) &&
                            exif_rational(tiff + off + 16, is_le, &s)) {
                            if (d >= 0.0 && m >= 0.0 && m < 60.0 && s >= 0.0 && s < 60.0) {
                                raw_lon = d + (m / 60.0) + (s / 3600.0);
                                has_lon = true;
                            }
                        }
                    }
                }
            } else if (tag == 0x0005) { /* GPSAltitudeRef */
                alt_ref = e[8];
            } else if (tag == 0x0006) { /* GPSAltitude */
                if (type == 5) {
                    uint32_t off = exif_u32(e + 8, is_le);
                    if (off + 8 <= tiff_len) {
                        double a = 0.0;
                        if (exif_rational(tiff + off, is_le, &a)) {
                            altitude = (alt_ref == 1) ? -a : a;
                            has_alt = true;
                        }
                    }
                }
            } else if (tag == 0x0007) { /* GPSTimeStamp */
                if (type == 5 && count >= 3) {
                    uint32_t off = exif_u32(e + 8, is_le);
                    if (off + 24 <= tiff_len) {
                        double h = 0, m = 0, s = 0;
                        if (exif_rational(tiff + off, is_le, &h) &&
                            exif_rational(tiff + off + 8, is_le, &m) &&
                            exif_rational(tiff + off + 16, is_le, &s)) {
                            gps_time[0] = h; gps_time[1] = m; gps_time[2] = s;
                            has_time = true;
                        }
                    }
                }
            } else if (tag == 0x001D) { /* GPSDateStamp */
                if (type == 2) {
                    const uint8_t *dp = (count <= 4) ? (e + 8) : (tiff + exif_u32(e + 8, is_le));
                    if (dp && dp + (count < 31 ? count : 31) <= tiff + tiff_len) {
                        size_t clen = count < sizeof(gps_date) ? count : (sizeof(gps_date) - 1);
                        memcpy(gps_date, dp, clen);
                        gps_date[clen] = '\0';
                    }
                }
            }
        }

        /* Validate latitude and longitude */
        if (has_lat && has_lon) {
            /* Reject empty 0, 0 */
            if (fabs(raw_lat) > 0.000001 || fabs(raw_lon) > 0.000001) {
                double signed_lat = (lat_ref == 'S' || lat_ref == 's') ? -fabs(raw_lat) : fabs(raw_lat);
                double signed_lon = (lon_ref == 'W' || lon_ref == 'w') ? -fabs(raw_lon) : fabs(raw_lon);

                if (signed_lat >= -90.0 && signed_lat <= 90.0 &&
                    signed_lon >= -180.0 && signed_lon <= 180.0) {
                    info->has_gps = true;
                    info->latitude = signed_lat;
                    info->longitude = signed_lon;
                    info->latitude_ref[0] = (lat_ref == 'S' || lat_ref == 's') ? 'S' : 'N';
                    info->latitude_ref[1] = '\0';
                    info->longitude_ref[0] = (lon_ref == 'W' || lon_ref == 'w') ? 'W' : 'E';
                    info->longitude_ref[1] = '\0';

                    if (has_alt) {
                        info->altitude = altitude;
                        info->has_altitude = true;
                    }

                    if (gps_date[0] != '\0' && has_time) {
                        snprintf(info->gps_timestamp, sizeof(info->gps_timestamp),
                                 "%s %02d:%02d:%02d",
                                 gps_date, (int)gps_time[0], (int)gps_time[1], (int)gps_time[2]);
                        info->has_timestamp = true;
                    } else if (info->datetime[0] != '\0') {
                        snprintf(info->gps_timestamp, sizeof(info->gps_timestamp), "%s", info->datetime);
                        info->has_timestamp = true;
                    }
                    return true;
                }
            }
        }
    }
    return false;
}

static bool parse_text_or_xmp_gps(const uint8_t *data, size_t len, StegoMetadataInfo *info) {
    if (!data || len < 16 || !info || info->has_gps) return false;

    const char *str = (const char *)data;
    size_t scan_limit = len - 16;

    for (size_t i = 0; i < scan_limit; i++) {
        /* Check for text formatted string: "GPS <lat> <ref> <lon> <ref>" */
        if (memcmp(data + i, "GPS ", 4) == 0) {
            double lat = 0.0, lon = 0.0;
            char lref = 'N', wref = 'E';
            if (sscanf(str + i, "GPS %lf %c %lf %c", &lat, &lref, &lon, &wref) == 4) {
                if (fabs(lat) > 0.000001 || fabs(lon) > 0.000001) {
                    double slat = (lref == 'S' || lref == 's') ? -fabs(lat) : fabs(lat);
                    double slon = (wref == 'W' || wref == 'w') ? -fabs(lon) : fabs(lon);
                    if (slat >= -90.0 && slat <= 90.0 && slon >= -180.0 && slon <= 180.0) {
                        info->has_gps = true;
                        info->latitude = slat;
                        info->longitude = slon;
                        info->latitude_ref[0] = (lref == 'S' || lref == 's') ? 'S' : 'N';
                        info->latitude_ref[1] = '\0';
                        info->longitude_ref[0] = (wref == 'W' || wref == 'w') ? 'W' : 'E';
                        info->longitude_ref[1] = '\0';
                        return true;
                    }
                }
            }
        }

        /* Check for XMP GPS tags: GPSLatitude / GPSLongitude */
        if (memcmp(data + i, "GPSLatitude", 11) == 0) {
            const char *val_p = str + i + 11;
            while (*val_p == '=' || *val_p == '>' || *val_p == '"' || *val_p == '\'' || *val_p == ' ') val_p++;

            double d = 0, m = 0;
            char r = 'N';
            double lat_val = 0;
            bool lat_ok = false;
            if (sscanf(val_p, "%lf,%lf%c", &d, &m, &r) >= 2) {
                lat_val = d + (m / 60.0);
                if (r == 'S' || r == 's') lat_val = -lat_val;
                lat_ok = true;
            } else if (sscanf(val_p, "%lf", &lat_val) == 1) {
                r = (lat_val < 0) ? 'S' : 'N';
                lat_ok = true;
            }

            const char *lon_p = strstr(val_p, "GPSLongitude");
            if (lat_ok && lon_p) {
                const char *lon_val_p = lon_p + 12;
                while (*lon_val_p == '=' || *lon_val_p == '>' || *lon_val_p == '"' || *lon_val_p == '\'' || *lon_val_p == ' ') lon_val_p++;

                double ld = 0, lm = 0;
                char lr = 'E';
                double lon_val = 0;
                bool lon_ok = false;
                if (sscanf(lon_val_p, "%lf,%lf%c", &ld, &lm, &lr) >= 2) {
                    lon_val = ld + (lm / 60.0);
                    if (lr == 'W' || lr == 'w') lon_val = -lon_val;
                    lon_ok = true;
                } else if (sscanf(lon_val_p, "%lf", &lon_val) == 1) {
                    lr = (lon_val < 0) ? 'W' : 'E';
                    lon_ok = true;
                }

                if (lon_ok) {
                    if (fabs(lat_val) > 0.000001 || fabs(lon_val) > 0.000001) {
                        if (lat_val >= -90.0 && lat_val <= 90.0 && lon_val >= -180.0 && lon_val <= 180.0) {
                            info->has_gps = true;
                            info->latitude = lat_val;
                            info->longitude = lon_val;
                            info->latitude_ref[0] = (r == 'S' || r == 's') ? 'S' : 'N';
                            info->latitude_ref[1] = '\0';
                            info->longitude_ref[0] = (lr == 'W' || lr == 'w') ? 'W' : 'E';
                            info->longitude_ref[1] = '\0';
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

StegoResult stego_metadata_scan(const char *filepath, StegoMetadataInfo *info) {
    if (!filepath || !info) return STEGO_ERR_INVALID_ARG;
    memset(info, 0, sizeof(*info));

    FILE *fp = fopen(filepath, "rb");
    if (!fp) return STEGO_ERR_FILE_NOT_FOUND;

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize < 16) {
        fclose(fp);
        return STEGO_OK;
    }

    uint8_t *data = (uint8_t *)malloc((size_t)fsize);
    if (!data) {
        fclose(fp);
        return STEGO_ERR_MEMORY;
    }

    if (fread(data, 1, (size_t)fsize, fp) != (size_t)fsize) {
        free(data);
        fclose(fp);
        return STEGO_ERR_FILE_READ;
    }
    fclose(fp);

    /* 1. Try JPEG APP1 segment parsing */
    if (fsize >= 4 && data[0] == 0xFF && data[1] == 0xD8) {
        size_t pos = 2;
        while (pos + 4 < (size_t)fsize) {
            if (data[pos] != 0xFF) { pos++; continue; }
            while (pos < (size_t)fsize && data[pos] == 0xFF) pos++;
            if (pos >= (size_t)fsize) break;
            uint8_t marker = data[pos++];
            if (marker == 0xD9 || marker == 0xDA) break; /* EOI or SOS */
            if (pos + 2 > (size_t)fsize) break;
            uint16_t seg_len = ((uint16_t)data[pos] << 8) | data[pos + 1];
            if (seg_len < 2 || pos + seg_len > (size_t)fsize) break;

            if (marker == 0xE1 && seg_len >= 14) { /* APP1 */
                const uint8_t *payload = data + pos + 2;
                size_t payload_len = seg_len - 2;
                if (memcmp(payload, "Exif\0\0", 6) == 0) {
                    parse_tiff_exif(payload + 6, payload_len - 6, info);
                }
            }
            pos += seg_len;
        }
    }

    /* 2. Try PNG eXIf chunk parsing */
    if (!info->has_gps && fsize >= 16 && memcmp(data, "\x89PNG\r\n\x1a\n", 8) == 0) {
        size_t pos = 8;
        while (pos + 12 <= (size_t)fsize) {
            uint32_t chunk_len = ((uint32_t)data[pos] << 24) | ((uint32_t)data[pos+1] << 16) |
                                 ((uint32_t)data[pos+2] << 8) | (uint32_t)data[pos+3];
            const uint8_t *chunk_type = data + pos + 4;
            if (pos + 12 + chunk_len > (size_t)fsize) break;

            if (memcmp(chunk_type, "eXIf", 4) == 0 && chunk_len >= 8) {
                parse_tiff_exif(data + pos + 8, chunk_len, info);
            }
            pos += 12 + chunk_len;
        }
    }

    /* 3. Fallback: Search memory for TIFF headers (II*\0 or MM\0*) */
    if (!info->has_gps) {
        for (size_t i = 0; i + 16 < (size_t)fsize; i++) {
            if ((data[i] == 'I' && data[i+1] == 'I' && data[i+2] == 0x2A && data[i+3] == 0x00) ||
                (data[i] == 'M' && data[i+1] == 'M' && data[i+2] == 0x00 && data[i+3] == 0x2A)) {
                if (parse_tiff_exif(data + i, (size_t)fsize - i, info)) {
                    break;
                }
            }
        }
    }

    /* 4. Fallback: Search for Text or XMP GPS strings */
    if (!info->has_gps) {
        parse_text_or_xmp_gps(data, (size_t)fsize, info);
    }

    /* Scan for metadata volume, signatures, and device models */
    for (size_t i = 0; i + 8 < (size_t)fsize; i++) {
        if (memcmp(data + i, "Exif\0\0", 6) == 0) {
            info->has_exif = true;
            info->metadata_bytes += 128;
        }
        if (memcmp(data + i, "http://ns.adobe.com/xap", 23) == 0) {
            info->has_exif = true;
            info->metadata_bytes += 256;
            if (info->software[0] == '\0') snprintf(info->software, sizeof(info->software), "Adobe XMP");
        }
        if (memcmp(data + i, "Photoshop 3.0", 13) == 0) {
            info->has_exif = true;
            if (info->software[0] == '\0') snprintf(info->software, sizeof(info->software), "Adobe Photoshop");
        }
        if (memcmp(data + i, "Apple\0", 6) == 0 || memcmp(data + i, "Canon\0", 6) == 0 ||
            memcmp(data + i, "Nikon\0", 6) == 0 || memcmp(data + i, "Sony\0", 5) == 0 ||
            memcmp(data + i, "Samsung\0", 8) == 0 || memcmp(data + i, "Google\0", 7) == 0) {
            info->has_camera_info = true;
            if (info->camera_make[0] == '\0') {
                size_t len = strlen((char *)(data + i));
                if (len < sizeof(info->camera_make)) {
                    snprintf(info->camera_make, sizeof(info->camera_make), "%s", (char *)(data + i));
                }
            }
        }
        if (memcmp(data + i, "tEXt", 4) == 0 || memcmp(data + i, "zTXt", 4) == 0 || memcmp(data + i, "iTXt", 4) == 0) {
            info->has_exif = true;
            info->metadata_bytes += 64;
        }
    }

    if (info->has_gps) {
        info->metadata_bytes += 64;
        snprintf(info->risk_level, sizeof(info->risk_level), "High");
        snprintf(info->risk_reason, sizeof(info->risk_reason), "GPS location coordinates detected (reveals precise physical location).");
    } else if (info->has_camera_info || info->has_exif || info->datetime[0] != '\0' || info->software[0] != '\0') {
        snprintf(info->risk_level, sizeof(info->risk_level), "Medium");
        snprintf(info->risk_reason, sizeof(info->risk_reason), "Device model, software fingerprint, or timestamp detected.");
    } else {
        snprintf(info->risk_level, sizeof(info->risk_level), "Low");
        snprintf(info->risk_reason, sizeof(info->risk_reason), "No sensitive geolocation or device metadata detected.");
    }

    free(data);
    return STEGO_OK;
}

/**
 * @brief Structure-aware JPEG segment stripper.
 *
 * Parses JPEG markers, stripping APP1 (EXIF, GPS, IFD1 thumbnails, XMP),
 * APP13 (Photoshop / IPTC), and COM segments, while preserving APP0 (JFIF),
 * APP2 (ICC color profile), APP14 (Adobe), DQT, DHT, SOF, and entropy scan data.
 * Does not re-encode or degrade image quality.
 */
static StegoResult strip_jpeg_metadata(const uint8_t *in_data, size_t file_len, const char *output_path) {
    if (file_len < 4 || in_data[0] != 0xFF || in_data[1] != 0xD8) {
        return STEGO_ERR_INVALID_FORMAT;
    }

    FILE *out = fopen(output_path, "wb");
    if (!out) return STEGO_ERR_FILE_WRITE;

    /* Write Start of Image (SOI) */
    fputc(0xFF, out);
    fputc(0xD8, out);

    size_t pos = 2;
    while (pos < file_len) {
        if (in_data[pos] != 0xFF) {
            pos++;
            continue;
        }

        /* Skip consecutive 0xFF fill bytes */
        while (pos < file_len && in_data[pos] == 0xFF) {
            pos++;
        }
        if (pos >= file_len) break;

        uint8_t marker = in_data[pos++];

        /* Standalone markers without a length field */
        if (marker == 0xD8) { /* SOI */
            fputc(0xFF, out);
            fputc(marker, out);
            continue;
        }
        if (marker == 0xD9) { /* EOI */
            fputc(0xFF, out);
            fputc(marker, out);
            break;
        }
        if (marker >= 0xD0 && marker <= 0xD7) { /* RST0..RST7 */
            fputc(0xFF, out);
            fputc(marker, out);
            continue;
        }
        if (marker == 0x01) { /* TEM */
            fputc(0xFF, out);
            fputc(marker, out);
            continue;
        }

        /* Markers with 2-byte length */
        if (pos + 2 > file_len) break;
        uint16_t seg_len = ((uint16_t)in_data[pos] << 8) | in_data[pos + 1];
        if (seg_len < 2 || pos + seg_len > file_len) break;

        const uint8_t *seg_payload = in_data + pos + 2;
        size_t payload_len = seg_len - 2;

        bool should_strip = false;

        /* 1. APP1 (0xE1): EXIF (IFD0, GPS, Exif, IFD1 thumbnails) and XMP */
        if (marker == 0xE1) {
            should_strip = true;
        }
        /* 2. APP13 (0xED): Photoshop 3.0 / IPTC */
        else if (marker == 0xED) {
            if (payload_len >= 14 && memcmp(seg_payload, "Photoshop 3.0", 13) == 0) {
                should_strip = true;
            } else if (payload_len >= 4 && memcmp(seg_payload, "8BIM", 4) == 0) {
                should_strip = true;
            } else {
                should_strip = true;
            }
        }
        /* 3. COM (0xFE): Comment segment */
        else if (marker == 0xFE) {
            should_strip = true;
        }

        /* Notice:
         * APP0 (0xE0) - JFIF is PRESERVED.
         * APP2 (0xE2) - ICC Profile is PRESERVED.
         * APP14 (0xEE) - Adobe color transform is PRESERVED.
         */

        /* Start of Scan (SOS): Contains header followed by compressed bitstream */
        if (marker == 0xDA) {
            fputc(0xFF, out);
            fputc(marker, out);
            fwrite(in_data + pos, 1, seg_len, out);
            pos += seg_len;

            /* Stream compressed entropy-coded data until next real marker */
            while (pos < file_len) {
                if (in_data[pos] == 0xFF) {
                    if (pos + 1 < file_len) {
                        uint8_t next_b = in_data[pos + 1];
                        if (next_b == 0x00) {
                            /* Byte stuffing for literal 0xFF: copy 0xFF 0x00 */
                            fputc(0xFF, out);
                            fputc(0x00, out);
                            pos += 2;
                            continue;
                        } else if (next_b >= 0xD0 && next_b <= 0xD7) {
                            /* Restart marker: copy 0xFF 0xDn */
                            fputc(0xFF, out);
                            fputc(next_b, out);
                            pos += 2;
                            continue;
                        } else if (next_b == 0xFF) {
                            /* Pad byte */
                            fputc(0xFF, out);
                            pos++;
                            continue;
                        } else {
                            /* Real marker encountered (e.g. 0xD9 EOI or next SOS) */
                            break;
                        }
                    } else {
                        fputc(in_data[pos++], out);
                        break;
                    }
                } else {
                    fputc(in_data[pos++], out);
                }
            }
            continue;
        }

        if (!should_strip) {
            fputc(0xFF, out);
            fputc(marker, out);
            fwrite(in_data + pos, 1, seg_len, out);
        }

        pos += seg_len;
    }

    fclose(out);
    return STEGO_OK;
}

/**
 * @brief Structure-aware PNG chunk stripper.
 *
 * Strips eXIf, tEXt, zTXt, and iTXt metadata chunks, preserving essential
 * image and rendering chunks (IHDR, PLTE, IDAT, IEND, pHYs, cHRM, gAMA, sRGB).
 */
static StegoResult strip_png_metadata(const uint8_t *in_data, size_t file_len, const char *output_path) {
    if (file_len < 8 || memcmp(in_data, "\x89PNG\r\n\x1a\n", 8) != 0) {
        return STEGO_ERR_INVALID_FORMAT;
    }

    FILE *out = fopen(output_path, "wb");
    if (!out) return STEGO_ERR_FILE_WRITE;

    /* Write PNG 8-byte signature */
    fwrite(in_data, 1, 8, out);

    size_t pos = 8;
    while (pos + 12 <= file_len) {
        uint32_t chunk_len = ((uint32_t)in_data[pos] << 24) |
                             ((uint32_t)in_data[pos + 1] << 16) |
                             ((uint32_t)in_data[pos + 2] << 8) |
                             (uint32_t)in_data[pos + 3];

        if (pos + 12 + chunk_len > file_len) break;

        const char *type = (const char *)(in_data + pos + 4);

        /* Metadata chunks to remove: eXIf, tEXt, zTXt, iTXt */
        bool strip = (memcmp(type, "eXIf", 4) == 0 ||
                      memcmp(type, "tEXt", 4) == 0 ||
                      memcmp(type, "zTXt", 4) == 0 ||
                      memcmp(type, "iTXt", 4) == 0);

        if (!strip) {
            fwrite(in_data + pos, 1, 12 + chunk_len, out);
        }

        pos += 12 + chunk_len;
        if (memcmp(type, "IEND", 4) == 0) break;
    }

    fclose(out);
    return STEGO_OK;
}

static StegoResult strip_bmp_metadata(const uint8_t *in_data, size_t file_len, const char *output_path) {
    FILE *out = fopen(output_path, "wb");
    if (!out) return STEGO_ERR_FILE_WRITE;
    fwrite(in_data, 1, file_len, out);
    fclose(out);
    return STEGO_OK;
}

StegoResult stego_metadata_strip(const char *input_path, const char *output_path) {
    if (!input_path || !output_path) return STEGO_ERR_INVALID_ARG;

    /* Open input file strictly read-only */
    FILE *in = fopen(input_path, "rb");
    if (!in) return STEGO_ERR_FILE_NOT_FOUND;

    fseek(in, 0, SEEK_END);
    long fsize = ftell(in);
    fseek(in, 0, SEEK_SET);

    if (fsize < 4) {
        fclose(in);
        return STEGO_ERR_FILE_READ;
    }

    uint8_t *data = (uint8_t *)malloc((size_t)fsize);
    if (!data) {
        fclose(in);
        return STEGO_ERR_MEMORY;
    }

    if (fread(data, 1, (size_t)fsize, in) != (size_t)fsize) {
        free(data);
        fclose(in);
        return STEGO_ERR_FILE_READ;
    }
    fclose(in); /* Closed immediately - original file is never modified */

    StegoImageFormat fmt = stego_detect_format_buffer(data, (size_t)fsize);
    StegoResult res;

    switch (fmt) {
        case STEGO_FORMAT_JPEG:
            res = strip_jpeg_metadata(data, (size_t)fsize, output_path);
            break;
        case STEGO_FORMAT_PNG:
            res = strip_png_metadata(data, (size_t)fsize, output_path);
            break;
        case STEGO_FORMAT_BMP:
            res = strip_bmp_metadata(data, (size_t)fsize, output_path);
            break;
        default:
            res = strip_bmp_metadata(data, (size_t)fsize, output_path);
            break;
    }

    free(data);
    return res;
}
