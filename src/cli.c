/**
 * @file cli.c
 * @brief Command-line interface implementation supporting all required commands.
 */

#include "stego/cli.h"
#include "stego/stego.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
#define getcwd_compat _getcwd
#else
#include <unistd.h>
#define getcwd_compat getcwd
#endif

static bool file_exists(const char *path) {
    if (!path || path[0] == '\0') return false;
    FILE *fp = fopen(path, "rb");
    if (fp) {
        fclose(fp);
        return true;
    }
    return false;
}

static void print_missing_image_error(const char *path, bool verbose) {
    fprintf(stderr, "[-] Error: Input image not found: %s\n", path);
    fprintf(stderr, "[-] Please check the file path and try again.\n");
    if (verbose) {
        char cwd[1024];
        if (getcwd_compat(cwd, sizeof(cwd))) {
            fprintf(stderr, "[-] Current working directory: %s\n", cwd);
        }
    }
}

static void print_banner(void) {
    printf("=================================================================\n");
    printf("  Hushframe (v%s) — Keep what matters out of sight.             \n", STEGO_VERSION_STRING);
    printf("  Privacy-First Multi-Format Steganography Toolkit               \n");
    printf("=================================================================\n");
}

static void print_usage(const char *prog) {
    print_banner();
    printf("USAGE:\n");
    printf("  %s <command> [arguments] [options]\n\n", prog);
    printf("COMMANDS:\n");
    printf("  embed, encode          Embed secret message/file into cover image (BMP, PNG)\n");
    printf("                         Usage: %s embed <cover> <stego> (-m \"text\" | -f <file>) [-p|--passphrase <pass>] [-z|--compress] [--bits <1|2|3>] [--adaptive]\n", prog);
    printf("  extract, decode        Extract hidden secret payload from stego image\n");
    printf("                         Usage: %s extract <stego> [output_file] [-o <output_file>] [-p|--passphrase <pass>] [--adaptive]\n", prog);
    printf("  estimate               Calculate capacity, encryption overhead, and check if payload fits\n");
    printf("                         Usage: %s estimate <cover> <secret_file> [-p <pass>] [--compress] [--bits <1|2|3>]\n", prog);
    printf("  embed-split            Split and embed a large secret across multiple cover images\n");
    printf("                         Usage: %s embed-split <secret_file> <output_prefix> <cover1> <cover2> ... [-p <pass>] [--compress] [--bits <1|2|3>]\n", prog);
    printf("  extract-split          Recombine multiple stego part images into original secret\n");
    printf("                         Usage: %s extract-split <output_file> <part1> <part2> ... [-p <pass>]\n", prog);
    printf("  capacity, info         Display image metadata and stego capacity\n");
    printf("                         Usage: %s capacity <image> [--adaptive]\n", prog);
    printf("  verify                 Check whether image contains valid CMC1, CMC2, CMC3, or CMC4 payload\n");
    printf("                         Usage: %s verify <image> [--adaptive]\n", prog);
    printf("  formats                List supported carrier image formats and phase roadmap\n");
    printf("                         Usage: %s formats\n", prog);
    printf("  metadata               Inspect and scan image for EXIF, GPS, and camera metadata\n");
    printf("                         Usage: %s metadata <image>\n", prog);
    printf("  strip-metadata         Create cleaned image copy with metadata stripped\n");
    printf("                         Usage: %s strip-metadata <input> <output>\n", prog);
    printf("  privacy-report         Generate human-readable privacy risk analysis\n");
    printf("                         Usage: %s privacy-report <image>\n", prog);
    printf("  secure-delete          Shred sensitive file with zero-fill before deletion\n");
    printf("                         Usage: %s secure-delete <file>\n", prog);
    printf("  attack-test            Run carrier robustness benchmark simulation\n");
    printf("                         Usage: %s attack-test <image>\n", prog);
    printf("  help, -h, --help       Show this help manual\n\n");
    printf("OPTIONS:\n");
    printf("  -v, --verbose          Enable verbose diagnostic output\n");
    printf("  -z, --compress         Compress payload before encryption and embedding\n");
    printf("  --bits <1|2|3>         Select bits per channel (1=Standard LSB default; 2 or 3 for High-Capacity)\n");
    printf("  --adaptive             Enable adaptive texture-based LSB embedding for PNG\n");
    printf("  -p, --passphrase, --password <pass>  Passphrase for Argon2id + AES-256-GCM encryption\n");
    printf("  -c, --cover <path>     Cover image path\n");
    printf("  -s, --stego <path>     Stego image path\n");
    printf("  -m, --message <text>   Secret message to hide\n");
    printf("  -f, --file <path>      Secret file to hide\n");
    printf("  -o, --output <path>    Output file for extracted data\n");
    printf("=================================================================\n");
}

static void cmd_formats(void) {
    print_banner();
    printf("\nSUPPORTED IMAGE FORMATS & NORMALIZATION MATRIX:\n\n");
    printf("  Format  | Detection     | Status      | Normalization Action   | Output\n");
    printf("  --------|---------------|-------------|------------------------|---------\n");
    printf("  BMP     | Magic 'BM'    | Supported   | 24-bit Spatial LSB     | BMP/PNG \n");
    printf("  PNG     | Magic 8-byte  | Supported   | 8-bit RGB/RGBA direct  | PNG     \n");
    printf("  JPEG    | Magic FF D8   | Supported   | Decoded to 8-bit RGB   | PNG     \n");
    printf("  WEBP    | Magic 'WEBP'  | Supported   | Decoded to 8-bit RGB/A | PNG     \n");
    printf("  GIF     | Magic 'GIF8'  | Supported   | Decoded (1st frame)    | PNG     \n");
    printf("  TGA     | Header/Footer | Supported   | Decoded to 8-bit RGB/A | PNG     \n");
    printf("  HEIC    | Magic 'ftyp'  | Phase 3     | Container / Metadata   | HEIC    \n\n");
    printf("Notice: To protect embedded steganographic payloads from lossy destruction,\n");
    printf("all lossy, paletted, or animation inputs (JPEG, WEBP, GIF, TGA) are automatically\n");
    printf("decoded and embedded into lossless PNG output images.\n");
    printf("Saving steganographic payloads to lossy formats (JPEG/WEBP) is strictly prevented.\n");
    printf("=================================================================\n");
}

int stego_cli_run(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    bool verbose = false;
    int cmd_arg_idx = 1;

    /* Scan arguments for verbose flag */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "-v") == 0) {
            if (i == 1 && argc > 2 && argv[2][0] != '-') {
                verbose = true;
            } else if (i > 1) {
                verbose = true;
            }
        }
    }

    if ((strcmp(argv[1], "--verbose") == 0 || strcmp(argv[1], "-v") == 0) && argc > 2) {
        cmd_arg_idx = 2;
    }

    const char *cmd = argv[cmd_arg_idx];

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    if (strcmp(cmd, "formats") == 0 || strcmp(cmd, "--formats") == 0) {
        cmd_formats();
        return 0;
    }

    /* Check for flag-based old invocation: -e, -d, -i, -v */
    bool is_embed = (strcmp(cmd, "embed") == 0 || strcmp(cmd, "encode") == 0 || strcmp(cmd, "-e") == 0 || strcmp(cmd, "--encode") == 0);
    bool is_extract = (strcmp(cmd, "extract") == 0 || strcmp(cmd, "decode") == 0 || strcmp(cmd, "-d") == 0 || strcmp(cmd, "--decode") == 0);
    bool is_info = (strcmp(cmd, "capacity") == 0 || strcmp(cmd, "info") == 0 || strcmp(cmd, "-i") == 0 || (strcmp(cmd, "-v") == 0 && argc == 2) || strcmp(cmd, "--info") == 0);
    bool is_estimate = (strcmp(cmd, "estimate") == 0);
    bool is_split_embed = (strcmp(cmd, "embed-split") == 0 || strcmp(cmd, "split-embed") == 0);
    bool is_split_extract = (strcmp(cmd, "extract-split") == 0 || strcmp(cmd, "split-extract") == 0);
    bool is_verify = (strcmp(cmd, "verify") == 0);
    bool is_metadata = (strcmp(cmd, "metadata") == 0);
    bool is_strip = (strcmp(cmd, "strip-metadata") == 0);
    bool is_privacy = (strcmp(cmd, "privacy-report") == 0);
    bool is_delete = (strcmp(cmd, "secure-delete") == 0);
    bool is_attack = (strcmp(cmd, "attack-test") == 0);

    /* Parse remaining arguments */
    const char *cover_path = NULL;
    const char *stego_path = NULL;
    const char *message = NULL;
    const char *file_path = NULL;
    const char *out_path = NULL;
    const char *passphrase = NULL;
    bool adaptive = false;
    bool compress = false;
    int bits_per_channel = 1;

    const char *pos_args[64];
    int num_pos_args = 0;

    for (int i = 1; i < argc; i++) {
        if (i == cmd_arg_idx) continue;

        if (strcmp(argv[i], "--adaptive") == 0) {
            adaptive = true;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "-z") == 0 || strcmp(argv[i], "--compress") == 0) {
            compress = true;
        } else if (strcmp(argv[i], "--bits") == 0) {
            if (i + 1 < argc) {
                bits_per_channel = atoi(argv[++i]);
            } else {
                fprintf(stderr, "[-] Error: Missing argument for '--bits'\n");
                return 1;
            }
        } else if (strncmp(argv[i], "--bits=", 7) == 0) {
            bits_per_channel = atoi(argv[i] + 7);
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--password") == 0 || strcmp(argv[i], "--passphrase") == 0) {
            if (i + 1 < argc) {
                passphrase = argv[++i];
            } else {
                fprintf(stderr, "[-] Error: Missing argument for '%s'\n", argv[i]);
                return 1;
            }
        } else if (strncmp(argv[i], "--password=", 11) == 0) {
            passphrase = argv[i] + 11;
        } else if (strncmp(argv[i], "--passphrase=", 13) == 0) {
            passphrase = argv[i] + 13;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--cover") == 0) {
            if (i + 1 < argc) {
                cover_path = argv[++i];
            } else {
                fprintf(stderr, "[-] Error: Missing argument for '%s'\n", argv[i]);
                return 1;
            }
        } else if (strncmp(argv[i], "--cover=", 8) == 0) {
            cover_path = argv[i] + 8;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--stego") == 0) {
            if (i + 1 < argc) {
                stego_path = argv[++i];
            } else {
                fprintf(stderr, "[-] Error: Missing argument for '%s'\n", argv[i]);
                return 1;
            }
        } else if (strncmp(argv[i], "--stego=", 8) == 0) {
            stego_path = argv[i] + 8;
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--message") == 0) {
            if (i + 1 < argc) {
                message = argv[++i];
            } else {
                fprintf(stderr, "[-] Error: Missing argument for '%s'\n", argv[i]);
                return 1;
            }
        } else if (strncmp(argv[i], "--message=", 10) == 0) {
            message = argv[i] + 10;
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0) {
            if (i + 1 < argc) {
                file_path = argv[++i];
            } else {
                fprintf(stderr, "[-] Error: Missing argument for '%s'\n", argv[i]);
                return 1;
            }
        } else if (strncmp(argv[i], "--file=", 7) == 0) {
            file_path = argv[i] + 7;
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) {
                out_path = argv[++i];
            } else {
                fprintf(stderr, "[-] Error: Missing argument for '%s'\n", argv[i]);
                return 1;
            }
        } else if (strncmp(argv[i], "--output=", 9) == 0) {
            out_path = argv[i] + 9;
        } else if (argv[i][0] != '-') {
            if (num_pos_args < 64) {
                pos_args[num_pos_args++] = argv[i];
            }
        } else {
            fprintf(stderr, "[-] Error: Unrecognized option '%s'\n", argv[i]);
            return 1;
        }
    }

    if (passphrase && passphrase[0] == '\0') {
        fprintf(stderr, "[-] Error: Passphrase cannot be empty.\n");
        return 1;
    }

    if (is_info) {
        const char *img_path = (num_pos_args > 0) ? pos_args[0] : (cover_path ? cover_path : stego_path);
        if (!img_path) {
            fprintf(stderr, "[-] Error: Missing image path. Usage: %s capacity <image> [--adaptive] [--verbose]\n", argv[0]);
            return 1;
        }

        if (!file_exists(img_path)) {
            print_missing_image_error(img_path, verbose);
            return 1;
        }

        StegoImageFormat fmt = stego_detect_format(img_path);
        printf("\nTarget Image     : %s\n", img_path);
        printf("Detected Format  : %s (verified by file magic bytes)\n", stego_format_name(fmt));

        StegoCarrier *carrier = NULL;
        StegoResult res = stego_carrier_open(img_path, adaptive, &carrier);
        if (res != STEGO_OK) {
            fprintf(stderr, "[-] Error opening carrier: %s\n", stego_strerror(res));
            return 1;
        }

        size_t raw_cap = carrier->max_capacity(carrier) + STEGO_CMC1_HEADER_SIZE;
        size_t cap_cmc1 = (raw_cap > STEGO_CMC1_HEADER_SIZE) ? (raw_cap - STEGO_CMC1_HEADER_SIZE) : 0;
        size_t cap_cmc2 = (raw_cap > STEGO_CMC2_HEADER_SIZE) ? (raw_cap - STEGO_CMC2_HEADER_SIZE) : 0;

        uint32_t detected_len = 0;
        StegoEnvelopeType env = carrier->detect_envelope ? carrier->detect_envelope(carrier, &detected_len) : STEGO_ENVELOPE_NONE;

        printf("Original Mode    : %s (%d-bit per channel)\n", carrier->image->orig_color_mode, carrier->image->orig_bit_depth);
        printf("Normalized Mode  : 8-bit %s (%u channels)\n", carrier->image->channels == 4 ? "RGBA" : "RGB", carrier->image->channels);
        printf("Conversion       : %s\n", carrier->image->was_converted ? "Converted to 8-bit RGB/RGBA for safe LSB embedding" : "Native lossless carrier format");
        printf("Output Format    : %s\n", stego_format_name(carrier->image->target_fmt));
        printf("Dimensions       : %u x %u pixels\n", carrier->image->width, carrier->image->height);
        printf("Channels         : %u (%s)\n", carrier->image->channels, carrier->image->channels == 4 ? "RGBA (Alpha preserved)" : "RGB");
        printf("Usable Channels  : 3 (R, G, B used for stego; alpha preserved)\n");
        printf("Embedding Mode   : %s\n", adaptive ? "Adaptive Texture LSB" : "Standard LSB");
        printf("Max Raw Capacity : %zu bytes (%.2f KB) [%zu bits]\n", raw_cap, (double)raw_cap / 1024.0, raw_cap * 8);
        printf("Payload Capacity :\n");
        printf("  - CMC1 Unencrypted : %zu bytes (%.2f KB) [Overhead: 8 bytes]\n", cap_cmc1, (double)cap_cmc1 / 1024.0);
        printf("  - CMC2 Encrypted   : %zu bytes (%.2f KB) [Overhead: 52 bytes (Argon2id + AES-256-GCM)]\n", cap_cmc2, (double)cap_cmc2 / 1024.0);
        if (env == STEGO_ENVELOPE_CMC2) {
            printf("Stego Payload    : DETECTED (%u bytes embedded via CMC2 Encrypted envelope)\n", detected_len);
        } else if (env == STEGO_ENVELOPE_CMC1) {
            printf("Stego Payload    : DETECTED (%u bytes embedded via CMC1 Unencrypted envelope)\n", detected_len);
        } else {
            printf("Stego Payload    : None detected\n");
        }
        printf("=================================================================\n");
        stego_carrier_close(carrier);
        return 0;
    }

    if (is_verify) {
        const char *img_path = (num_pos_args > 0) ? pos_args[0] : (cover_path ? cover_path : stego_path);
        if (!img_path) {
            fprintf(stderr, "[-] Error: Missing image path. Usage: %s verify <image> [--verbose]\n", argv[0]);
            return 1;
        }

        if (!file_exists(img_path)) {
            print_missing_image_error(img_path, verbose);
            return 1;
        }

        StegoCarrier *carrier = NULL;
        StegoResult res = stego_carrier_open(img_path, adaptive, &carrier);
        if (res != STEGO_OK) {
            fprintf(stderr, "[-] Error opening carrier: %s\n", stego_strerror(res));
            return 1;
        }
        uint32_t detected_len = 0;
        StegoEnvelopeType env = carrier->detect_envelope ? carrier->detect_envelope(carrier, &detected_len) : STEGO_ENVELOPE_NONE;
        stego_carrier_close(carrier);

        if (env == STEGO_ENVELOPE_CMC2) {
            printf("[+] VALID: Steganographic payload verified (Length: %u bytes, Envelope: CMC2 Encrypted)\n", detected_len);
            return 0;
        } else if (env == STEGO_ENVELOPE_CMC1) {
            printf("[+] VALID: Steganographic payload verified (Length: %u bytes, Envelope: CMC1 Unencrypted)\n", detected_len);
            return 0;
        } else if (env == STEGO_ENVELOPE_CMC4) {
            printf("[+] VALID: Steganographic multi-part chunk verified (Chunk Length: %u bytes, Envelope: CMC4 Encrypted Part)\n", detected_len);
            return 0;
        } else if (env == STEGO_ENVELOPE_CMC3) {
            printf("[+] VALID: Steganographic multi-part chunk verified (Chunk Length: %u bytes, Envelope: CMC3 Unencrypted Part)\n", detected_len);
            return 0;
        } else {
            printf("[-] NO PAYLOAD: Image does not contain a valid steganography envelope.\n");
            return 2;
        }
    }

    if (is_embed) {
        if (!cover_path && num_pos_args > 0) cover_path = pos_args[0];
        if (!stego_path && num_pos_args > 1) stego_path = pos_args[1];

        if (!cover_path || !stego_path || (!message && !file_path)) {
            fprintf(stderr, "[-] Error: Missing arguments.\n");
            fprintf(stderr, "    Usage: %s embed <cover> <stego> (-m \"text\" | -f <file>) [-p|--passphrase <pass>] [--adaptive] [--verbose]\n", argv[0]);
            return 1;
        }

        if (!file_exists(cover_path)) {
            print_missing_image_error(cover_path, verbose);
            return 1;
        }

        if (file_path && !file_exists(file_path)) {
            fprintf(stderr, "[-] Error: Input secret file not found: %s\n", file_path);
            fprintf(stderr, "[-] Please check the file path and try again.\n");
            if (verbose) {
                char cwd[1024];
                if (getcwd_compat(cwd, sizeof(cwd))) {
                    fprintf(stderr, "[-] Current working directory: %s\n", cwd);
                }
            }
            return 1;
        }

        const char *temp_file = NULL;
        if (message) {
            temp_file = "tmp_msg_payload.tmp";
            FILE *tfp = fopen(temp_file, "wb");
            if (!tfp) {
                fprintf(stderr, "[-] Error creating temporary payload file\n");
                return 1;
            }
            fwrite(message, 1, strlen(message), tfp);
            fclose(tfp);
            file_path = temp_file;
        }

        if (passphrase) {
            printf("[*] Embedding into '%s' -> '%s' (Mode: %s, %d-bit LSB, Envelope: 52-byte CMC2 Encrypted%s)...\n",
                   cover_path, stego_path, adaptive ? "Adaptive Texture LSB" : "Standard LSB",
                   bits_per_channel, compress ? ", Compressed" : "");
        } else {
            printf("[*] Embedding into '%s' -> '%s' (Mode: %s, %d-bit LSB, Envelope: 8-byte CMC1 Unencrypted%s)...\n",
                   cover_path, stego_path, adaptive ? "Adaptive Texture LSB" : "Standard LSB",
                   bits_per_channel, compress ? ", Compressed" : "");
        }

        StegoResult res = stego_hide_file_unified_advanced(cover_path, stego_path, file_path, passphrase, adaptive, compress, bits_per_channel);
        if (temp_file) {
            stego_secure_delete_file(temp_file);
        }

        if (res != STEGO_OK) {
            if (res != STEGO_ERR_CAPACITY_EXCEEDED) {
                fprintf(stderr, "[-] Embedding failed: %s\n", stego_strerror(res));
            }
            return 1;
        }
        printf("[+] Success! Payload embedded and saved to '%s'\n", stego_path);
        return 0;
    }

    if (is_estimate) {
        if (num_pos_args < 2 && (!cover_path || (!file_path && !message))) {
            fprintf(stderr, "[-] Error: Missing arguments. Usage: %s estimate <cover> <secret_file> [-p <pass>] [--compress] [--bits <1|2|3>]\n", argv[0]);
            return 1;
        }
        const char *cov = cover_path ? cover_path : pos_args[0];
        const char *sec = file_path ? file_path : (num_pos_args > 1 ? pos_args[1] : NULL);
        if (!cov || !sec) {
            fprintf(stderr, "[-] Error: Please specify cover image and secret file.\n");
            return 1;
        }
        if (!file_exists(cov)) {
            print_missing_image_error(cov, verbose);
            return 1;
        }
        if (!file_exists(sec)) {
            fprintf(stderr, "[-] Error: Secret file not found: %s\n", sec);
            return 1;
        }

        StegoCarrier *c = NULL;
        StegoResult res = stego_carrier_open(cov, adaptive, &c);
        if (res != STEGO_OK) {
            fprintf(stderr, "[-] Error opening cover image: %s\n", stego_strerror(res));
            return 1;
        }

        FILE *fp = fopen(sec, "rb");
        fseek(fp, 0, SEEK_END);
        long sz = ftell(fp);
        fclose(fp);

        size_t assessed_sz = (size_t)sz;
        bool was_compressed = false;
        size_t orig_sz = (size_t)sz;

        if (compress) {
            if (stego_is_already_compressed_format(sec)) {
                printf("[*] Notice: '%s' has an already-compressed format extension.\n"
                       "    Pre-compression will likely not reduce its size.\n", sec);
            }
            FILE *fpin = fopen(sec, "rb");
            if (fpin) {
                uint8_t *in_buf = malloc(sz > 0 ? (size_t)sz : 1);
                if (in_buf && fread(in_buf, 1, (size_t)sz, fpin) == (size_t)sz) {
                    uint8_t *out_cmp = NULL;
                    size_t out_cmp_len = 0;
                    if (stego_compress_payload_if_beneficial(in_buf, (size_t)sz, &out_cmp, &out_cmp_len, &was_compressed) == STEGO_OK) {
                        if (was_compressed && out_cmp) {
                            assessed_sz = out_cmp_len;
                            free(out_cmp);
                        }
                    }
                }
                free(in_buf);
                fclose(fpin);
            }
        }

        StegoCapacityAssessment assess;
        stego_assess_capacity(c, sec, assessed_sz, passphrase != NULL, compress && was_compressed, bits_per_channel, &assess);
        stego_carrier_close(c);

        char sz_sec[32], sz_avail[32], sz_add[32];
        stego_format_bytes(orig_sz, sz_sec, sizeof(sz_sec));
        stego_format_bytes(assess.available_capacity, sz_avail, sizeof(sz_avail));
        stego_format_bytes(assess.additional_required, sz_add, sizeof(sz_add));

        printf("\n=================================================================\n");
        printf("               CAPACITY ESTIMATION & FEASIBILITY REPORT          \n");
        printf("=================================================================\n");
        printf("Cover Image          : %s (%u x %u pixels)\n", cov, assess.cover_width, assess.cover_height);
        if (was_compressed) {
            char sz_cmp[32];
            stego_format_bytes(assessed_sz, sz_cmp, sizeof(sz_cmp));
            double ratio = (orig_sz > 0) ? ((double)(orig_sz - assessed_sz) / (double)orig_sz) * 100.0 : 0.0;
            printf("Secret File          : %s (%s -> Compressed: %s, -%.1f%%)\n", sec, sz_sec, sz_cmp, ratio);
        } else {
            printf("Secret File          : %s (%s)\n", sec, sz_sec);
        }
        printf("Security Mode        : %s (Overhead: %zu bytes)\n", passphrase ? "Argon2id + AES-256-GCM (CMC2)" : "Unencrypted (CMC1)", assess.envelope_overhead);
        printf("Embedding Bit Depth  : %d-bit LSB per RGB channel\n", assess.bits_per_channel);
        printf("Available Capacity   : %s\n", sz_avail);
        printf("Total Space Needed   : %zu bytes\n", assess.total_required);
        printf("Status               : %s\n", assess.fits ? "[PASS] Secret fits comfortably" : "[FAIL] Secret exceeds cover capacity");
        if (!assess.fits) {
            printf("\n[-] %s\n", assess.error_summary);
            printf("%s\n", assess.formatted_details);
        }
        printf("=================================================================\n");
        return assess.fits ? 0 : 1;
    }

    if (is_split_embed) {
        if (num_pos_args < 3 && (!file_path || num_pos_args < 2)) {
            fprintf(stderr, "[-] Error: Usage: %s embed-split <secret_file> <output_prefix> <cover1> <cover2> ... [-p <pass>] [--compress] [--bits <1|2|3>]\n", argv[0]);
            return 1;
        }
        const char *sec_file = file_path ? file_path : pos_args[0];
        int prefix_idx = file_path ? 0 : 1;
        const char *prefix = pos_args[prefix_idx];
        int covers_start = prefix_idx + 1;
        int num_covers = num_pos_args - covers_start;

        if (num_covers < 1) {
            fprintf(stderr, "[-] Error: At least one cover image must be provided.\n");
            return 1;
        }

        const char *covers[64];
        for (int i = 0; i < num_covers; i++) {
            covers[i] = pos_args[covers_start + i];
        }

        printf("[*] Splitting secret '%s' across %d cover images (Prefix: '%s')...\n", sec_file, num_covers, prefix);
        StegoManifest manifest;
        char err_msg[512] = {0};
        StegoResult res = stego_split_embed(sec_file, covers, (uint16_t)num_covers, prefix, passphrase, compress, bits_per_channel, &manifest, err_msg, sizeof(err_msg));
        if (res != STEGO_OK) {
            fprintf(stderr, "[-] Split embedding failed: %s\n", err_msg[0] ? err_msg : stego_strerror(res));
            return 1;
        }

        printf("[+] Success! Secret '%s' split and embedded into %u parts:\n", manifest.original_filename, manifest.total_parts);
        for (uint16_t i = 0; i < manifest.total_parts; i++) {
            printf("    Part %u: %s (%zu bytes chunk)\n", manifest.parts[i].part_num, manifest.parts[i].part_path, manifest.parts[i].chunk_size);
        }
        printf("[+] Manifest saved: %s_manifest.json\n", prefix);
        printf("[!] Warning: All parts in correct order are required for extraction. Losing any part makes recovery impossible.\n");
        return 0;
    }

    if (is_split_extract) {
        if (num_pos_args < 2 && (!out_path || num_pos_args < 1)) {
            fprintf(stderr, "[-] Error: Usage: %s extract-split <output_file> <part1> <part2> ... [-p <pass>]\n", argv[0]);
            return 1;
        }
        const char *target_out = out_path ? out_path : pos_args[0];
        int parts_start = out_path ? 0 : 1;
        int num_parts = num_pos_args - parts_start;

        if (num_parts < 1) {
            fprintf(stderr, "[-] Error: Please specify the stego part images to recombine.\n");
            return 1;
        }

        const char *part_paths[64];
        for (int i = 0; i < num_parts; i++) {
            part_paths[i] = pos_args[parts_start + i];
        }

        printf("[*] Recombining %d stego part images into '%s'...\n", num_parts, target_out);
        char err_msg[512] = {0};
        StegoResult res = stego_split_extract(part_paths, (uint16_t)num_parts, target_out, passphrase, err_msg, sizeof(err_msg));
        if (res != STEGO_OK) {
            fprintf(stderr, "[-] Multi-part extraction failed: %s\n", err_msg[0] ? err_msg : stego_strerror(res));
            return 1;
        }

        printf("[+] Success! All %d parts cryptographically verified and recombined into '%s'.\n", num_parts, target_out);
        return 0;
    }

    if (is_extract) {
        /* Resolve target stego image and output file path */
        const char *target = NULL;
        if (stego_path) {
            target = stego_path;
        } else if (cover_path) {
            target = cover_path;
        }

        if (num_pos_args == 1) {
            if (!target) target = pos_args[0];
            else if (!out_path) out_path = pos_args[0];
        } else if (num_pos_args >= 2) {
            /* Two positional arguments provided: determine which is stego image and which is output file */
            if (file_exists(pos_args[0]) && stego_detect_format(pos_args[0]) != STEGO_FORMAT_UNKNOWN) {
                target = pos_args[0];
                if (!out_path) out_path = pos_args[1];
            } else if (file_exists(pos_args[1]) && stego_detect_format(pos_args[1]) != STEGO_FORMAT_UNKNOWN) {
                target = pos_args[1];
                if (!out_path) out_path = pos_args[0];
            } else {
                target = pos_args[0];
                if (!out_path) out_path = pos_args[1];
            }
        }

        if (!target) {
            fprintf(stderr, "[-] Error: Missing stego image path.\n");
            fprintf(stderr, "    Usage: %s extract <stego> [output_file] [-o <out>] [-p|--passphrase <pass>] [--adaptive] [--verbose]\n", argv[0]);
            return 1;
        }

        if (!file_exists(target)) {
            print_missing_image_error(target, verbose);
            return 1;
        }

        /* Open carrier and verify envelope requirements prior to releasing or creating files */
        StegoCarrier *carrier = NULL;
        StegoResult res = stego_carrier_open(target, adaptive, &carrier);
        if (res != STEGO_OK) {
            fprintf(stderr, "[-] Error opening carrier: %s\n", stego_strerror(res));
            return 1;
        }

        uint32_t detected_len = 0;
        StegoEnvelopeType env = carrier->detect_envelope ? carrier->detect_envelope(carrier, &detected_len) : STEGO_ENVELOPE_NONE;

        if (env == STEGO_ENVELOPE_NONE) {
            fprintf(stderr, "[-] Extraction failed: No steganographic payload detected in '%s'.\n", target);
            stego_carrier_close(carrier);
            return 1;
        }

        if (env == STEGO_ENVELOPE_CMC2 && (!passphrase || passphrase[0] == '\0')) {
            fprintf(stderr, "[-] Extraction failed: Stego image is encrypted (CMC2). Passphrase is required for decryption.\n");
            fprintf(stderr, "[-] Please specify the passphrase using -p, --passphrase, or --password.\n");
            stego_carrier_close(carrier);
            return 1;
        }

        if (env == STEGO_ENVELOPE_CMC1 && (passphrase && passphrase[0] != '\0')) {
            fprintf(stderr, "[-] Extraction failed: Image contains an unencrypted (CMC1) payload, but a passphrase was specified.\n");
            stego_carrier_close(carrier);
            return 1;
        }

        printf("[*] Extracting payload from '%s' (Mode: %s)...\n", target, adaptive ? "Adaptive" : "Standard");
        uint8_t *payload = NULL;
        size_t payload_len = 0;
        res = carrier->extract_secure(carrier, passphrase, &payload, &payload_len);
        stego_carrier_close(carrier);

        if (res == STEGO_ERR_AUTH_FAILED) {
            fprintf(stderr, "[-] Extraction failed: Authentication failed (wrong passphrase or corrupted/tampered payload).\n");
            if (out_path && file_exists(out_path)) {
                remove(out_path);
            }
            return 1;
        } else if (res != STEGO_OK) {
            fprintf(stderr, "[-] Extraction failed: %s\n", stego_strerror(res));
            if (out_path && file_exists(out_path)) {
                remove(out_path);
            }
            return 1;
        }

        if (out_path) {
            FILE *ofp = fopen(out_path, "wb");
            if (!ofp) {
                fprintf(stderr, "[-] Error: Failed to open output file '%s' for writing.\n", out_path);
                if (payload) {
                    stego_secure_zero(payload, payload_len);
                    free(payload);
                }
                return 1;
            }
            if (payload_len > 0) {
                if (fwrite(payload, 1, payload_len, ofp) != payload_len) {
                    fclose(ofp);
                    remove(out_path);
                    fprintf(stderr, "[-] Error: Failed to write complete payload to '%s'.\n", out_path);
                    stego_secure_zero(payload, payload_len);
                    free(payload);
                    return 1;
                }
            }
            fclose(ofp);
            printf("[+] Success! Decoded payload written to '%s' (%zu bytes)\n", out_path, payload_len);
        } else {
            printf("\n[+] Payload successfully extracted (%zu bytes):\n", payload_len);
            printf("----------------------------------------------------\n");
            fwrite(payload, 1, payload_len, stdout);
            printf("\n----------------------------------------------------\n");
        }

        if (payload) {
            stego_secure_zero(payload, payload_len);
            free(payload);
        }
        return 0;
    }

    if (is_metadata) {
        const char *target = (num_pos_args > 0) ? pos_args[0] : (cover_path ? cover_path : stego_path);
        if (!target) {
            fprintf(stderr, "[-] Error: Missing image path. Usage: %s metadata <image> [--verbose]\n", argv[0]);
            return 1;
        }

        if (!file_exists(target)) {
            print_missing_image_error(target, verbose);
            return 1;
        }

        StegoMetadataInfo info;
        StegoResult res = stego_metadata_scan(target, &info);
        if (res != STEGO_OK) {
            fprintf(stderr, "[-] Scan failed: %s\n", stego_strerror(res));
            return 1;
        }
        printf("\n================ Metadata Scan ================\n");
        printf("Target File : %s\n", target);
        printf("EXIF Header : %s\n", info.has_exif ? "Present" : "Not detected");
        printf("GPS Location: %s\n", info.has_gps ? "Present" : "Not detected");
        printf("===============================================\n");
        return 0;
    }

    if (is_strip) {
        if (!cover_path && num_pos_args > 0) cover_path = pos_args[0];
        if (!stego_path && num_pos_args > 1) stego_path = pos_args[1];

        if (!cover_path || !stego_path) {
            fprintf(stderr, "[-] Error: Usage: %s strip-metadata <input> <output> [--verbose]\n", argv[0]);
            return 1;
        }

        if (!file_exists(cover_path)) {
            print_missing_image_error(cover_path, verbose);
            return 1;
        }

        StegoResult res = stego_metadata_strip(cover_path, stego_path);
        if (res != STEGO_OK) {
            fprintf(stderr, "[-] Strip metadata failed: %s\n", stego_strerror(res));
            return 1;
        }
        printf("[+] Success: Created cleaned copy at '%s' with metadata stripped.\n", stego_path);
        return 0;
    }

    if (is_privacy) {
        const char *target = (num_pos_args > 0) ? pos_args[0] : (cover_path ? cover_path : stego_path);
        if (!target) {
            fprintf(stderr, "[-] Error: Missing image path. Usage: %s privacy-report <image> [--verbose]\n", argv[0]);
            return 1;
        }

        if (!file_exists(target)) {
            print_missing_image_error(target, verbose);
            return 1;
        }

        return (stego_privacy_report(target) == STEGO_OK) ? 0 : 1;
    }

    if (is_delete) {
        const char *target = (num_pos_args > 0) ? pos_args[0] : (cover_path ? cover_path : (file_path ? file_path : NULL));
        if (!target) {
            fprintf(stderr, "[-] Error: Missing file path. Usage: %s secure-delete <file>\n", argv[0]);
            return 1;
        }

        if (!file_exists(target)) {
            fprintf(stderr, "[-] Error: Input file not found: %s\n", target);
            fprintf(stderr, "[-] Please check the file path and try again.\n");
            if (verbose) {
                char cwd[1024];
                if (getcwd_compat(cwd, sizeof(cwd))) {
                    fprintf(stderr, "[-] Current working directory: %s\n", cwd);
                }
            }
            return 1;
        }

        StegoResult res = stego_secure_delete_file(target);
        if (res != STEGO_OK) {
            fprintf(stderr, "[-] Secure delete failed: %s\n", stego_strerror(res));
            return 1;
        }
        printf("[+] Success: File '%s' securely zero-overwritten and deleted.\n", target);
        return 0;
    }

    if (is_attack) {
        const char *target = (num_pos_args > 0) ? pos_args[0] : (cover_path ? cover_path : stego_path);
        if (target && !file_exists(target)) {
            print_missing_image_error(target, verbose);
            return 1;
        }

        printf("\n[*] Attack-Test & Robustness Simulation (Phase 4 / Phase 6):\n");
        printf("    JPEG Recompression Simulation: Scheduled for Phase 4.\n");
        printf("    Noise and Cropping Resilience: Scheduled for Phase 6 (Reed-Solomon FEC).\n");
        printf("    Current Phase 1 validates lossless spatial LSB for BMP and PNG.\n");
        return 0;
    }

    print_usage(argv[0]);
    return 1;
}
