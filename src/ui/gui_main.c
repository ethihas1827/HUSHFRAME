/**
 * @file gui_main.c
 * @brief Native Windows GUI for Privacy & Multi-Format Steganography Toolkit.
 *
 * Implements a modern, responsive, 100% offline desktop interface utilizing
 * the existing secure C core: Argon2id, AES-256-GCM, CMC1/CMC2 envelopes,
 * and unified carrier engines for BMP and PNG images.
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stego/stego.h"

/* ========================================================================= */
/* Custom Window Messages for Worker Thread Synchronization                  */
/* ========================================================================= */
#define WM_APP_EMBED_DONE (WM_APP + 101)
#define WM_APP_EXTRACT_DONE (WM_APP + 102)
#define WM_APP_VERIFY_DONE (WM_APP + 103)
#define WM_APP_INFO_DONE (WM_APP + 104)

/* ========================================================================= */
/* Control Identifiers                                                       */
/* ========================================================================= */
#define IDC_MAIN_TAB 1001
#define IDC_STATUS_BAR 1002

/* Embed Page Controls */
#define IDC_EMBED_COVER_EDIT 1101
#define IDC_EMBED_COVER_BROWSE 1102
#define IDC_EMBED_STEGO_EDIT 1103
#define IDC_EMBED_STEGO_BROWSE 1104
#define IDC_EMBED_RADIO_TEXT 1105
#define IDC_EMBED_RADIO_FILE 1106
#define IDC_EMBED_TEXT_EDIT 1107
#define IDC_EMBED_FILE_EDIT 1108
#define IDC_EMBED_FILE_BROWSE 1109
#define IDC_EMBED_PASS_EDIT 1110
#define IDC_EMBED_CONFIRM_EDIT 1111
#define IDC_EMBED_SHOW_PASS 1112
#define IDC_EMBED_CHK_ADAPTIVE 1113
#define IDC_EMBED_BTN_EXEC 1114
#define IDC_EMBED_STATUS_LBL 1115
#define IDC_EMBED_BTN_OPEN_DIR 1116
#define IDC_EMBED_BTN_VERIFY 1117
#define IDC_EMBED_BTN_SWITCH_EXT 1118
#define IDC_EMBED_COVER_INFO_LBL 1119
#define IDC_EMBED_CONVERT_NOTE_LBL 1120

/* Extract Page Controls */
#define IDC_EXTRACT_IMAGE_EDIT 1201
#define IDC_EXTRACT_IMAGE_BROWSE 1202
#define IDC_EXTRACT_DETECT_BTN 1203
#define IDC_EXTRACT_DETECT_LBL 1204
#define IDC_EXTRACT_PASS_EDIT 1205
#define IDC_EXTRACT_SHOW_PASS 1206
#define IDC_EXTRACT_FILE_EDIT 1207
#define IDC_EXTRACT_FILE_BROWSE 1208
#define IDC_EXTRACT_CHK_ADAPTIVE 1209
#define IDC_EXTRACT_BTN_EXEC 1210
#define IDC_EXTRACT_STATUS_LBL 1211
#define IDC_EXTRACT_RESULT_EDIT 1212

/* Verify Page Controls */
#define IDC_VERIFY_IMAGE_EDIT 1301
#define IDC_VERIFY_IMAGE_BROWSE 1302
#define IDC_VERIFY_CHK_ADAPTIVE 1303
#define IDC_VERIFY_BTN_EXEC 1304
#define IDC_VERIFY_STATUS_LBL 1305
#define IDC_VERIFY_DETAILS_EDIT 1306

/* Capacity / Info Page Controls */
#define IDC_INFO_IMAGE_EDIT 1401
#define IDC_INFO_IMAGE_BROWSE 1402
#define IDC_INFO_CHK_ADAPTIVE 1403
#define IDC_INFO_BTN_EXEC 1404
#define IDC_INFO_DETAILS_EDIT 1405

/* ========================================================================= */
/* Global Variables and Handles                                              */
/* ========================================================================= */
static HINSTANCE g_hInstance = NULL;
static HWND g_hMainWnd = NULL;
static HWND g_hTab = NULL;
static HWND g_hStatusBar = NULL;
static HWND g_hPages[4] = {NULL, NULL, NULL, NULL};

static HFONT g_hFontNormal = NULL;
static HFONT g_hFontBold = NULL;
static HFONT g_hFontTitle = NULL;
static HFONT g_hFontMono = NULL;

/* Status Colors: 0 = Normal, 1 = Success (Green), 2 = Error (Red), 3 = Warning
 * (Orange/Amber) */
static int g_embed_status_type = 0;
static int g_extract_status_type = 0;
static int g_verify_status_type = 0;

static COLORREF g_colSuccess = RGB(0, 135, 60);
static COLORREF g_colError = RGB(204, 0, 0);
static COLORREF g_colWarning = RGB(190, 105, 0);

static char g_last_stego_output[MAX_PATH] = {0};

/* ========================================================================= */
/* Thread Parameter and Result Structures                                    */
/* ========================================================================= */
typedef struct {
  char cover_path[MAX_PATH];
  char stego_path[MAX_PATH];
  char secret_file[MAX_PATH];
  char temp_payload[MAX_PATH];
  char passphrase[256];
  bool has_passphrase;
  bool adaptive;
  bool is_text_mode;
} EmbedWorkerParams;

typedef struct {
  StegoResult result;
  char error_detail[256];
  char stego_path[MAX_PATH];
  bool has_passphrase;
  bool adaptive;
  size_t payload_len;
} EmbedWorkerResult;

typedef struct {
  char stego_path[MAX_PATH];
  char output_path[MAX_PATH];
  char passphrase[256];
  bool has_passphrase;
  bool adaptive;
} ExtractWorkerParams;

typedef struct {
  StegoResult result;
  char error_detail[256];
  char output_path[MAX_PATH];
  uint8_t *extracted_data;
  size_t extracted_len;
  bool is_printable_text;
  StegoEnvelopeType envelope;
} ExtractWorkerResult;

/* ========================================================================= */
/* Utility Functions                                                         */
/* ========================================================================= */
static inline void safe_strcpy(char *dest, size_t dest_sz, const char *src) {
  if (!dest || dest_sz == 0)
    return;
  if (!src) {
    dest[0] = '\0';
    return;
  }
  snprintf(dest, dest_sz, "%s", src);
}

static bool file_exists_local(const char *path) {
  if (!path || path[0] == '\0')
    return false;
  DWORD attrs = GetFileAttributesA(path);
  return (attrs != INVALID_FILE_ATTRIBUTES &&
          !(attrs & FILE_ATTRIBUTE_DIRECTORY));
}

static void apply_font_to_children(HWND hwndParent, HFONT hFont) {
  HWND hChild = GetWindow(hwndParent, GW_CHILD);
  while (hChild) {
    SendMessage(hChild, WM_SETFONT, (WPARAM)hFont, TRUE);
    hChild = GetWindow(hChild, GW_HWNDNEXT);
  }
}

static bool browse_open_file(HWND hwndOwner, const char *filter,
                             const char *title, char *out_buf, DWORD max_len) {
  OPENFILENAMEA ofn;
  ZeroMemory(&ofn, sizeof(ofn));
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = hwndOwner;
  ofn.lpstrFilter = filter;
  ofn.lpstrFile = out_buf;
  ofn.nMaxFile = max_len;
  ofn.lpstrTitle = title;
  ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
  return GetOpenFileNameA(&ofn) != FALSE;
}

static bool browse_save_file(HWND hwndOwner, const char *filter,
                             const char *title, const char *def_ext,
                             char *out_buf, DWORD max_len) {
  OPENFILENAMEA ofn;
  ZeroMemory(&ofn, sizeof(ofn));
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = hwndOwner;
  ofn.lpstrFilter = filter;
  ofn.lpstrFile = out_buf;
  ofn.nMaxFile = max_len;
  ofn.lpstrTitle = title;
  ofn.lpstrDefExt = def_ext;
  ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
  return GetSaveFileNameA(&ofn) != FALSE;
}

static bool is_text_payload(const uint8_t *data, size_t len) {
  if (!data || len == 0)
    return true;
  for (size_t i = 0; i < len; i++) {
    uint8_t c = data[i];
    if (c == 0)
      return false;
    if (c < 32 && c != '\r' && c != '\n' && c != '\t') {
      return false;
    }
  }
  return true;
}

/* ========================================================================= */
/* Worker Threads                                                            */
/* ========================================================================= */
static DWORD WINAPI EmbedWorkerThread(LPVOID lpParam) {
  EmbedWorkerParams *params = (EmbedWorkerParams *)lpParam;
  EmbedWorkerResult *res =
      (EmbedWorkerResult *)malloc(sizeof(EmbedWorkerResult));
  memset(res, 0, sizeof(EmbedWorkerResult));

  safe_strcpy(res->stego_path, sizeof(res->stego_path), params->stego_path);
  res->has_passphrase = params->has_passphrase;
  res->adaptive = params->adaptive;

  const char *actual_secret =
      params->is_text_mode ? params->temp_payload : params->secret_file;

  /* Call the existing secure unified hide function */
  res->result = stego_hide_file_unified_secure(
      params->cover_path, params->stego_path, actual_secret,
      params->has_passphrase ? params->passphrase : NULL, params->adaptive);

  /* Securely delete temporary file if used */
  if (params->is_text_mode && params->temp_payload[0]) {
    stego_secure_delete_file(params->temp_payload);
  }

  /* Wipe memory in parameters */
  stego_secure_zero(params->passphrase, sizeof(params->passphrase));
  free(params);

  PostMessage(g_hMainWnd, WM_APP_EMBED_DONE, 0, (LPARAM)res);
  return 0;
}

static DWORD WINAPI ExtractWorkerThread(LPVOID lpParam) {
  ExtractWorkerParams *params = (ExtractWorkerParams *)lpParam;
  ExtractWorkerResult *res =
      (ExtractWorkerResult *)malloc(sizeof(ExtractWorkerResult));
  memset(res, 0, sizeof(ExtractWorkerResult));

  safe_strcpy(res->output_path, sizeof(res->output_path), params->output_path);

  StegoCarrier *carrier = NULL;
  StegoResult st =
      stego_carrier_open(params->stego_path, params->adaptive, &carrier);
  if (st != STEGO_OK) {
    res->result = st;
    snprintf(res->error_detail, sizeof(res->error_detail),
             "Could not open carrier: %s", stego_strerror(st));
  } else {
    uint32_t det_len = 0;
    res->envelope = carrier->detect_envelope
                        ? carrier->detect_envelope(carrier, &det_len)
                        : STEGO_ENVELOPE_NONE;

    if (res->envelope == STEGO_ENVELOPE_NONE) {
      res->result = STEGO_ERR_NO_PAYLOAD;
      snprintf(res->error_detail, sizeof(res->error_detail),
               "No valid steganographic envelope detected in carrier.");
    } else if (res->envelope == STEGO_ENVELOPE_CMC2 &&
               !params->has_passphrase) {
      res->result = STEGO_ERR_AUTH_FAILED;
      snprintf(res->error_detail, sizeof(res->error_detail),
               "Payload is encrypted (CMC2). Passphrase is required.");
    } else {
      uint8_t *payload_data = NULL;
      size_t payload_len = 0;
      res->result = carrier->extract_secure(
          carrier, params->has_passphrase ? params->passphrase : NULL,
          &payload_data, &payload_len);

      if (res->result == STEGO_OK) {
        res->extracted_data = payload_data;
        res->extracted_len = payload_len;
        res->is_printable_text = is_text_payload(payload_data, payload_len);

        /* If output file specified, write cleanly now */
        if (params->output_path[0] != '\0') {
          FILE *fp = fopen(params->output_path, "wb");
          if (!fp) {
            res->result = STEGO_ERR_FILE_WRITE;
            snprintf(res->error_detail, sizeof(res->error_detail),
                     "Failed to open destination file for writing.");
          } else {
            if (payload_len > 0) {
              if (fwrite(payload_data, 1, payload_len, fp) != payload_len) {
                res->result = STEGO_ERR_FILE_WRITE;
                snprintf(res->error_detail, sizeof(res->error_detail),
                         "Incomplete disk write to destination file.");
              }
            }
            fclose(fp);
          }
        }
      } else if (res->result == STEGO_ERR_AUTH_FAILED) {
        snprintf(res->error_detail, sizeof(res->error_detail),
                 "Authentication failed! Incorrect passphrase or "
                 "corrupted/tampered payload.");
      } else {
        snprintf(res->error_detail, sizeof(res->error_detail),
                 "Extraction error: %s", stego_strerror(res->result));
      }
    }
    stego_carrier_close(carrier);
  }

  /* Wipe memory */
  stego_secure_zero(params->passphrase, sizeof(params->passphrase));
  free(params);

  PostMessage(g_hMainWnd, WM_APP_EXTRACT_DONE, 0, (LPARAM)res);
  return 0;
}

/* ========================================================================= */
/* Tab Switching Helper                                                      */
/* ========================================================================= */
static void SwitchToTab(int tab_index) {
  if (tab_index < 0 || tab_index > 3)
    return;
  SendMessage(g_hTab, TCM_SETCURSEL, (WPARAM)tab_index, 0);
  for (int i = 0; i < 4; i++) {
    ShowWindow(g_hPages[i], (i == tab_index) ? SW_SHOW : SW_HIDE);
  }
}

/* ========================================================================= */
/* Page 0: Embed Secret                                                      */
/* ========================================================================= */
static LRESULT CALLBACK EmbedPageProc(HWND hwnd, UINT uMsg, WPARAM wParam,
                                      LPARAM lParam) {
  switch (uMsg) {
  case WM_CTLCOLORSTATIC: {
    HDC hdc = (HDC)wParam;
    HWND hCtl = (HWND)lParam;
    int ctlId = GetDlgCtrlID(hCtl);
    if (ctlId == IDC_EMBED_STATUS_LBL) {
      if (g_embed_status_type == 1) {
        SetTextColor(hdc, g_colSuccess);
      } else if (g_embed_status_type == 2) {
        SetTextColor(hdc, g_colError);
      } else if (g_embed_status_type == 3) {
        SetTextColor(hdc, g_colWarning);
      }
      SetBkMode(hdc, TRANSPARENT);
      return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
    }
    if (ctlId == IDC_EMBED_CONVERT_NOTE_LBL) {
      SetTextColor(hdc, g_colWarning);
      SetBkMode(hdc, TRANSPARENT);
      return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
    }
    if (ctlId == IDC_EMBED_COVER_INFO_LBL) {
      SetTextColor(hdc, RGB(0, 90, 180));
      SetBkMode(hdc, TRANSPARENT);
      return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
    }
    break;
  }

  case WM_COMMAND: {
    int wmId = LOWORD(wParam);

    if (wmId == IDC_EMBED_COVER_BROWSE) {
      char path[MAX_PATH] = {0};
      if (browse_open_file(hwnd,
                           "Supported Cover Images "
                           "(*.png;*.bmp;*.jpg;*.jpeg;*.webp;*.gif;*.tga)\0*."
                           "png;*.bmp;*.jpg;*.jpeg;*.webp;*.gif;*.tga\0"
                           "PNG Images (*.png)\0*.png\0"
                           "BMP Images (*.bmp)\0*.bmp\0"
                           "JPEG Images (*.jpg;*.jpeg)\0*.jpg;*.jpeg\0"
                           "WebP Images (*.webp)\0*.webp\0"
                           "GIF Images (*.gif)\0*.gif\0"
                           "TGA Images (*.tga)\0*.tga\0"
                           "All Files (*.*)\0*.*\0",
                           "Select Cover Image", path, MAX_PATH)) {
        SetDlgItemTextA(hwnd, IDC_EMBED_COVER_EDIT, path);

        /* Inspect cover image properties and update diagnostics */
        StegoImage *inspect_img = NULL;
        StegoResult lres = stego_image_load(path, &inspect_img);
        if (lres == STEGO_OK && inspect_img) {
          char info_txt[256];
          snprintf(info_txt, sizeof(info_txt),
                   "Detected: %s (%s, %d-bit) | Normalization: %s | Final "
                   "Output: %s",
                   stego_format_name(inspect_img->format),
                   inspect_img->orig_color_mode, inspect_img->orig_bit_depth,
                   inspect_img->was_converted ? "Converted to 8-bit RGB/RGBA"
                                              : "Native",
                   stego_format_name(inspect_img->target_fmt));
          SetDlgItemTextA(hwnd, IDC_EMBED_COVER_INFO_LBL, info_txt);

          if (inspect_img->was_converted) {
            char warn_txt[256];
            snprintf(warn_txt, sizeof(warn_txt),
                     "[!] Notice: Input format (%s) is lossy/paletted. Stego "
                     "image will be saved as lossless PNG.",
                     stego_format_name(inspect_img->format));
            SetDlgItemTextA(hwnd, IDC_EMBED_CONVERT_NOTE_LBL, warn_txt);
          } else {
            SetDlgItemTextA(hwnd, IDC_EMBED_CONVERT_NOTE_LBL,
                            "Native lossless carrier format: direct LSB "
                            "embedding supported.");
          }

          /* Propose default output path */
          char out_path[MAX_PATH + 64] = {0};
          char dot_buf[MAX_PATH];
          safe_strcpy(dot_buf, sizeof(dot_buf), path);
          char *dot = strrchr(dot_buf, '.');
          if (dot)
            *dot = '\0';
          snprintf(out_path, sizeof(out_path), "%s_stego.%s", dot_buf,
                   inspect_img->target_fmt == STEGO_FORMAT_BMP ? "bmp" : "png");
          SetDlgItemTextA(hwnd, IDC_EMBED_STEGO_EDIT, out_path);

          stego_image_free(inspect_img);
        } else {
          SetDlgItemTextA(hwnd, IDC_EMBED_COVER_INFO_LBL,
                          "[-] Invalid or unsupported image format.");
          SetDlgItemTextA(hwnd, IDC_EMBED_CONVERT_NOTE_LBL, "");
        }
      }
      return 0;
    }

    if (wmId == IDC_EMBED_STEGO_BROWSE) {
      char path[MAX_PATH] = {0};
      GetDlgItemTextA(hwnd, IDC_EMBED_STEGO_EDIT, path, MAX_PATH);
      if (browse_save_file(hwnd,
                           "PNG Stego Image (*.png)\0*.png\0BMP Stego Image "
                           "(*.bmp)\0*.bmp\0All Files (*.*)\0*.*\0",
                           "Save Stego Image As", "png", path, MAX_PATH)) {
        SetDlgItemTextA(hwnd, IDC_EMBED_STEGO_EDIT, path);
      }
      return 0;
    }

    if (wmId == IDC_EMBED_RADIO_TEXT || wmId == IDC_EMBED_RADIO_FILE) {
      bool is_text =
          (IsDlgButtonChecked(hwnd, IDC_EMBED_RADIO_TEXT) == BST_CHECKED);
      EnableWindow(GetDlgItem(hwnd, IDC_EMBED_TEXT_EDIT), is_text);
      EnableWindow(GetDlgItem(hwnd, IDC_EMBED_FILE_EDIT), !is_text);
      EnableWindow(GetDlgItem(hwnd, IDC_EMBED_FILE_BROWSE), !is_text);
      return 0;
    }

    if (wmId == IDC_EMBED_FILE_BROWSE) {
      char path[MAX_PATH] = {0};
      if (browse_open_file(
              hwnd,
              "All Secret Files (*.*)\0*.*\0Text Documents (*.txt)\0*.txt\0",
              "Select Secret File to Hide", path, MAX_PATH)) {
        SetDlgItemTextA(hwnd, IDC_EMBED_FILE_EDIT, path);
      }
      return 0;
    }

    if (wmId == IDC_EMBED_SHOW_PASS) {
      bool show =
          (IsDlgButtonChecked(hwnd, IDC_EMBED_SHOW_PASS) == BST_CHECKED);
      SendDlgItemMessage(hwnd, IDC_EMBED_PASS_EDIT, EM_SETPASSWORDCHAR,
                         show ? 0 : '*', 0);
      SendDlgItemMessage(hwnd, IDC_EMBED_CONFIRM_EDIT, EM_SETPASSWORDCHAR,
                         show ? 0 : '*', 0);
      InvalidateRect(GetDlgItem(hwnd, IDC_EMBED_PASS_EDIT), NULL, TRUE);
      InvalidateRect(GetDlgItem(hwnd, IDC_EMBED_CONFIRM_EDIT), NULL, TRUE);
      return 0;
    }

    if (wmId == IDC_EMBED_BTN_OPEN_DIR) {
      if (g_last_stego_output[0] && file_exists_local(g_last_stego_output)) {
        char param[MAX_PATH + 32];
        snprintf(param, sizeof(param), "/select,\"%s\"", g_last_stego_output);
        ShellExecuteA(NULL, "open", "explorer.exe", param, NULL, SW_SHOWNORMAL);
      }
      return 0;
    }

    if (wmId == IDC_EMBED_BTN_VERIFY) {
      if (g_last_stego_output[0]) {
        SetDlgItemTextA(g_hPages[2], IDC_VERIFY_IMAGE_EDIT,
                        g_last_stego_output);
        SwitchToTab(2);
        PostMessage(g_hPages[2], WM_COMMAND,
                    MAKEWPARAM(IDC_VERIFY_BTN_EXEC, BN_CLICKED),
                    (LPARAM)GetDlgItem(g_hPages[2], IDC_VERIFY_BTN_EXEC));
      }
      return 0;
    }

    if (wmId == IDC_EMBED_BTN_SWITCH_EXT) {
      if (g_last_stego_output[0]) {
        SetDlgItemTextA(g_hPages[1], IDC_EXTRACT_IMAGE_EDIT,
                        g_last_stego_output);
        SwitchToTab(1);
        PostMessage(g_hPages[1], WM_COMMAND,
                    MAKEWPARAM(IDC_EXTRACT_DETECT_BTN, BN_CLICKED), 0);
      }
      return 0;
    }

    if (wmId == IDC_EMBED_BTN_EXEC) {
      char cover_path[MAX_PATH] = {0};
      char stego_path[MAX_PATH] = {0};
      GetDlgItemTextA(hwnd, IDC_EMBED_COVER_EDIT, cover_path, MAX_PATH);
      GetDlgItemTextA(hwnd, IDC_EMBED_STEGO_EDIT, stego_path, MAX_PATH);

      if (!cover_path[0]) {
        MessageBoxA(hwnd, "Please specify a cover image.",
                    "Missing Cover Image", MB_ICONWARNING);
        SetFocus(GetDlgItem(hwnd, IDC_EMBED_COVER_EDIT));
        return 0;
      }

      if (!file_exists_local(cover_path)) {
        MessageBoxA(hwnd, "The specified cover image could not be found.",
                    "File Not Found", MB_ICONERROR);
        return 0;
      }

      /* Format validation */
      StegoImageFormat fmt = stego_detect_format(cover_path);
      if (fmt == STEGO_FORMAT_UNKNOWN || fmt == STEGO_FORMAT_HEIC) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "Selected cover image format (%s) is not supported for "
                 "embedding.\n\n"
                 "Supported input formats: PNG, BMP, JPEG, WebP, GIF, TGA.",
                 stego_format_name(fmt));
        MessageBoxA(hwnd, msg, "Unsupported Format", MB_ICONERROR);
        return 0;
      }

      if (!stego_path[0]) {
        MessageBoxA(hwnd, "Please specify an output stego image path.",
                    "Missing Output Path", MB_ICONWARNING);
        SetFocus(GetDlgItem(hwnd, IDC_EMBED_STEGO_EDIT));
        return 0;
      }

      /* Check output extension safety */
      const char *out_dot = strrchr(stego_path, '.');
      if (out_dot &&
          (_stricmp(out_dot, ".jpg") == 0 || _stricmp(out_dot, ".jpeg") == 0 ||
           _stricmp(out_dot, ".webp") == 0 || _stricmp(out_dot, ".gif") == 0)) {
        MessageBoxA(
            hwnd,
            "Unsafe output format! Saving steganographic data to lossy or "
            "animation formats (JPEG, WebP, GIF) will destroy payload bits.\n\n"
            "Please specify a .png (or .bmp) output file to safely preserve "
            "the stego payload.",
            "Unsafe Output Blocked", MB_ICONERROR);
        return 0;
      }

      /* Overwrite confirmation if destination exists */
      if (file_exists_local(stego_path)) {
        if (MessageBoxA(
                hwnd,
                "The output file already exists. Do you want to overwrite it?",
                "Confirm Overwrite", MB_YESNO | MB_ICONQUESTION) != IDYES) {
          return 0;
        }
      }

      bool is_text =
          (IsDlgButtonChecked(hwnd, IDC_EMBED_RADIO_TEXT) == BST_CHECKED);
      char secret_file[MAX_PATH] = {0};
      char temp_payload[MAX_PATH] = {0};

      if (is_text) {
        int txt_len =
            GetWindowTextLengthA(GetDlgItem(hwnd, IDC_EMBED_TEXT_EDIT));
        if (txt_len <= 0) {
          MessageBoxA(hwnd, "Please enter a secret message to embed.",
                      "Empty Payload", MB_ICONWARNING);
          SetFocus(GetDlgItem(hwnd, IDC_EMBED_TEXT_EDIT));
          return 0;
        }
        char *txt_buf = (char *)malloc(txt_len + 1);
        if (!txt_buf)
          return 0;
        GetDlgItemTextA(hwnd, IDC_EMBED_TEXT_EDIT, txt_buf, txt_len + 1);

        /* Write to temporary payload file */
        snprintf(temp_payload, MAX_PATH, "tmp_gui_embed_%u.tmp",
                 (unsigned int)GetTickCount());
        FILE *tfp = fopen(temp_payload, "wb");
        if (!tfp) {
          free(txt_buf);
          MessageBoxA(hwnd, "Unable to create temporary file for embedding.",
                      "Error", MB_ICONERROR);
          return 0;
        }
        fwrite(txt_buf, 1, txt_len, tfp);
        fclose(tfp);
        stego_secure_zero(txt_buf, txt_len);
        free(txt_buf);
      } else {
        GetDlgItemTextA(hwnd, IDC_EMBED_FILE_EDIT, secret_file, MAX_PATH);
        if (!secret_file[0] || !file_exists_local(secret_file)) {
          MessageBoxA(hwnd, "Please select an existing secret file to embed.",
                      "File Error", MB_ICONWARNING);
          return 0;
        }
      }

      /* Passphrase and confirmation check */
      char pass1[256] = {0};
      char pass2[256] = {0};
      GetDlgItemTextA(hwnd, IDC_EMBED_PASS_EDIT, pass1, sizeof(pass1));
      GetDlgItemTextA(hwnd, IDC_EMBED_CONFIRM_EDIT, pass2, sizeof(pass2));

      if (pass1[0] != '\0' || pass2[0] != '\0') {
        if (strcmp(pass1, pass2) != 0) {
          MessageBoxA(hwnd,
                      "Passphrases do not match. Please re-enter carefully.",
                      "Passphrase Mismatch", MB_ICONERROR);
          stego_secure_zero(pass1, sizeof(pass1));
          stego_secure_zero(pass2, sizeof(pass2));
          SetDlgItemTextA(hwnd, IDC_EMBED_PASS_EDIT, "");
          SetDlgItemTextA(hwnd, IDC_EMBED_CONFIRM_EDIT, "");
          SetFocus(GetDlgItem(hwnd, IDC_EMBED_PASS_EDIT));
          if (temp_payload[0])
            stego_secure_delete_file(temp_payload);
          return 0;
        }
      }
      stego_secure_zero(pass2, sizeof(pass2));

      bool adaptive =
          (IsDlgButtonChecked(hwnd, IDC_EMBED_CHK_ADAPTIVE) == BST_CHECKED);

      /* Capacity Pre-Validation */
      StegoCarrier *carrier = NULL;
      StegoResult cres = stego_carrier_open(cover_path, adaptive, &carrier);
      if (cres == STEGO_OK) {
        size_t raw_cap =
            carrier->max_capacity(carrier) + STEGO_CMC1_HEADER_SIZE;
        size_t overhead = (pass1[0] != '\0') ? STEGO_CMC2_HEADER_SIZE
                                             : STEGO_CMC1_HEADER_SIZE;
        size_t usable_cap = (raw_cap > overhead) ? (raw_cap - overhead) : 0;

        size_t needed_len = 0;
        if (is_text) {
          needed_len =
              GetWindowTextLengthA(GetDlgItem(hwnd, IDC_EMBED_TEXT_EDIT));
        } else {
          FILE *fp = fopen(secret_file, "rb");
          if (fp) {
            fseek(fp, 0, SEEK_END);
            needed_len = (size_t)ftell(fp);
            fclose(fp);
          }
        }

        if (needed_len > usable_cap) {
          char cap_msg[384];
          snprintf(
              cap_msg, sizeof(cap_msg),
              "Payload too large for carrier!\n\n"
              "Required Payload : %zu bytes (+ %zu byte %s envelope)\n"
              "Maximum Usable   : %zu bytes\n"
              "Total Raw Carrier: %zu bytes\n\n"
              "Please choose a larger cover image or smaller secret payload.",
              needed_len, overhead,
              (pass1[0] != '\0') ? "CMC2 Encrypted" : "CMC1 Unencrypted",
              usable_cap, raw_cap);
          stego_carrier_close(carrier);
          stego_secure_zero(pass1, sizeof(pass1));
          if (temp_payload[0])
            stego_secure_delete_file(temp_payload);
          MessageBoxA(hwnd, cap_msg, "Capacity Exceeded", MB_ICONERROR);
          return 0;
        }
        stego_carrier_close(carrier);
      }

      /* Launch worker thread */
      EmbedWorkerParams *params =
          (EmbedWorkerParams *)malloc(sizeof(EmbedWorkerParams));
      memset(params, 0, sizeof(EmbedWorkerParams));
      safe_strcpy(params->cover_path, sizeof(params->cover_path), cover_path);
      safe_strcpy(params->stego_path, sizeof(params->stego_path), stego_path);
      safe_strcpy(params->secret_file, sizeof(params->secret_file),
                  secret_file);
      safe_strcpy(params->temp_payload, sizeof(params->temp_payload),
                  temp_payload);
      params->is_text_mode = is_text;
      params->adaptive = adaptive;
      if (pass1[0] != '\0') {
        safe_strcpy(params->passphrase, sizeof(params->passphrase), pass1);
        params->has_passphrase = true;
      }
      stego_secure_zero(pass1, sizeof(pass1));

      /* Update UI to busy state */
      EnableWindow(GetDlgItem(hwnd, IDC_EMBED_BTN_EXEC), FALSE);
      g_embed_status_type = 3;
      SetDlgItemTextA(hwnd, IDC_EMBED_STATUS_LBL,
                      "Embedding in progress... Computing Argon2id key "
                      "derivation & AES-256-GCM...");
      SendMessage(g_hStatusBar, SB_SETTEXT, 0,
                  (LPARAM) "Embedding payload in background thread...");

      HANDLE hThread =
          CreateThread(NULL, 0, EmbedWorkerThread, params, 0, NULL);
      if (hThread)
        CloseHandle(hThread);
      return 0;
    }
    break;
  }
  }
  return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

/* ========================================================================= */
/* Page 1: Extract Secret                                                    */
/* ========================================================================= */
static LRESULT CALLBACK ExtractPageProc(HWND hwnd, UINT uMsg, WPARAM wParam,
                                        LPARAM lParam) {
  switch (uMsg) {
  case WM_CTLCOLORSTATIC: {
    HDC hdc = (HDC)wParam;
    HWND hCtl = (HWND)lParam;
    int ctlId = GetDlgCtrlID(hCtl);
    if (ctlId == IDC_EXTRACT_STATUS_LBL) {
      if (g_extract_status_type == 1)
        SetTextColor(hdc, g_colSuccess);
      else if (g_extract_status_type == 2)
        SetTextColor(hdc, g_colError);
      else if (g_extract_status_type == 3)
        SetTextColor(hdc, g_colWarning);
      SetBkMode(hdc, TRANSPARENT);
      return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
    }
    if (ctlId == IDC_EXTRACT_DETECT_LBL) {
      SetBkMode(hdc, TRANSPARENT);
      return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
    }
    break;
  }

  case WM_COMMAND: {
    int wmId = LOWORD(wParam);

    if (wmId == IDC_EXTRACT_IMAGE_BROWSE) {
      char path[MAX_PATH] = {0};
      if (browse_open_file(hwnd,
                           "Stego Images (*.bmp;*.png)\0*.bmp;*.png\0BMP "
                           "Images (*.bmp)\0*.bmp\0PNG Images "
                           "(*.png)\0*.png\0All Files (*.*)\0*.*\0",
                           "Select Stego Image", path, MAX_PATH)) {
        SetDlgItemTextA(hwnd, IDC_EXTRACT_IMAGE_EDIT, path);
        PostMessage(hwnd, WM_COMMAND,
                    MAKEWPARAM(IDC_EXTRACT_DETECT_BTN, BN_CLICKED), 0);
      }
      return 0;
    }

    if (wmId == IDC_EXTRACT_DETECT_BTN) {
      char path[MAX_PATH] = {0};
      GetDlgItemTextA(hwnd, IDC_EXTRACT_IMAGE_EDIT, path, MAX_PATH);
      if (!path[0] || !file_exists_local(path)) {
        SetDlgItemTextA(hwnd, IDC_EXTRACT_DETECT_LBL,
                        "Please select an existing stego image.");
        return 0;
      }

      bool adaptive =
          (IsDlgButtonChecked(hwnd, IDC_EXTRACT_CHK_ADAPTIVE) == BST_CHECKED);
      StegoCarrier *carrier = NULL;
      StegoResult res = stego_carrier_open(path, adaptive, &carrier);
      if (res != STEGO_OK) {
        SetDlgItemTextA(hwnd, IDC_EXTRACT_DETECT_LBL,
                        "[-] Error opening image file.");
        return 0;
      }

      uint32_t payload_len = 0;
      StegoEnvelopeType env =
          carrier->detect_envelope
              ? carrier->detect_envelope(carrier, &payload_len)
              : STEGO_ENVELOPE_NONE;
      stego_carrier_close(carrier);

      if (env == STEGO_ENVELOPE_CMC2) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "[+] CMC2 Encrypted Payload Detected (%u bytes payload, "
                 "Argon2id + AES-256-GCM) - Passphrase required",
                 payload_len);
        SetDlgItemTextA(hwnd, IDC_EXTRACT_DETECT_LBL, msg);
        SetFocus(GetDlgItem(hwnd, IDC_EXTRACT_PASS_EDIT));
      } else if (env == STEGO_ENVELOPE_CMC1) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "[!] CMC1 Unencrypted Payload Detected (%u bytes plaintext) - "
                 "No passphrase required",
                 payload_len);
        SetDlgItemTextA(hwnd, IDC_EXTRACT_DETECT_LBL, msg);
      } else {
        SetDlgItemTextA(
            hwnd, IDC_EXTRACT_DETECT_LBL,
            "[-] No valid steganographic envelope detected in this image.");
      }
      return 0;
    }

    if (wmId == IDC_EXTRACT_FILE_BROWSE) {
      char path[MAX_PATH] = {0};
      GetDlgItemTextA(hwnd, IDC_EXTRACT_FILE_EDIT, path, MAX_PATH);
      if (browse_save_file(
              hwnd, "All Files (*.*)\0*.*\0Text Files (*.txt)\0*.txt\0",
              "Save Extracted Payload To", "txt", path, MAX_PATH)) {
        SetDlgItemTextA(hwnd, IDC_EXTRACT_FILE_EDIT, path);
      }
      return 0;
    }

    if (wmId == IDC_EXTRACT_SHOW_PASS) {
      bool show =
          (IsDlgButtonChecked(hwnd, IDC_EXTRACT_SHOW_PASS) == BST_CHECKED);
      SendDlgItemMessage(hwnd, IDC_EXTRACT_PASS_EDIT, EM_SETPASSWORDCHAR,
                         show ? 0 : '*', 0);
      InvalidateRect(GetDlgItem(hwnd, IDC_EXTRACT_PASS_EDIT), NULL, TRUE);
      return 0;
    }

    if (wmId == IDC_EXTRACT_BTN_EXEC) {
      char stego_path[MAX_PATH] = {0};
      char out_path[MAX_PATH] = {0};
      char pass[256] = {0};

      GetDlgItemTextA(hwnd, IDC_EXTRACT_IMAGE_EDIT, stego_path, MAX_PATH);
      GetDlgItemTextA(hwnd, IDC_EXTRACT_FILE_EDIT, out_path, MAX_PATH);
      GetDlgItemTextA(hwnd, IDC_EXTRACT_PASS_EDIT, pass, sizeof(pass));

      if (!stego_path[0] || !file_exists_local(stego_path)) {
        MessageBoxA(hwnd, "Please select an existing stego image.",
                    "Missing Input Image", MB_ICONWARNING);
        return 0;
      }

      bool adaptive =
          (IsDlgButtonChecked(hwnd, IDC_EXTRACT_CHK_ADAPTIVE) == BST_CHECKED);

      /* Launch worker thread */
      ExtractWorkerParams *params =
          (ExtractWorkerParams *)malloc(sizeof(ExtractWorkerParams));
      memset(params, 0, sizeof(ExtractWorkerParams));
      safe_strcpy(params->stego_path, sizeof(params->stego_path), stego_path);
      safe_strcpy(params->output_path, sizeof(params->output_path), out_path);
      params->adaptive = adaptive;
      if (pass[0] != '\0') {
        safe_strcpy(params->passphrase, sizeof(params->passphrase), pass);
        params->has_passphrase = true;
      }
      stego_secure_zero(pass, sizeof(pass));

      EnableWindow(GetDlgItem(hwnd, IDC_EXTRACT_BTN_EXEC), FALSE);
      g_extract_status_type = 3;
      SetDlgItemTextA(hwnd, IDC_EXTRACT_STATUS_LBL,
                      "Extracting payload... Verifying envelope & "
                      "cryptographic authentication...");
      SetDlgItemTextA(hwnd, IDC_EXTRACT_RESULT_EDIT, "");
      SendMessage(g_hStatusBar, SB_SETTEXT, 0,
                  (LPARAM) "Extracting secret in background thread...");

      HANDLE hThread =
          CreateThread(NULL, 0, ExtractWorkerThread, params, 0, NULL);
      if (hThread)
        CloseHandle(hThread);
      return 0;
    }
    break;
  }
  }
  return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

/* ========================================================================= */
/* Page 2: Verify Image                                                      */
/* ========================================================================= */
static LRESULT CALLBACK VerifyPageProc(HWND hwnd, UINT uMsg, WPARAM wParam,
                                       LPARAM lParam) {
  switch (uMsg) {
  case WM_CTLCOLORSTATIC: {
    HDC hdc = (HDC)wParam;
    HWND hCtl = (HWND)lParam;
    int ctlId = GetDlgCtrlID(hCtl);
    if (ctlId == IDC_VERIFY_STATUS_LBL) {
      if (g_verify_status_type == 1)
        SetTextColor(hdc, g_colSuccess);
      else if (g_verify_status_type == 2)
        SetTextColor(hdc, g_colError);
      else if (g_verify_status_type == 3)
        SetTextColor(hdc, g_colWarning);
      SetBkMode(hdc, TRANSPARENT);
      return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
    }
    break;
  }

  case WM_COMMAND: {
    int wmId = LOWORD(wParam);

    if (wmId == IDC_VERIFY_IMAGE_BROWSE) {
      char path[MAX_PATH] = {0};
      if (browse_open_file(hwnd,
                           "Supported Images "
                           "(*.png;*.bmp;*.jpg;*.jpeg;*.webp;*.gif;*.tga)\0*."
                           "png;*.bmp;*.jpg;*.jpeg;*.webp;*.gif;*.tga\0"
                           "All Files (*.*)\0*.*\0",
                           "Select Image to Verify", path, MAX_PATH)) {
        SetDlgItemTextA(hwnd, IDC_VERIFY_IMAGE_EDIT, path);
      }
      return 0;
    }

    if (wmId == IDC_VERIFY_BTN_EXEC) {
      char path[MAX_PATH] = {0};
      GetDlgItemTextA(hwnd, IDC_VERIFY_IMAGE_EDIT, path, MAX_PATH);
      if (!path[0] || !file_exists_local(path)) {
        MessageBoxA(hwnd, "Please select an existing image to verify.",
                    "Missing Image", MB_ICONWARNING);
        return 0;
      }

      bool adaptive =
          (IsDlgButtonChecked(hwnd, IDC_VERIFY_CHK_ADAPTIVE) == BST_CHECKED);
      StegoCarrier *carrier = NULL;
      StegoResult res = stego_carrier_open(path, adaptive, &carrier);
      if (res != STEGO_OK) {
        g_verify_status_type = 2;
        SetDlgItemTextA(hwnd, IDC_VERIFY_STATUS_LBL,
                        "[-] Error: Failed to open carrier image.");
        SetDlgItemTextA(hwnd, IDC_VERIFY_DETAILS_EDIT, stego_strerror(res));
        return 0;
      }

      uint32_t payload_len = 0;
      StegoEnvelopeType env =
          carrier->detect_envelope
              ? carrier->detect_envelope(carrier, &payload_len)
              : STEGO_ENVELOPE_NONE;
      stego_carrier_close(carrier);

      char details[1024];
      if (env == STEGO_ENVELOPE_CMC2) {
        g_verify_status_type = 1;
        SetDlgItemTextA(hwnd, IDC_VERIFY_STATUS_LBL,
                        "[+] VALID ENVELOPE: Steganographic payload verified "
                        "(CMC2 Encrypted)");
        snprintf(
            details, sizeof(details),
            "STATUS: VALID STEGANOGRAPHIC PAYLOAD DETECTED\r\n\r\n"
            "• Envelope Type : CMC2 Authenticated Encrypted Envelope\r\n"
            "• Payload Size  : %u bytes\r\n"
            "• Header Size   : 52 bytes\r\n"
            "• Key Derivation: Argon2id (Memory-hard passphrase derivation)\r\n"
            "• Encryption    : AES-256-GCM (Galois/Counter Mode with 128-bit "
            "authentication tag)\r\n"
            "• Integrity     : Authenticated AAD (Header + Salt + Nonce) & "
            "Ciphertext\r\n\r\n"
            "[+] SECURITY SUMMARY: Strong encryption and authentication are "
            "active.\r\n"
            "Unauthorized extraction without the secret passphrase is "
            "mathematically infeasible.",
            payload_len);
      } else if (env == STEGO_ENVELOPE_CMC1) {
        g_verify_status_type = 3;
        SetDlgItemTextA(hwnd, IDC_VERIFY_STATUS_LBL,
                        "[!] VALID ENVELOPE: Steganographic payload verified "
                        "(CMC1 Unencrypted)");
        snprintf(
            details, sizeof(details),
            "STATUS: UNENCRYPTED STEGANOGRAPHIC PAYLOAD DETECTED\r\n\r\n"
            "• Envelope Type : CMC1 Plaintext Header\r\n"
            "• Payload Size  : %u bytes\r\n"
            "• Header Size   : 8 bytes\r\n"
            "• Encryption    : NONE (Plaintext)\r\n\r\n"
            "=================================================================="
            "====\r\n"
            " [!] CRITICAL PRIVACY & SECURITY WARNING:\r\n"
            "=================================================================="
            "====\r\n"
            "This payload is stored WITHOUT encryption or passphrase "
            "protection.\r\n"
            "Any person or automated inspection tool capable of reading "
            "standard\r\n"
            "steganography can instantly recover and read the secret in "
            "plaintext.\r\n"
            "To protect sensitive data, embed with a strong passphrase (CMC2).",
            payload_len);
      } else {
        g_verify_status_type = 2;
        SetDlgItemTextA(hwnd, IDC_VERIFY_STATUS_LBL,
                        "[-] NO PAYLOAD: Image does not contain a recognized "
                        "stego envelope.");
        snprintf(details, sizeof(details),
                 "STATUS: NO RECOGNIZED STEGANOGRAPHIC PAYLOAD\r\n\r\n"
                 "• Detected Format: Verified image\r\n"
                 "• CMC1 Envelope : Not detected\r\n"
                 "• CMC2 Envelope : Not detected\r\n\r\n"
                 "This image either contains no hidden data, uses a different "
                 "embedding\r\n"
                 "mode (e.g. Adaptive vs Standard LSB), or has had its stego "
                 "bits altered.");
      }
      SetDlgItemTextA(hwnd, IDC_VERIFY_DETAILS_EDIT, details);
      InvalidateRect(GetDlgItem(hwnd, IDC_VERIFY_STATUS_LBL), NULL, TRUE);
      return 0;
    }
    break;
  }
  }
  return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

/* ========================================================================= */
/* Page 3: Capacity / Info                                                   */
/* ========================================================================= */
static LRESULT CALLBACK InfoPageProc(HWND hwnd, UINT uMsg, WPARAM wParam,
                                     LPARAM lParam) {
  switch (uMsg) {
  case WM_COMMAND: {
    int wmId = LOWORD(wParam);

    if (wmId == IDC_INFO_IMAGE_BROWSE) {
      char path[MAX_PATH] = {0};
      if (browse_open_file(hwnd,
                           "Supported Images "
                           "(*.png;*.bmp;*.jpg;*.jpeg;*.webp;*.gif;*.tga)\0*."
                           "png;*.bmp;*.jpg;*.jpeg;*.webp;*.gif;*.tga\0"
                           "All Files (*.*)\0*.*\0",
                           "Select Image to Analyze", path, MAX_PATH)) {
        SetDlgItemTextA(hwnd, IDC_INFO_IMAGE_EDIT, path);
      }
      return 0;
    }

    if (wmId == IDC_INFO_BTN_EXEC) {
      char path[MAX_PATH] = {0};
      GetDlgItemTextA(hwnd, IDC_INFO_IMAGE_EDIT, path, MAX_PATH);
      if (!path[0] || !file_exists_local(path)) {
        MessageBoxA(hwnd, "Please select an existing image file.",
                    "Missing Image", MB_ICONWARNING);
        return 0;
      }

      StegoImageFormat fmt = stego_detect_format(path);
      bool adaptive =
          (IsDlgButtonChecked(hwnd, IDC_INFO_CHK_ADAPTIVE) == BST_CHECKED);

      StegoCarrier *carrier = NULL;
      StegoResult res = stego_carrier_open(path, adaptive, &carrier);
      if (res != STEGO_OK) {
        char err[256];
        snprintf(err, sizeof(err), "Error opening image carrier: %s",
                 stego_strerror(res));
        SetDlgItemTextA(hwnd, IDC_INFO_DETAILS_EDIT, err);
        return 0;
      }

      size_t raw_cap = carrier->max_capacity(carrier) + STEGO_CMC1_HEADER_SIZE;
      size_t cap_cmc1 = (raw_cap > STEGO_CMC1_HEADER_SIZE)
                            ? (raw_cap - STEGO_CMC1_HEADER_SIZE)
                            : 0;
      size_t cap_cmc2 = (raw_cap > STEGO_CMC2_HEADER_SIZE)
                            ? (raw_cap - STEGO_CMC2_HEADER_SIZE)
                            : 0;

      uint32_t det_len = 0;
      StegoEnvelopeType env = carrier->detect_envelope
                                  ? carrier->detect_envelope(carrier, &det_len)
                                  : STEGO_ENVELOPE_NONE;

      char env_str[64];
      if (env != STEGO_ENVELOPE_NONE) {
        snprintf(env_str, sizeof(env_str), "%u bytes (%.2f KB)", det_len,
                 (double)det_len / 1024.0);
      } else {
        strncpy(env_str, "0 bytes (clean image)", sizeof(env_str));
      }

      char report[2048];
      snprintf(
          report, sizeof(report),
          "IMAGE PROPERTIES & STEGANOGRAPHIC CAPACITY REPORT\r\n"
          "===================================================================="
          "==\r\n"
          "Target Image Path: %s\r\n"
          "Detected Format  : %s (Verified by magic bytes)\r\n"
          "Original Mode    : %s (%d-bit per channel)\r\n"
          "Normalized Mode  : 8-bit %s (%u channels)\r\n"
          "Conversion Status: %s\r\n"
          "Final Stego Output: %s\r\n"
          "Dimensions       : %u x %u pixels\r\n"
          "Color Channels   : %u (%s)\r\n"
          "Usable Channels  : 3 (R, G, B used for LSB; %s)\r\n"
          "Embedding Mode   : %s\r\n\r\n"
          "CAPACITY SPECIFICATIONS:\r\n"
          "--------------------------------------------------------------------"
          "--\r\n"
          "• Total Raw Carrier Capacity : %zu bytes (%.2f KB) [%zu bits]\r\n"
          "• Usable CMC1 Unencrypted    : %zu bytes (%.2f KB) [Overhead: 8 "
          "bytes]\r\n"
          "• Usable CMC2 Encrypted      : %zu bytes (%.2f KB) [Overhead: 52 "
          "bytes (Argon2id + AES-GCM)]\r\n\r\n"
          "PAYLOAD STATUS:\r\n"
          "--------------------------------------------------------------------"
          "--\r\n"
          "• Existing Envelope Detected : %s\r\n"
          "• Embedded Payload Length    : %s\r\n"
          "===================================================================="
          "==",
          path, stego_format_name(fmt), carrier->image->orig_color_mode,
          carrier->image->orig_bit_depth,
          carrier->image->channels == 4 ? "RGBA" : "RGB",
          carrier->image->channels,
          carrier->image->was_converted
              ? "Converted to 8-bit RGB/RGBA (lossless PNG output required)"
              : "Native lossless carrier format",
          stego_format_name(carrier->image->target_fmt), carrier->image->width,
          carrier->image->height, carrier->image->channels,
          carrier->image->channels == 4 ? "RGBA (32-bit)" : "RGB (24-bit)",
          carrier->image->channels == 4 ? "Alpha transparency preserved"
                                        : "No alpha channel",
          adaptive ? "Adaptive Texture-based LSB (Edge/Variance guided)"
                   : "Standard Linear LSB",
          raw_cap, (double)raw_cap / 1024.0, raw_cap * 8, cap_cmc1,
          (double)cap_cmc1 / 1024.0, cap_cmc2, (double)cap_cmc2 / 1024.0,
          (env == STEGO_ENVELOPE_CMC2)
              ? "CMC2 Encrypted (Argon2id + AES-256-GCM)"
          : (env == STEGO_ENVELOPE_CMC1) ? "CMC1 Unencrypted (Plaintext)"
                                         : "None Detected",
          env_str);

      SetDlgItemTextA(hwnd, IDC_INFO_DETAILS_EDIT, report);
      stego_carrier_close(carrier);
      return 0;
    }
    break;
  }
  }
  return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

/* ========================================================================= */
/* Child Page Creation Helpers                                               */
/* ========================================================================= */
static void CreateEmbedPage(HWND hwndParent) {
  (void)hwndParent;
  WNDCLASSA wc = {0};
  wc.lpfnWndProc = EmbedPageProc;
  wc.hInstance = g_hInstance;
  wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
  wc.lpszClassName = "StegoEmbedPageClass";
  RegisterClassA(&wc);

  RECT rc;
  GetClientRect(g_hTab, &rc);
  TabCtrl_AdjustRect(g_hTab, FALSE, &rc);

  HWND hPage = CreateWindowExA(
      0, "StegoEmbedPageClass", "", WS_CHILD | WS_VISIBLE, rc.left, rc.top,
      rc.right - rc.left, rc.bottom - rc.top, g_hTab, NULL, g_hInstance, NULL);
  g_hPages[0] = hPage;

  /* Cover Image */
  CreateWindowExA(0, "STATIC", "Cover Image (PNG, BMP, JPEG, WebP, GIF, TGA):",
                  WS_CHILD | WS_VISIBLE, 15, 6, 380, 16, hPage, NULL,
                  g_hInstance, NULL);
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                  WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 15, 23, 560, 24,
                  hPage, (HMENU)IDC_EMBED_COVER_EDIT, g_hInstance, NULL);
  CreateWindowExA(0, "BUTTON", "Browse...",
                  WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 585, 22, 95, 26, hPage,
                  (HMENU)IDC_EMBED_COVER_BROWSE, g_hInstance, NULL);

  /* Dynamic Diagnostics Display */
  CreateWindowExA(0, "STATIC",
                  "Select any common image (PNG, BMP, JPEG, WebP, GIF, TGA) to "
                  "inspect format.",
                  WS_CHILD | WS_VISIBLE, 15, 50, 665, 16, hPage,
                  (HMENU)IDC_EMBED_COVER_INFO_LBL, g_hInstance, NULL);

  /* Output Stego Image */
  CreateWindowExA(0, "STATIC", "Output Stego Image Path (Lossless PNG or BMP):",
                  WS_CHILD | WS_VISIBLE, 15, 68, 380, 16, hPage, NULL,
                  g_hInstance, NULL);
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                  WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 15, 86, 560, 24,
                  hPage, (HMENU)IDC_EMBED_STEGO_EDIT, g_hInstance, NULL);
  CreateWindowExA(0, "BUTTON", "Browse...",
                  WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 585, 85, 95, 26, hPage,
                  (HMENU)IDC_EMBED_STEGO_BROWSE, g_hInstance, NULL);

  /* Format Conversion Notice */
  CreateWindowExA(0, "STATIC", "", WS_CHILD | WS_VISIBLE, 15, 112, 665, 16,
                  hPage, (HMENU)IDC_EMBED_CONVERT_NOTE_LBL, g_hInstance, NULL);

  /* Secret Payload Group */
  CreateWindowExA(0, "BUTTON", "Secret Payload",
                  WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 15, 115, 665, 140, hPage,
                  NULL, g_hInstance, NULL);
  CreateWindowExA(0, "BUTTON", "Text Message",
                  WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP, 30,
                  135, 120, 20, hPage, (HMENU)IDC_EMBED_RADIO_TEXT, g_hInstance,
                  NULL);
  CreateWindowExA(0, "BUTTON", "Secret File",
                  WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON, 170, 135, 120, 20,
                  hPage, (HMENU)IDC_EMBED_RADIO_FILE, g_hInstance, NULL);
  CheckDlgButton(hPage, IDC_EMBED_RADIO_TEXT, BST_CHECKED);

  CreateWindowExA(
      WS_EX_CLIENTEDGE, "EDIT", "",
      WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL, 30,
      160, 635, 85, hPage, (HMENU)IDC_EMBED_TEXT_EDIT, g_hInstance, NULL);
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | ES_AUTOHSCROLL, 30,
                  160, 525, 24, hPage, (HMENU)IDC_EMBED_FILE_EDIT, g_hInstance,
                  NULL);
  CreateWindowExA(0, "BUTTON", "Browse File...", WS_CHILD | BS_PUSHBUTTON, 565,
                  159, 100, 26, hPage, (HMENU)IDC_EMBED_FILE_BROWSE,
                  g_hInstance, NULL);

  /* Security & Passphrase Group */
  CreateWindowExA(0, "BUTTON", "Security & Passphrase Protection (Optional)",
                  WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 15, 265, 665, 95, hPage,
                  NULL, g_hInstance, NULL);
  CreateWindowExA(0, "STATIC", "Passphrase (leave blank for CMC1 unencrypted):",
                  WS_CHILD | WS_VISIBLE, 30, 285, 270, 18, hPage, NULL,
                  g_hInstance, NULL);
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                  WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL, 30, 303,
                  230, 24, hPage, (HMENU)IDC_EMBED_PASS_EDIT, g_hInstance,
                  NULL);

  CreateWindowExA(0, "STATIC", "Confirm Passphrase:", WS_CHILD | WS_VISIBLE,
                  280, 285, 200, 18, hPage, NULL, g_hInstance, NULL);
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                  WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL, 280,
                  303, 230, 24, hPage, (HMENU)IDC_EMBED_CONFIRM_EDIT,
                  g_hInstance, NULL);

  CreateWindowExA(0, "BUTTON", "Show Passphrase",
                  WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 530, 304, 130, 22,
                  hPage, (HMENU)IDC_EMBED_SHOW_PASS, g_hInstance, NULL);
  CreateWindowExA(0, "STATIC",
                  "• Providing a passphrase generates an Argon2id key and "
                  "embeds via AES-256-GCM (CMC2 Authenticated Envelope).",
                  WS_CHILD | WS_VISIBLE, 30, 335, 635, 18, hPage, NULL,
                  g_hInstance, NULL);

  /* Options & Embed Button */
  CreateWindowExA(
      0, "BUTTON",
      "Enable Adaptive Texture-based LSB embedding (PNG carriers only)",
      WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 20, 370, 420, 22, hPage,
      (HMENU)IDC_EMBED_CHK_ADAPTIVE, g_hInstance, NULL);

  CreateWindowExA(0, "BUTTON", "Embed Secret Payload",
                  WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 460, 366, 220, 34,
                  hPage, (HMENU)IDC_EMBED_BTN_EXEC, g_hInstance, NULL);

  /* Result Status */
  CreateWindowExA(0, "STATIC", "Ready.", WS_CHILD | WS_VISIBLE, 20, 410, 660,
                  42, hPage, (HMENU)IDC_EMBED_STATUS_LBL, g_hInstance, NULL);

  /* Quick Action Buttons */
  CreateWindowExA(0, "BUTTON", "Open Output Folder",
                  WS_CHILD | WS_VISIBLE | WS_DISABLED | BS_PUSHBUTTON, 20, 460,
                  160, 28, hPage, (HMENU)IDC_EMBED_BTN_OPEN_DIR, g_hInstance,
                  NULL);
  CreateWindowExA(0, "BUTTON", "Verify Stego Image",
                  WS_CHILD | WS_VISIBLE | WS_DISABLED | BS_PUSHBUTTON, 190, 460,
                  160, 28, hPage, (HMENU)IDC_EMBED_BTN_VERIFY, g_hInstance,
                  NULL);
  CreateWindowExA(0, "BUTTON", "Switch to Extraction",
                  WS_CHILD | WS_VISIBLE | WS_DISABLED | BS_PUSHBUTTON, 360, 460,
                  160, 28, hPage, (HMENU)IDC_EMBED_BTN_SWITCH_EXT, g_hInstance,
                  NULL);

  apply_font_to_children(hPage, g_hFontNormal);
  SendMessage(GetDlgItem(hPage, IDC_EMBED_BTN_EXEC), WM_SETFONT,
              (WPARAM)g_hFontBold, TRUE);
}

static void CreateExtractPage(HWND hwndParent) {
  (void)hwndParent;
  WNDCLASSA wc = {0};
  wc.lpfnWndProc = ExtractPageProc;
  wc.hInstance = g_hInstance;
  wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
  wc.lpszClassName = "StegoExtractPageClass";
  RegisterClassA(&wc);

  RECT rc;
  GetClientRect(g_hTab, &rc);
  TabCtrl_AdjustRect(g_hTab, FALSE, &rc);

  HWND hPage = CreateWindowExA(
      0, "StegoExtractPageClass", "", WS_CHILD, rc.left, rc.top,
      rc.right - rc.left, rc.bottom - rc.top, g_hTab, NULL, g_hInstance, NULL);
  g_hPages[1] = hPage;

  /* Stego Image */
  CreateWindowExA(0, "STATIC",
                  "Stego Image (BMP or PNG):", WS_CHILD | WS_VISIBLE, 15, 10,
                  300, 18, hPage, NULL, g_hInstance, NULL);
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                  WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 15, 30, 460, 24,
                  hPage, (HMENU)IDC_EXTRACT_IMAGE_EDIT, g_hInstance, NULL);
  CreateWindowExA(0, "BUTTON", "Browse...",
                  WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 485, 29, 90, 26, hPage,
                  (HMENU)IDC_EXTRACT_IMAGE_BROWSE, g_hInstance, NULL);
  CreateWindowExA(0, "BUTTON", "Inspect Header",
                  WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 585, 29, 95, 26, hPage,
                  (HMENU)IDC_EXTRACT_DETECT_BTN, g_hInstance, NULL);

  /* Detection Header Banner */
  CreateWindowExA(
      0, "STATIC",
      "Select a stego image to inspect envelope and encryption status.",
      WS_CHILD | WS_VISIBLE, 15, 60, 665, 22, hPage,
      (HMENU)IDC_EXTRACT_DETECT_LBL, g_hInstance, NULL);

  /* Passphrase Group */
  CreateWindowExA(0, "BUTTON", "Decryption Passphrase",
                  WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 15, 85, 665, 68, hPage,
                  NULL, g_hInstance, NULL);
  CreateWindowExA(
      0, "STATIC", "Passphrase (leave empty if envelope is CMC1 Unencrypted):",
      WS_CHILD | WS_VISIBLE, 30, 103, 380, 18, hPage, NULL, g_hInstance, NULL);
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                  WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL, 30, 122,
                  490, 24, hPage, (HMENU)IDC_EXTRACT_PASS_EDIT, g_hInstance,
                  NULL);
  CreateWindowExA(0, "BUTTON", "Show Passphrase",
                  WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 535, 123, 130, 22,
                  hPage, (HMENU)IDC_EXTRACT_SHOW_PASS, g_hInstance, NULL);

  /* Destination Output File */
  CreateWindowExA(0, "STATIC",
                  "Save Extracted Payload to File (optional - text will be "
                  "displayed below):",
                  WS_CHILD | WS_VISIBLE, 15, 162, 500, 18, hPage, NULL,
                  g_hInstance, NULL);
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                  WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 15, 182, 560, 24,
                  hPage, (HMENU)IDC_EXTRACT_FILE_EDIT, g_hInstance, NULL);
  CreateWindowExA(0, "BUTTON", "Browse...",
                  WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 585, 181, 95, 26,
                  hPage, (HMENU)IDC_EXTRACT_FILE_BROWSE, g_hInstance, NULL);

  /* Adaptive Checkbox & Extract Button */
  CreateWindowExA(0, "BUTTON", "Use Adaptive Texture-based LSB decoding",
                  WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 20, 218, 320, 22,
                  hPage, (HMENU)IDC_EXTRACT_CHK_ADAPTIVE, g_hInstance, NULL);
  CreateWindowExA(0, "BUTTON", "Extract Secret Payload",
                  WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 460, 214, 220, 32,
                  hPage, (HMENU)IDC_EXTRACT_BTN_EXEC, g_hInstance, NULL);

  /* Status Label */
  CreateWindowExA(0, "STATIC", "Ready.", WS_CHILD | WS_VISIBLE, 20, 252, 660,
                  22, hPage, (HMENU)IDC_EXTRACT_STATUS_LBL, g_hInstance, NULL);

  /* Extracted Text Box */
  CreateWindowExA(0, "STATIC", "Extracted Secret Content (Text / ASCII):",
                  WS_CHILD | WS_VISIBLE, 15, 278, 300, 18, hPage, NULL,
                  g_hInstance, NULL);
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                  WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
                      ES_AUTOVSCROLL | WS_VSCROLL | WS_HSCROLL,
                  15, 298, 665, 190, hPage, (HMENU)IDC_EXTRACT_RESULT_EDIT,
                  g_hInstance, NULL);

  apply_font_to_children(hPage, g_hFontNormal);
  SendMessage(GetDlgItem(hPage, IDC_EXTRACT_BTN_EXEC), WM_SETFONT,
              (WPARAM)g_hFontBold, TRUE);
  SendMessage(GetDlgItem(hPage, IDC_EXTRACT_RESULT_EDIT), WM_SETFONT,
              (WPARAM)g_hFontMono, TRUE);
}

static void CreateVerifyPage(HWND hwndParent) {
  (void)hwndParent;
  WNDCLASSA wc = {0};
  wc.lpfnWndProc = VerifyPageProc;
  wc.hInstance = g_hInstance;
  wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
  wc.lpszClassName = "StegoVerifyPageClass";
  RegisterClassA(&wc);

  RECT rc;
  GetClientRect(g_hTab, &rc);
  TabCtrl_AdjustRect(g_hTab, FALSE, &rc);

  HWND hPage = CreateWindowExA(0, "StegoVerifyPageClass", "", WS_CHILD, rc.left,
                               rc.top, rc.right - rc.left, rc.bottom - rc.top,
                               g_hTab, NULL, g_hInstance, NULL);
  g_hPages[2] = hPage;

  CreateWindowExA(0, "STATIC", "Select Image to Verify:", WS_CHILD | WS_VISIBLE,
                  15, 12, 300, 18, hPage, NULL, g_hInstance, NULL);
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                  WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 15, 32, 560, 24,
                  hPage, (HMENU)IDC_VERIFY_IMAGE_EDIT, g_hInstance, NULL);
  CreateWindowExA(0, "BUTTON", "Browse...",
                  WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 585, 31, 95, 26, hPage,
                  (HMENU)IDC_VERIFY_IMAGE_BROWSE, g_hInstance, NULL);

  CreateWindowExA(0, "BUTTON", "Check using Adaptive Texture-based LSB mode",
                  WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 20, 68, 350, 22,
                  hPage, (HMENU)IDC_VERIFY_CHK_ADAPTIVE, g_hInstance, NULL);

  CreateWindowExA(0, "BUTTON", "Verify Stego Envelope",
                  WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 460, 64, 220, 32,
                  hPage, (HMENU)IDC_VERIFY_BTN_EXEC, g_hInstance, NULL);

  CreateWindowExA(0, "STATIC", "Ready.", WS_CHILD | WS_VISIBLE, 20, 106, 660,
                  24, hPage, (HMENU)IDC_VERIFY_STATUS_LBL, g_hInstance, NULL);

  CreateWindowExA(0, "BUTTON", "Verification & Integrity Report",
                  WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 15, 135, 665, 355, hPage,
                  NULL, g_hInstance, NULL);

  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                  WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
                      ES_AUTOVSCROLL | WS_VSCROLL,
                  30, 160, 635, 315, hPage, (HMENU)IDC_VERIFY_DETAILS_EDIT,
                  g_hInstance, NULL);

  apply_font_to_children(hPage, g_hFontNormal);
  SendMessage(GetDlgItem(hPage, IDC_VERIFY_BTN_EXEC), WM_SETFONT,
              (WPARAM)g_hFontBold, TRUE);
  SendMessage(GetDlgItem(hPage, IDC_VERIFY_STATUS_LBL), WM_SETFONT,
              (WPARAM)g_hFontBold, TRUE);
  SendMessage(GetDlgItem(hPage, IDC_VERIFY_DETAILS_EDIT), WM_SETFONT,
              (WPARAM)g_hFontMono, TRUE);
}

static void CreateInfoPage(HWND hwndParent) {
  (void)hwndParent;
  WNDCLASSA wc = {0};
  wc.lpfnWndProc = InfoPageProc;
  wc.hInstance = g_hInstance;
  wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
  wc.lpszClassName = "StegoInfoPageClass";
  RegisterClassA(&wc);

  RECT rc;
  GetClientRect(g_hTab, &rc);
  TabCtrl_AdjustRect(g_hTab, FALSE, &rc);

  HWND hPage = CreateWindowExA(0, "StegoInfoPageClass", "", WS_CHILD, rc.left,
                               rc.top, rc.right - rc.left, rc.bottom - rc.top,
                               g_hTab, NULL, g_hInstance, NULL);
  g_hPages[3] = hPage;

  CreateWindowExA(0, "STATIC",
                  "Select Image to Analyze:", WS_CHILD | WS_VISIBLE, 15, 12,
                  300, 18, hPage, NULL, g_hInstance, NULL);
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                  WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 15, 32, 560, 24,
                  hPage, (HMENU)IDC_INFO_IMAGE_EDIT, g_hInstance, NULL);
  CreateWindowExA(0, "BUTTON", "Browse...",
                  WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 585, 31, 95, 26, hPage,
                  (HMENU)IDC_INFO_IMAGE_BROWSE, g_hInstance, NULL);

  CreateWindowExA(0, "BUTTON", "Analyze with Adaptive Texture LSB (PNG)",
                  WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 20, 68, 350, 22,
                  hPage, (HMENU)IDC_INFO_CHK_ADAPTIVE, g_hInstance, NULL);

  CreateWindowExA(0, "BUTTON", "Inspect Image Capacity",
                  WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 460, 64, 220, 32,
                  hPage, (HMENU)IDC_INFO_BTN_EXEC, g_hInstance, NULL);

  CreateWindowExA(0, "BUTTON", "Detailed Image & Steganography Capacity Report",
                  WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 15, 110, 665, 380, hPage,
                  NULL, g_hInstance, NULL);

  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                  WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
                      ES_AUTOVSCROLL | WS_VSCROLL,
                  30, 135, 635, 340, hPage, (HMENU)IDC_INFO_DETAILS_EDIT,
                  g_hInstance, NULL);

  apply_font_to_children(hPage, g_hFontNormal);
  SendMessage(GetDlgItem(hPage, IDC_INFO_BTN_EXEC), WM_SETFONT,
              (WPARAM)g_hFontBold, TRUE);
  SendMessage(GetDlgItem(hPage, IDC_INFO_DETAILS_EDIT), WM_SETFONT,
              (WPARAM)g_hFontMono, TRUE);
}

/* ========================================================================= */
/* Main Window Procedure                                                     */
/* ========================================================================= */
static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT uMsg, WPARAM wParam,
                                    LPARAM lParam) {
  switch (uMsg) {
  case WM_CREATE: {
    g_hMainWnd = hwnd;

    /* Create Tab Control */
    g_hTab = CreateWindowExA(
        0, WC_TABCONTROLA, "", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS, 10, 10,
        715, 545, hwnd, (HMENU)IDC_MAIN_TAB, g_hInstance, NULL);
    SendMessage(g_hTab, WM_SETFONT, (WPARAM)g_hFontBold, TRUE);

    TCITEMA tie;
    tie.mask = TCIF_TEXT;

    tie.pszText = (char *)"  Embed Secret  ";
    TabCtrl_InsertItem(g_hTab, 0, &tie);

    tie.pszText = (char *)"  Extract Secret  ";
    TabCtrl_InsertItem(g_hTab, 1, &tie);

    tie.pszText = (char *)"  Verify Image  ";
    TabCtrl_InsertItem(g_hTab, 2, &tie);

    tie.pszText = (char *)"  Capacity / Info  ";
    TabCtrl_InsertItem(g_hTab, 3, &tie);

    /* Create Child Pages */
    CreateEmbedPage(hwnd);
    CreateExtractPage(hwnd);
    CreateVerifyPage(hwnd);
    CreateInfoPage(hwnd);

    /* Create Status Bar */
    g_hStatusBar = CreateWindowExA(
        0, STATUSCLASSNAMEA, "", WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0,
        0, 0, hwnd, (HMENU)IDC_STATUS_BAR, g_hInstance, NULL);
    int parts[2] = {490, -1};
    SendMessage(g_hStatusBar, SB_SETPARTS, 2, (LPARAM)parts);
    SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM) "Ready");
    SendMessage(g_hStatusBar, SB_SETTEXT, 1,
                (LPARAM) "Engine: Argon2id + AES-256-GCM (Offline)");
    SendMessage(g_hStatusBar, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);

    SwitchToTab(0);
    return 0;
  }

  case WM_NOTIFY: {
    LPNMHDR pnm = (LPNMHDR)lParam;
    if (pnm->idFrom == IDC_MAIN_TAB && pnm->code == TCN_SELCHANGE) {
      int sel = TabCtrl_GetCurSel(g_hTab);
      SwitchToTab(sel);
    }
    break;
  }

  case WM_APP_EMBED_DONE: {
    EmbedWorkerResult *res = (EmbedWorkerResult *)lParam;
    HWND hEmbedPage = g_hPages[0];
    EnableWindow(GetDlgItem(hEmbedPage, IDC_EMBED_BTN_EXEC), TRUE);

    if (res->result == STEGO_OK) {
      g_embed_status_type = 1;
      safe_strcpy(g_last_stego_output, sizeof(g_last_stego_output),
                  res->stego_path);

      char status_msg[512];
      snprintf(status_msg, sizeof(status_msg),
               "[+] SUCCESS: Payload embedded and saved to '%s'!\r\n"
               "Mode: %s | Envelope: %s",
               res->stego_path,
               res->adaptive ? "Adaptive Texture LSB" : "Standard LSB",
               res->has_passphrase ? "CMC2 Encrypted (AES-256-GCM + Argon2id)"
                                   : "CMC1 Unencrypted (Plaintext)");
      SetDlgItemTextA(hEmbedPage, IDC_EMBED_STATUS_LBL, status_msg);

      /* Enable quick action buttons */
      EnableWindow(GetDlgItem(hEmbedPage, IDC_EMBED_BTN_OPEN_DIR), TRUE);
      EnableWindow(GetDlgItem(hEmbedPage, IDC_EMBED_BTN_VERIFY), TRUE);
      EnableWindow(GetDlgItem(hEmbedPage, IDC_EMBED_BTN_SWITCH_EXT), TRUE);

      /* Clear passphrase fields for security */
      SetDlgItemTextA(hEmbedPage, IDC_EMBED_PASS_EDIT, "");
      SetDlgItemTextA(hEmbedPage, IDC_EMBED_CONFIRM_EDIT, "");

      SendMessage(
          g_hStatusBar, SB_SETTEXT, 0,
          (LPARAM) "Embedding complete: payload embedded successfully.");
    } else {
      g_embed_status_type = 2;
      char err_msg[256];
      snprintf(err_msg, sizeof(err_msg), "[-] Embedding failed: %s",
               stego_strerror(res->result));
      SetDlgItemTextA(hEmbedPage, IDC_EMBED_STATUS_LBL, err_msg);
      SendMessage(g_hStatusBar, SB_SETTEXT, 0,
                  (LPARAM) "Embedding operation failed.");
    }

    InvalidateRect(GetDlgItem(hEmbedPage, IDC_EMBED_STATUS_LBL), NULL, TRUE);
    free(res);
    return 0;
  }

  case WM_APP_EXTRACT_DONE: {
    ExtractWorkerResult *res = (ExtractWorkerResult *)lParam;
    HWND hExtractPage = g_hPages[1];
    EnableWindow(GetDlgItem(hExtractPage, IDC_EXTRACT_BTN_EXEC), TRUE);

    if (res->result == STEGO_OK) {
      g_extract_status_type = 1;
      char stat[512];
      if (res->output_path[0] != '\0') {
        snprintf(stat, sizeof(stat),
                 "[+] SUCCESS: Extracted %zu bytes and saved to '%s'.",
                 res->extracted_len, res->output_path);
      } else {
        snprintf(stat, sizeof(stat),
                 "[+] SUCCESS: Extracted %zu bytes from stego image.",
                 res->extracted_len);
      }
      SetDlgItemTextA(hExtractPage, IDC_EXTRACT_STATUS_LBL, stat);

      /* Display text if printable */
      if (res->extracted_data) {
        if (res->is_printable_text) {
          char *txt = (char *)malloc(res->extracted_len + 1);
          if (txt) {
            memcpy(txt, res->extracted_data, res->extracted_len);
            txt[res->extracted_len] = '\0';
            SetDlgItemTextA(hExtractPage, IDC_EXTRACT_RESULT_EDIT, txt);
            stego_secure_zero(txt, res->extracted_len);
            free(txt);
          }
        } else {
          char bin_info[256];
          snprintf(bin_info, sizeof(bin_info),
                   "[Binary data: %zu bytes]\r\n"
                   "Payload contains non-printable binary characters.\r\n"
                   "%s",
                   res->extracted_len,
                   (res->output_path[0] != '\0')
                       ? "Payload has been saved directly to output file."
                       : "Please specify an output file above to save the "
                         "binary payload.");
          SetDlgItemTextA(hExtractPage, IDC_EXTRACT_RESULT_EDIT, bin_info);
        }
        stego_secure_zero(res->extracted_data, res->extracted_len);
        free(res->extracted_data);
        res->extracted_data = NULL;
      }

      /* Clear passphrase field */
      SetDlgItemTextA(hExtractPage, IDC_EXTRACT_PASS_EDIT, "");
      SendMessage(g_hStatusBar, SB_SETTEXT, 0,
                  (LPARAM) "Extraction complete: secret payload recovered "
                           "successfully.");
    } else {
      g_extract_status_type = 2;
      char err_msg[384];
      snprintf(err_msg, sizeof(err_msg), "[-] %s", res->error_detail);
      SetDlgItemTextA(hExtractPage, IDC_EXTRACT_STATUS_LBL, err_msg);
      SetDlgItemTextA(hExtractPage, IDC_EXTRACT_RESULT_EDIT, "");
      SendMessage(
          g_hStatusBar, SB_SETTEXT, 0,
          (LPARAM) "Extraction failed: authentication or envelope error.");
    }

    InvalidateRect(GetDlgItem(hExtractPage, IDC_EXTRACT_STATUS_LBL), NULL,
                   TRUE);
    free(res);
    return 0;
  }

  case WM_SIZE: {
    SendMessage(g_hStatusBar, WM_SIZE, 0, 0);
    return 0;
  }

  case WM_DESTROY: {
    if (g_hFontNormal)
      DeleteObject(g_hFontNormal);
    if (g_hFontBold)
      DeleteObject(g_hFontBold);
    if (g_hFontTitle)
      DeleteObject(g_hFontTitle);
    if (g_hFontMono)
      DeleteObject(g_hFontMono);
    PostQuitMessage(0);
    return 0;
  }
  }
  return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

/* ========================================================================= */
/* Application Entry Point                                                   */
/* ========================================================================= */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
  (void)hPrevInstance;
  (void)lpCmdLine;
  g_hInstance = hInstance;

  /* Initialize Common Controls */
  INITCOMMONCONTROLSEX icc;
  icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
  icc.dwICC = ICC_TAB_CLASSES | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES;
  InitCommonControlsEx(&icc);

  /* Setup Fonts */
  g_hFontNormal =
      CreateFontA(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                  OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                  DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
  g_hFontBold =
      CreateFontA(-13, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                  OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                  DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
  g_hFontTitle =
      CreateFontA(-16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                  OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                  DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
  g_hFontMono =
      CreateFontA(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                  OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                  FIXED_PITCH | FF_MODERN, "Consolas");

  /* Register Main Window Class */
  WNDCLASSA wc = {0};
  wc.lpfnWndProc = MainWndProc;
  wc.hInstance = hInstance;
  wc.hCursor = LoadCursor(NULL, IDC_ARROW);
  wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
  wc.lpszClassName = "PrivacyStegoToolkitMainClass";
  RegisterClassA(&wc);

  /* Create Main Window (Centered, Fixed Dialog Style) */
  int w = 750;
  int h = 615;
  int screen_w = GetSystemMetrics(SM_CXSCREEN);
  int screen_h = GetSystemMetrics(SM_CYSCREEN);
  int x = (screen_w - w) / 2;
  int y = (screen_h - h) / 2;

  HWND hwnd =
      CreateWindowExA(WS_EX_APPWINDOW, "PrivacyStegoToolkitMainClass",
                      "Hushframe — Keep what matters out of sight",
                      WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                      x, y, w, h, NULL, NULL, hInstance, NULL);

  if (!hwnd)
    return 1;

  ShowWindow(hwnd, nCmdShow);
  UpdateWindow(hwnd);

  MSG msg;
  while (GetMessageA(&msg, NULL, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessageA(&msg);
  }

  return (int)msg.wParam;
}
