/**
 * @file ui_tui.c
 * @brief Interactive Terminal User Interface (TUI) implementation for bmp-stego.
 *
 * Implements a beginner-friendly interactive terminal UI with selectable buttons,
 * arrow key navigation, mouse click support, progress feedback, plain-English
 * status messages, and seamless integration with the secure steganography core.
 */

#include "ui_tui.h"
#include "stego/stego.h"
#include "stego/metadata.h"
#include "stego/privacy.h"
#include "stego/carrier.h"
#include "stego/image_loader.h"
#include "stego/image_format.h"
#include "stego/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#include <direct.h>
#define isatty_compat _isatty
#define fileno_compat _fileno
#else
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#define isatty_compat isatty
#define fileno_compat fileno
#endif

static void tui_ensure_image_dirs(void) {
#if defined(_WIN32)
    _mkdir("images");
    _mkdir("images/input");
    _mkdir("images/output");
#else
    mkdir("images", 0755);
    mkdir("images/input", 0755);
    mkdir("images/output", 0755);
#endif
}

/* ========================================================================= */
/* Terminal Styling & ANSI Escape Codes                                      */
/* ========================================================================= */

#define TUI_RESET       "\033[0m"
#define TUI_BOLD        "\033[1m"
#define TUI_DIM         "\033[2m"
#define TUI_INVERSE     "\033[7m"
#define TUI_GREEN       "\033[1;32m"
#define TUI_YELLOW      "\033[1;33m"
#define TUI_RED         "\033[1;31m"
#define TUI_CYAN        "\033[1;36m"
#define TUI_WHITE       "\033[1;37m"
#define TUI_BG_BLUE     "\033[44m"
#define TUI_BG_DARK     "\033[40m"

/* Screen IDs */
typedef enum {
    SCREEN_MAIN = 0,
    SCREEN_HIDE,
    SCREEN_REVEAL,
    SCREEN_CHECK,
    SCREEN_PRIVACY,
    SCREEN_HELP,
    SCREEN_EXIT
} TuiScreenId;

/* Key codes */
typedef enum {
    KEY_NONE = 0,
    KEY_UP,
    KEY_DOWN,
    KEY_LEFT,
    KEY_RIGHT,
    KEY_ENTER,
    KEY_ESC,
    KEY_TAB,
    KEY_BACKTAB,
    KEY_BACKSPACE,
    KEY_SPACE,
    KEY_CHAR,
    KEY_MOUSE_CLICK
} TuiKey;

/* Widget Types */
typedef enum {
    WIDGET_BUTTON,
    WIDGET_INPUT,
    WIDGET_PASSWORD,
    WIDGET_RADIO,
    WIDGET_CHECKBOX
} WidgetType;

#define MAX_WIDGETS 32
#define MAX_BUTTON_RECTS 64

typedef struct {
    int id;
    WidgetType type;
    char label[64];
    char *text_val;
    size_t max_len;
    bool checked;
    int radio_group;
    int row;
    int col_start;
    int col_end;
} Widget;

typedef struct {
    int widget_id;
    int row;
    int col_start;
    int col_end;
} ButtonHitRect;

/* ========================================================================= */
/* Global Terminal State                                                     */
/* ========================================================================= */

#if defined(_WIN32)
static HANDLE g_hIn = INVALID_HANDLE_VALUE;
static HANDLE g_hOut = INVALID_HANDLE_VALUE;
static DWORD g_orig_in_mode = 0;
static DWORD g_orig_out_mode = 0;
#else
static struct termios g_orig_termios;
#endif

static bool g_terminal_initialized = false;
static bool g_has_color = true;

static ButtonHitRect g_hit_rects[MAX_BUTTON_RECTS];
static int g_num_hit_rects = 0;

/* Signal and Exit Handler */
static void tui_restore_terminal(void) {
    if (!g_terminal_initialized) return;

    /* Reset formatting and show cursor */
    printf("%s\033[?25h", TUI_RESET);
    fflush(stdout);

#if defined(_WIN32)
    if (g_hOut != INVALID_HANDLE_VALUE && g_orig_out_mode != 0) {
        SetConsoleMode(g_hOut, g_orig_out_mode);
    }
    if (g_hIn != INVALID_HANDLE_VALUE && g_orig_in_mode != 0) {
        SetConsoleMode(g_hIn, g_orig_in_mode);
    }
#else
    tcsetattr(STDIN_FILENO, TCSANOW, &g_orig_termios);
#endif

    g_terminal_initialized = false;
}

#if defined(_WIN32)
static BOOL WINAPI tui_ctrl_handler(DWORD ctrlType) {
    (void)ctrlType;
    tui_restore_terminal();
    ExitProcess(0);
    return TRUE;
}
#else
static void tui_sigint_handler(int sig) {
    (void)sig;
    tui_restore_terminal();
    exit(0);
}
#endif

static bool tui_init_terminal(void) {
    if (g_terminal_initialized) return true;

#if defined(_WIN32)
    g_hIn = GetStdHandle(STD_INPUT_HANDLE);
    g_hOut = GetStdHandle(STD_OUTPUT_HANDLE);

    if (g_hIn == INVALID_HANDLE_VALUE || g_hOut == INVALID_HANDLE_VALUE) {
        return false;
    }

    if (!GetConsoleMode(g_hIn, &g_orig_in_mode) ||
        !GetConsoleMode(g_hOut, &g_orig_out_mode)) {
        return false;
    }

    /* Enable VT processing on output if available */
    DWORD out_mode = g_orig_out_mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    if (!SetConsoleMode(g_hOut, out_mode)) {
        /* VT failed, keep standard output mode */
        SetConsoleMode(g_hOut, g_orig_out_mode);
        g_has_color = true; /* Standard windows still supports basic ANSI in modern Windows */
    }

    /* Enable mouse input, window input, and extended flags */
    DWORD in_mode = ENABLE_EXTENDED_FLAGS | ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT;
    SetConsoleMode(g_hIn, in_mode);

    SetConsoleCtrlHandler(tui_ctrl_handler, TRUE);
#else
    if (tcgetattr(STDIN_FILENO, &g_orig_termios) < 0) {
        return false;
    }

    struct termios raw = g_orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON | ISIG);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);

    signal(SIGINT, tui_sigint_handler);
    signal(SIGTERM, tui_sigint_handler);
#endif

    atexit(tui_restore_terminal);
    g_terminal_initialized = true;

    /* Hide text cursor initially */
    printf("\033[?25l");
    fflush(stdout);
    return true;
}

/* Clear screen and reset cursor to home (row 1, col 1) */
static void tui_clear_screen(void) {
    printf("\033[2J\033[H");
    fflush(stdout);
    g_num_hit_rects = 0;
}

/* Sleep helper (milliseconds) */
static void tui_sleep_ms(int ms) {
#if defined(_WIN32)
    Sleep((DWORD)ms);
#else
    usleep((useconds_t)ms * 1000);
#endif
}

/* Hit rect registration for mouse support */
static void tui_register_hit_rect(int widget_id, int row, int col_start, int col_end) {
    if (g_num_hit_rects < MAX_BUTTON_RECTS) {
        g_hit_rects[g_num_hit_rects].widget_id = widget_id;
        g_hit_rects[g_num_hit_rects].row = row;
        g_hit_rects[g_num_hit_rects].col_start = col_start;
        g_hit_rects[g_num_hit_rects].col_end = col_end;
        g_num_hit_rects++;
    }
}

static int tui_find_widget_by_coords(int mouse_x, int mouse_y) {
    for (int i = 0; i < g_num_hit_rects; i++) {
        if (g_hit_rects[i].row == mouse_y &&
            mouse_x >= g_hit_rects[i].col_start &&
            mouse_x <= g_hit_rects[i].col_end) {
            return g_hit_rects[i].widget_id;
        }
    }
    return -1;
}

/* Get single keyboard or mouse event */
static TuiKey tui_get_key(char *out_char, int *out_mouse_x, int *out_mouse_y) {
    if (out_char) *out_char = '\0';
    if (out_mouse_x) *out_mouse_x = -1;
    if (out_mouse_y) *out_mouse_y = -1;

#if defined(_WIN32)
    INPUT_RECORD ir;
    DWORD read_count = 0;

    while (ReadConsoleInput(g_hIn, &ir, 1, &read_count)) {
        if (read_count == 0) continue;

        if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) {
            WORD vk = ir.Event.KeyEvent.wVirtualKeyCode;
            DWORD ctrl = ir.Event.KeyEvent.dwControlKeyState;

            switch (vk) {
                case VK_UP:     return KEY_UP;
                case VK_DOWN:   return KEY_DOWN;
                case VK_LEFT:   return KEY_LEFT;
                case VK_RIGHT:  return KEY_RIGHT;
                case VK_RETURN: return KEY_ENTER;
                case VK_ESCAPE: return KEY_ESC;
                case VK_BACK:   return KEY_BACKSPACE;
                case VK_SPACE:
                    if (out_char) *out_char = ' ';
                    return KEY_SPACE;
                case VK_TAB:
                    return (ctrl & SHIFT_PRESSED) ? KEY_BACKTAB : KEY_TAB;
                default: {
                    char c = ir.Event.KeyEvent.uChar.AsciiChar;
                    if (c >= 32 && c <= 126) {
                        if (out_char) *out_char = c;
                        return KEY_CHAR;
                    }
                    break;
                }
            }
        } else if (ir.EventType == MOUSE_EVENT) {
            /* Check for left-mouse button press */
            if (ir.Event.MouseEvent.dwEventFlags == 0 &&
                (ir.Event.MouseEvent.dwButtonState & FROM_LEFT_1ST_BUTTON_PRESSED)) {
                if (out_mouse_x) *out_mouse_x = ir.Event.MouseEvent.dwMousePosition.X;
                if (out_mouse_y) *out_mouse_y = ir.Event.MouseEvent.dwMousePosition.Y;
                return KEY_MOUSE_CLICK;
            }
        }
    }
    return KEY_NONE;
#else
    char c = 0;
    if (read(STDIN_FILENO, &c, 1) <= 0) return KEY_NONE;

    if (c == 27) { /* Escape sequence */
        char seq[4] = {0};
        if (read(STDIN_FILENO, &seq[0], 1) <= 0) return KEY_ESC;
        if (seq[0] == '[') {
            if (read(STDIN_FILENO, &seq[1], 1) <= 0) return KEY_ESC;
            if (seq[1] == 'A') return KEY_UP;
            if (seq[1] == 'B') return KEY_DOWN;
            if (seq[1] == 'C') return KEY_RIGHT;
            if (seq[1] == 'D') return KEY_LEFT;
            if (seq[1] == 'Z') return KEY_BACKTAB;
        }
        return KEY_ESC;
    } else if (c == '\r' || c == '\n') {
        return KEY_ENTER;
    } else if (c == '\t') {
        return KEY_TAB;
    } else if (c == 127 || c == 8) {
        return KEY_BACKSPACE;
    } else if (c == ' ') {
        if (out_char) *out_char = ' ';
        return KEY_SPACE;
    } else if (c >= 32 && c <= 126) {
        if (out_char) *out_char = c;
        return KEY_CHAR;
    }
    return KEY_NONE;
#endif
}

/* ========================================================================= */
/* Animated Stepped Progress Bar                                             */
/* ========================================================================= */

static void tui_render_progress(const char *action_text) {
    const int bar_width = 30;
    printf("\n  %s[*] %s...%s\n", TUI_CYAN, action_text, TUI_RESET);

    for (int p = 0; p <= 100; p += 20) {
        int filled = (p * bar_width) / 100;
        printf("\r  Progress: [");
        if (g_has_color) printf("%s", TUI_GREEN);
        for (int i = 0; i < filled; i++) printf("#");
        if (g_has_color) printf("%s", TUI_RESET);
        for (int i = filled; i < bar_width; i++) printf(".");
        printf("] %3d%%", p);
        fflush(stdout);
        tui_sleep_ms(40);
    }
    printf("\n\n");
}

/* ========================================================================= */
/* File Picker & Pre-populated Samples Helper                                */
/* ========================================================================= */

static const char *g_known_samples[] = {
    "images/input/cover.bmp",
    "images/input/cover.png",
    "images/output/stego.png",
    "samples/cover.png",
    "samples/cover.bmp",
    "samples/cover.jpg",
    "samples/compat/rgb8.png",
    "samples/compat/rgba8.png",
    "samples/compat/sample.jpg",
    "samples/compat/sample.webp",
    "samples/compat/sample.gif",
    "output_stego.png"
};
static const int g_num_known_samples = sizeof(g_known_samples) / sizeof(g_known_samples[0]);

static bool tui_file_exists(const char *path) {
    if (!path || path[0] == '\0') return false;
    FILE *fp = fopen(path, "rb");
    if (fp) {
        fclose(fp);
        return true;
    }
    return false;
}

/* Interactive File Chooser overlay */
static void tui_choose_file_dialog(char *target_buf, size_t max_len, const char *title) {
    tui_clear_screen();
    printf("+--------------------------------------------+\n");
    printf("|       CHOOSE FILE / SAMPLE IMAGE           |\n");
    printf("+--------------------------------------------+\n\n");
    printf("  %s%s%s\n\n", TUI_CYAN, title, TUI_RESET);

    /* Collect existing files */
    const char *available[16];
    int count = 0;
    for (int i = 0; i < g_num_known_samples && count < 15; i++) {
        if (tui_file_exists(g_known_samples[i])) {
            available[count++] = g_known_samples[i];
        }
    }

    int selected = 0;
    bool done = false;

    while (!done) {
        tui_clear_screen();
        printf("+--------------------------------------------+\n");
        printf("|       CHOOSE FILE / SAMPLE IMAGE           |\n");
        printf("+--------------------------------------------+\n\n");
        printf("  %s%s%s\n\n", TUI_CYAN, title, TUI_RESET);
        printf("  Select a detected file or type a custom path:\n\n");

        int line = 6;
        for (int i = 0; i < count; i++) {
            if (i == selected) {
                printf("  %s> [ %-34s ]%s\n", TUI_CYAN, available[i], TUI_RESET);
            } else {
                printf("    [ %-34s ]\n", available[i]);
            }
            tui_register_hit_rect(i, line, 4, 42);
            line++;
        }

        /* Option to enter custom path */
        if (selected == count) {
            printf("  %s> [ Enter Custom Path Manually...      ]%s\n", TUI_CYAN, TUI_RESET);
        } else {
            printf("    [ Enter Custom Path Manually...      ]\n");
        }
        tui_register_hit_rect(count, line, 4, 42);
        line += 2;

        /* Back button */
        if (selected == count + 1) {
            printf("  %s> [ Cancel / Keep Current Path         ]%s\n\n", TUI_YELLOW, TUI_RESET);
        } else {
            printf("    [ Cancel / Keep Current Path         ]\n\n");
        }
        tui_register_hit_rect(count + 1, line, 4, 42);

        printf("  %s^ v Move   Enter Select   Esc Cancel%s\n", TUI_DIM, TUI_RESET);

        char ch = 0;
        int mx = -1, my = -1;
        TuiKey k = tui_get_key(&ch, &mx, &my);

        if (k == KEY_UP) {
            if (selected > 0) selected--;
            else selected = count + 1;
        } else if (k == KEY_DOWN || k == KEY_TAB) {
            if (selected < count + 1) selected++;
            else selected = 0;
        } else if (k == KEY_ESC) {
            return;
        } else if (k == KEY_MOUSE_CLICK) {
            int clicked = tui_find_widget_by_coords(mx, my);
            if (clicked >= 0 && clicked <= count + 1) {
                selected = clicked;
                k = KEY_ENTER;
            }
        }

        if (k == KEY_ENTER) {
            if (selected < count) {
                strncpy(target_buf, available[selected], max_len - 1);
                target_buf[max_len - 1] = '\0';
                done = true;
            } else if (selected == count) {
                /* Enter custom path */
                printf("\033[?25h\n  Enter file path: ");
                fflush(stdout);
                char input[512] = {0};
                if (fgets(input, sizeof(input), stdin)) {
                    size_t len = strlen(input);
                    while (len > 0 && (input[len - 1] == '\r' || input[len - 1] == '\n')) {
                        input[--len] = '\0';
                    }
                    if (len > 0) {
                        strncpy(target_buf, input, max_len - 1);
                        target_buf[max_len - 1] = '\0';
                    }
                }
                printf("\033[?25l");
                done = true;
            } else {
                /* Cancel */
                done = true;
            }
        }
    }
}

/* ========================================================================= */
/* Confirmation Dialog                                                       */
/* ========================================================================= */

static bool tui_confirm_dialog(const char *prompt_text) {
    int selected = 1; /* Default to No for safety */
    while (true) {
        tui_clear_screen();
        printf("+--------------------------------------------+\n");
        printf("|                CONFIRMATION                |\n");
        printf("+--------------------------------------------+\n\n");
        printf("  %s%s%s\n\n", TUI_YELLOW, prompt_text, TUI_RESET);

        if (selected == 0) {
            printf("  %s> [ Yes, Proceed ]%s    [ No, Cancel ]\n\n", TUI_GREEN, TUI_RESET);
        } else {
            printf("    [ Yes, Proceed ]  %s> [ No, Cancel ]%s\n\n", TUI_YELLOW, TUI_RESET);
        }

        tui_register_hit_rect(0, 5, 4, 20);
        tui_register_hit_rect(1, 5, 24, 40);

        printf("  < > Move   Enter Confirm   Esc Cancel\n");

        char ch = 0;
        int mx = -1, my = -1;
        TuiKey k = tui_get_key(&ch, &mx, &my);

        if (k == KEY_LEFT || k == KEY_RIGHT || k == KEY_TAB) {
            selected = (selected == 0) ? 1 : 0;
        } else if (k == KEY_ESC) {
            return false;
        } else if (k == KEY_MOUSE_CLICK) {
            int clicked = tui_find_widget_by_coords(mx, my);
            if (clicked == 0 || clicked == 1) {
                return (clicked == 0);
            }
        } else if (k == KEY_ENTER) {
            return (selected == 0);
        }
    }
}

/* ========================================================================= */
/* Screen: Main Menu                                                         */
/* ========================================================================= */

static TuiScreenId tui_screen_main(void) {
    const char *buttons[] = {
        "Hide a Secret",
        "Reveal a Secret",
        "Check Image",
        "Privacy Tools",
        "Help",
        "Exit"
    };
    const int num_buttons = 6;
    int selected = 0;

    while (true) {
        tui_clear_screen();
        printf("+--------------------------------------------+\n");
        printf("|          HUSHFRAME PRIVACY TOOLKIT         |\n");
        printf("+--------------------------------------------+\n\n");
        printf("  What would you like to do?\n\n");

        int line = 5;
        for (int i = 0; i < num_buttons; i++) {
            if (i == selected) {
                if (g_has_color) {
                    printf("  %s> [ %-21s ]%s\n", TUI_CYAN, buttons[i], TUI_RESET);
                } else {
                    printf("  > [ %-21s ]\n", buttons[i]);
                }
            } else {
                printf("    [ %-21s ]\n", buttons[i]);
            }
            tui_register_hit_rect(i, line, 4, 29);
            line++;
        }

        printf("\n  %s^ v Move   Enter Select   Esc Exit%s\n", TUI_DIM, TUI_RESET);

        char ch = 0;
        int mx = -1, my = -1;
        TuiKey k = tui_get_key(&ch, &mx, &my);

        if (k == KEY_UP) {
            if (selected > 0) selected--;
            else selected = num_buttons - 1;
        } else if (k == KEY_DOWN || k == KEY_TAB) {
            if (selected < num_buttons - 1) selected++;
            else selected = 0;
        } else if (k == KEY_ESC) {
            return SCREEN_EXIT;
        } else if (k == KEY_MOUSE_CLICK) {
            int clicked = tui_find_widget_by_coords(mx, my);
            if (clicked >= 0 && clicked < num_buttons) {
                selected = clicked;
                k = KEY_ENTER;
            }
        }

        if (k == KEY_ENTER) {
            switch (selected) {
                case 0: return SCREEN_HIDE;
                case 1: return SCREEN_REVEAL;
                case 2: return SCREEN_CHECK;
                case 3: return SCREEN_PRIVACY;
                case 4: return SCREEN_HELP;
                case 5: return SCREEN_EXIT;
            }
        }
    }
}

/* ========================================================================= */
/* Screen: Hide a Secret                                                     */
/* ========================================================================= */

static TuiScreenId tui_screen_hide(void) {
    tui_ensure_image_dirs();
    char cover_path[512] = "images/input/cover.bmp";
    if (!tui_file_exists(cover_path)) {
        snprintf(cover_path, sizeof(cover_path), "samples/cover.bmp");
    }
    char output_path[512] = "images/output/stego.png";
    char secret_text[1024] = "Confidential secret payload";
    char secret_file[512] = "samples/secret.txt";
    char password[256] = "";
    char confirm_pass[256] = "";
    bool is_file_mode = false;
    bool is_adaptive = false;
    bool show_pass = false;

    char status_msg[512] = "";
    int status_type = 0; /* 0: None, 1: Success, 2: Warning, 3: Error */

    enum {
        WID_CHOOSE_COVER = 0,
        WID_RADIO_TEXT,
        WID_RADIO_FILE,
        WID_SECRET_INPUT,
        WID_CHOOSE_SECRET_FILE,
        WID_PASSWORD,
        WID_CONFIRM_PASS,
        WID_SHOW_PASS,
        WID_OUTPUT_PATH,
        WID_ADAPTIVE,
        WID_ACTION_HIDE,
        WID_ACTION_BACK,
        WID_TOTAL
    };

    int focused = WID_ACTION_HIDE;

    while (true) {
        tui_clear_screen();
        printf("+--------------------------------------------+\n");
        printf("|                HIDE A SECRET               |\n");
        printf("+--------------------------------------------+\n\n");

        int line = 4;

        /* 1. Cover image */
        printf("  Cover Image: %-32s ", cover_path);
        if (focused == WID_CHOOSE_COVER) {
            printf("%s> [ Choose Image ]%s\n", TUI_CYAN, TUI_RESET);
        } else {
            printf("  [ Choose Image ]\n");
        }
        tui_register_hit_rect(WID_CHOOSE_COVER, line, 47, 65);
        line++;

        /* 2. Secret Type Radio */
        printf("  Secret Type: ");
        if (!is_file_mode) {
            printf("%s(*) Text message%s   ( ) Secret file\n", TUI_GREEN, TUI_RESET);
        } else {
            printf("( ) Text message   %s(*) Secret file%s\n", TUI_GREEN, TUI_RESET);
        }
        tui_register_hit_rect(WID_RADIO_TEXT, line, 15, 30);
        tui_register_hit_rect(WID_RADIO_FILE, line, 35, 50);
        line++;

        /* 3. Secret content / file */
        if (!is_file_mode) {
            printf("  Message    : [ %-38s ] ", secret_text);
            if (focused == WID_SECRET_INPUT) {
                printf("%s<editing>%s\n", TUI_CYAN, TUI_RESET);
            } else {
                printf("\n");
            }
            tui_register_hit_rect(WID_SECRET_INPUT, line, 15, 57);
            line++;
        } else {
            printf("  Secret File: %-32s ", secret_file);
            if (focused == WID_CHOOSE_SECRET_FILE) {
                printf("%s> [ Choose File ]%s\n", TUI_CYAN, TUI_RESET);
            } else {
                printf("  [ Choose File ]\n");
            }
            tui_register_hit_rect(WID_CHOOSE_SECRET_FILE, line, 47, 64);
            line++;
        }

        /* 4. Password fields */
        char pass_display[256] = {0};
        char conf_display[256] = {0};
        if (show_pass) {
            snprintf(pass_display, sizeof(pass_display), "%s", password);
            snprintf(conf_display, sizeof(conf_display), "%s", confirm_pass);
        } else {
            size_t plen = strlen(password);
            for (size_t i = 0; i < plen && i < 20; i++) pass_display[i] = '*';
            size_t clen = strlen(confirm_pass);
            for (size_t i = 0; i < clen && i < 20; i++) conf_display[i] = '*';
        }

        printf("  Password   : [ %-20s ] (leave blank for unencrypted)\n", pass_display);
        tui_register_hit_rect(WID_PASSWORD, line, 15, 39);
        line++;

        printf("  Confirm Pwd: [ %-20s ] ", conf_display);
        if (focused == WID_SHOW_PASS) {
            printf("%s> [%s] Show Password%s\n", TUI_CYAN, show_pass ? "x" : " ", TUI_RESET);
        } else {
            printf("  [%s] Show Password\n", show_pass ? "x" : " ");
        }
        tui_register_hit_rect(WID_CONFIRM_PASS, line, 15, 39);
        tui_register_hit_rect(WID_SHOW_PASS, line, 43, 62);
        line++;

        /* 5. Output path */
        printf("  Output File: [ %-30s ]\n", output_path);
        tui_register_hit_rect(WID_OUTPUT_PATH, line, 15, 49);
        line++;

        /* 6. Advanced options: Adaptive LSB */
        if (focused == WID_ADAPTIVE) {
            printf("  %s> [%s] Adaptive Texture LSB (PNG only)%s\n\n",
                   TUI_CYAN, is_adaptive ? "x" : " ", TUI_RESET);
        } else {
            printf("    [%s] Adaptive Texture LSB (PNG only)\n\n",
                   is_adaptive ? "x" : " ");
        }
        tui_register_hit_rect(WID_ADAPTIVE, line, 4, 40);
        line += 2;

        /* 7. Action buttons */
        if (focused == WID_ACTION_HIDE) {
            printf("  %s> [ Hide Secret ]%s    [ Back ]\n\n", TUI_GREEN, TUI_RESET);
        } else if (focused == WID_ACTION_BACK) {
            printf("    [ Hide Secret ]  %s> [ Back ]%s\n\n", TUI_YELLOW, TUI_RESET);
        } else {
            printf("    [ Hide Secret ]    [ Back ]\n\n");
        }
        tui_register_hit_rect(WID_ACTION_HIDE, line, 4, 19);
        tui_register_hit_rect(WID_ACTION_BACK, line, 23, 31);
        line += 2;

        /* Status Area */
        if (status_msg[0] != '\0') {
            const char *col = (status_type == 1) ? TUI_GREEN :
                              ((status_type == 2) ? TUI_YELLOW : TUI_RED);
            printf("  %s%s%s\n\n", col, status_msg, TUI_RESET);
        }

        printf("  %s^ v Navigate   Enter Select/Edit   Esc Back%s\n", TUI_DIM, TUI_RESET);

        char ch = 0;
        int mx = -1, my = -1;
        TuiKey k = tui_get_key(&ch, &mx, &my);

        if (k == KEY_UP) {
            do {
                focused = (focused > 0) ? focused - 1 : WID_TOTAL - 1;
            } while ((focused == WID_SECRET_INPUT && is_file_mode) ||
                     (focused == WID_CHOOSE_SECRET_FILE && !is_file_mode));
        } else if (k == KEY_DOWN || k == KEY_TAB) {
            do {
                focused = (focused < WID_TOTAL - 1) ? focused + 1 : 0;
            } while ((focused == WID_SECRET_INPUT && is_file_mode) ||
                     (focused == WID_CHOOSE_SECRET_FILE && !is_file_mode));
        } else if (k == KEY_ESC) {
            /* Zero passwords on exit */
            stego_secure_zero(password, sizeof(password));
            stego_secure_zero(confirm_pass, sizeof(confirm_pass));
            return SCREEN_MAIN;
        } else if (k == KEY_MOUSE_CLICK) {
            int clicked = tui_find_widget_by_coords(mx, my);
            if (clicked >= 0 && clicked < WID_TOTAL) {
                focused = clicked;
                k = KEY_ENTER;
            }
        }

        /* Widget Actions */
        if (k == KEY_ENTER || (k == KEY_SPACE && (focused == WID_RADIO_TEXT || focused == WID_RADIO_FILE || focused == WID_SHOW_PASS || focused == WID_ADAPTIVE))) {
            if (focused == WID_CHOOSE_COVER) {
                tui_choose_file_dialog(cover_path, sizeof(cover_path), "Select Cover Image");
            } else if (focused == WID_RADIO_TEXT) {
                is_file_mode = false;
            } else if (focused == WID_RADIO_FILE) {
                is_file_mode = true;
            } else if (focused == WID_SECRET_INPUT) {
                /* Inline edit secret text */
                printf("\033[?25h\n  Enter secret message: ");
                fflush(stdout);
                char input[1024] = {0};
                if (fgets(input, sizeof(input), stdin)) {
                    size_t len = strlen(input);
                    while (len > 0 && (input[len - 1] == '\r' || input[len - 1] == '\n')) input[--len] = '\0';
                    if (len > 0) snprintf(secret_text, sizeof(secret_text), "%s", input);
                }
                printf("\033[?25l");
            } else if (focused == WID_CHOOSE_SECRET_FILE) {
                tui_choose_file_dialog(secret_file, sizeof(secret_file), "Select Secret Payload File");
            } else if (focused == WID_PASSWORD) {
                printf("\033[?25h\n  Enter password: ");
                fflush(stdout);
                char input[256] = {0};
                if (fgets(input, sizeof(input), stdin)) {
                    size_t len = strlen(input);
                    while (len > 0 && (input[len - 1] == '\r' || input[len - 1] == '\n')) input[--len] = '\0';
                    snprintf(password, sizeof(password), "%s", input);
                }
                printf("\033[?25l");
            } else if (focused == WID_CONFIRM_PASS) {
                printf("\033[?25h\n  Confirm password: ");
                fflush(stdout);
                char input[256] = {0};
                if (fgets(input, sizeof(input), stdin)) {
                    size_t len = strlen(input);
                    while (len > 0 && (input[len - 1] == '\r' || input[len - 1] == '\n')) input[--len] = '\0';
                    snprintf(confirm_pass, sizeof(confirm_pass), "%s", input);
                }
                printf("\033[?25l");
            } else if (focused == WID_SHOW_PASS) {
                show_pass = !show_pass;
            } else if (focused == WID_OUTPUT_PATH) {
                printf("\033[?25h\n  Enter output file path: ");
                fflush(stdout);
                char input[512] = {0};
                if (fgets(input, sizeof(input), stdin)) {
                    size_t len = strlen(input);
                    while (len > 0 && (input[len - 1] == '\r' || input[len - 1] == '\n')) input[--len] = '\0';
                    if (len > 0) snprintf(output_path, sizeof(output_path), "%s", input);
                }
                printf("\033[?25l");
            } else if (focused == WID_ADAPTIVE) {
                is_adaptive = !is_adaptive;
            } else if (focused == WID_ACTION_BACK) {
                stego_secure_zero(password, sizeof(password));
                stego_secure_zero(confirm_pass, sizeof(confirm_pass));
                return SCREEN_MAIN;
            } else if (focused == WID_ACTION_HIDE) {
                /* Validate inputs */
                if (!tui_file_exists(cover_path)) {
                    snprintf(status_msg, sizeof(status_msg), "[-] Error: Cover image '%s' not found.", cover_path);
                    status_type = 3;
                    continue;
                }

                if (is_file_mode && !tui_file_exists(secret_file)) {
                    snprintf(status_msg, sizeof(status_msg), "[-] Error: Secret file '%s' not found.", secret_file);
                    status_type = 3;
                    continue;
                }

                if (!is_file_mode && strlen(secret_text) == 0) {
                    snprintf(status_msg, sizeof(status_msg), "[-] Error: Secret message cannot be empty.");
                    status_type = 3;
                    continue;
                }

                /* Password validation */
                bool use_encryption = (strlen(password) > 0);
                if (use_encryption) {
                    if (strcmp(password, confirm_pass) != 0) {
                        snprintf(status_msg, sizeof(status_msg), "[-] Error: Passwords do not match. Please re-enter.");
                        status_type = 3;
                        continue;
                    }
                }

                /* Check output overwrite */
                if (tui_file_exists(output_path)) {
                    char prompt[600];
                    snprintf(prompt, sizeof(prompt), "Output file '%s' already exists. Overwrite it?", output_path);
                    if (!tui_confirm_dialog(prompt)) {
                        snprintf(status_msg, sizeof(status_msg), "[*] Embedding cancelled. File was not overwritten.");
                        status_type = 2;
                        continue;
                    }
                }

                /* Execute Embedding */
                tui_render_progress("Hiding secret into image");

                const char *secret_source = secret_file;
                char tmp_secret_path[128] = "tmp_tui_secret.txt";
                bool using_tmp_secret = false;

                if (!is_file_mode) {
                    FILE *sfp = fopen(tmp_secret_path, "wb");
                    if (sfp) {
                        fwrite(secret_text, 1, strlen(secret_text), sfp);
                        fclose(sfp);
                        secret_source = tmp_secret_path;
                        using_tmp_secret = true;
                    }
                }

                StegoResult res = stego_hide_file_unified_secure(
                    cover_path,
                    output_path,
                    secret_source,
                    use_encryption ? password : NULL,
                    is_adaptive
                );

                if (using_tmp_secret) {
                    stego_secure_delete_file(tmp_secret_path);
                }

                /* Zero password buffers immediately */
                stego_secure_zero(password, sizeof(password));
                stego_secure_zero(confirm_pass, sizeof(confirm_pass));

                if (res == STEGO_OK) {
                    snprintf(status_msg, sizeof(status_msg),
                             "[+] Success! Secret hidden and saved to '%s'\n"
                             "    Status: %s",
                             output_path,
                             use_encryption ? "Password protected (Argon2id + AES-256-GCM)" : "Not password protected");
                    status_type = 1;
                } else {
                    snprintf(status_msg, sizeof(status_msg), "[-] Error: %s", stego_strerror(res));
                    status_type = 3;
                }
            }
        }
    }
}

/* ========================================================================= */
/* Screen: Reveal a Secret                                                   */
/* ========================================================================= */

static TuiScreenId tui_screen_reveal(void) {
    tui_ensure_image_dirs();
    char stego_path[512] = "images/output/stego.png";
    if (!tui_file_exists(stego_path)) {
        snprintf(stego_path, sizeof(stego_path), "output_stego.png");
    }
    char password[256] = "";
    char output_file[512] = "images/output/revealed_secret.txt";
    bool save_to_file = false;
    bool show_pass = false;

    char revealed_text[2048] = "";
    bool has_revealed_text = false;

    char status_msg[512] = "";
    int status_type = 0;

    enum {
        WID_CHOOSE_STEGO = 0,
        WID_PASSWORD,
        WID_SHOW_PASS,
        WID_SAVE_TO_FILE,
        WID_OUTPUT_FILE,
        WID_ACTION_REVEAL,
        WID_ACTION_BACK,
        WID_TOTAL
    };

    int focused = WID_ACTION_REVEAL;

    while (true) {
        tui_clear_screen();
        printf("+--------------------------------------------+\n");
        printf("|               REVEAL A SECRET              |\n");
        printf("+--------------------------------------------+\n\n");

        int line = 4;

        /* 1. Stego Image */
        printf("  Stego Image : %-32s ", stego_path);
        if (focused == WID_CHOOSE_STEGO) {
            printf("%s> [ Choose Stego Image ]%s\n", TUI_CYAN, TUI_RESET);
        } else {
            printf("  [ Choose Stego Image ]\n");
        }
        tui_register_hit_rect(WID_CHOOSE_STEGO, line, 47, 71);
        line++;

        /* 2. Password */
        char pass_display[256] = {0};
        if (show_pass) {
            snprintf(pass_display, sizeof(pass_display), "%s", password);
        } else {
            size_t plen = strlen(password);
            for (size_t i = 0; i < plen && i < 20; i++) pass_display[i] = '*';
        }

        printf("  Password    : [ %-20s ] ", pass_display);
        if (focused == WID_SHOW_PASS) {
            printf("%s> [%s] Show Password%s\n", TUI_CYAN, show_pass ? "x" : " ", TUI_RESET);
        } else {
            printf("  [%s] Show Password\n", show_pass ? "x" : " ");
        }
        tui_register_hit_rect(WID_PASSWORD, line, 16, 40);
        tui_register_hit_rect(WID_SHOW_PASS, line, 44, 63);
        line++;

        /* 3. Output options */
        if (focused == WID_SAVE_TO_FILE) {
            printf("  %s> [%s] Save extracted payload to file%s\n",
                   TUI_CYAN, save_to_file ? "x" : " ", TUI_RESET);
        } else {
            printf("    [%s] Save extracted payload to file\n",
                   save_to_file ? "x" : " ");
        }
        tui_register_hit_rect(WID_SAVE_TO_FILE, line, 4, 40);
        line++;

        if (save_to_file) {
            printf("  Output File : [ %-30s ]\n", output_file);
            tui_register_hit_rect(WID_OUTPUT_FILE, line, 16, 50);
            line++;
        }

        printf("\n");
        line++;

        /* 4. Action buttons */
        if (focused == WID_ACTION_REVEAL) {
            printf("  %s> [ Reveal Secret ]%s    [ Back ]\n\n", TUI_GREEN, TUI_RESET);
        } else if (focused == WID_ACTION_BACK) {
            printf("    [ Reveal Secret ]  %s> [ Back ]%s\n\n", TUI_YELLOW, TUI_RESET);
        } else {
            printf("    [ Reveal Secret ]    [ Back ]\n\n");
        }
        tui_register_hit_rect(WID_ACTION_REVEAL, line, 4, 21);
        tui_register_hit_rect(WID_ACTION_BACK, line, 25, 33);
        line += 2;

        /* Status & Results Area */
        if (status_msg[0] != '\0') {
            const char *col = (status_type == 1) ? TUI_GREEN :
                              ((status_type == 2) ? TUI_YELLOW : TUI_RED);
            printf("  %s%s%s\n\n", col, status_msg, TUI_RESET);
        }

        if (has_revealed_text) {
            printf("+-------------------- REVEALED SECRET --------------------+\n");
            printf("| %-56s |\n", revealed_text);
            printf("+---------------------------------------------------------+\n\n");
        }

        printf("  %s^ v Navigate   Enter Select/Edit   Esc Back%s\n", TUI_DIM, TUI_RESET);

        char ch = 0;
        int mx = -1, my = -1;
        TuiKey k = tui_get_key(&ch, &mx, &my);

        if (k == KEY_UP) {
            do {
                focused = (focused > 0) ? focused - 1 : WID_TOTAL - 1;
            } while (focused == WID_OUTPUT_FILE && !save_to_file);
        } else if (k == KEY_DOWN || k == KEY_TAB) {
            do {
                focused = (focused < WID_TOTAL - 1) ? focused + 1 : 0;
            } while (focused == WID_OUTPUT_FILE && !save_to_file);
        } else if (k == KEY_ESC) {
            stego_secure_zero(password, sizeof(password));
            return SCREEN_MAIN;
        } else if (k == KEY_MOUSE_CLICK) {
            int clicked = tui_find_widget_by_coords(mx, my);
            if (clicked >= 0 && clicked < WID_TOTAL) {
                focused = clicked;
                k = KEY_ENTER;
            }
        }

        if (k == KEY_ENTER || (k == KEY_SPACE && (focused == WID_SHOW_PASS || focused == WID_SAVE_TO_FILE))) {
            if (focused == WID_CHOOSE_STEGO) {
                tui_choose_file_dialog(stego_path, sizeof(stego_path), "Select Stego Image");
            } else if (focused == WID_PASSWORD) {
                printf("\033[?25h\n  Enter password: ");
                fflush(stdout);
                char input[256] = {0};
                if (fgets(input, sizeof(input), stdin)) {
                    size_t len = strlen(input);
                    while (len > 0 && (input[len - 1] == '\r' || input[len - 1] == '\n')) input[--len] = '\0';
                    snprintf(password, sizeof(password), "%s", input);
                }
                printf("\033[?25l");
            } else if (focused == WID_SHOW_PASS) {
                show_pass = !show_pass;
            } else if (focused == WID_SAVE_TO_FILE) {
                save_to_file = !save_to_file;
            } else if (focused == WID_OUTPUT_FILE) {
                printf("\033[?25h\n  Enter output file path: ");
                fflush(stdout);
                char input[512] = {0};
                if (fgets(input, sizeof(input), stdin)) {
                    size_t len = strlen(input);
                    while (len > 0 && (input[len - 1] == '\r' || input[len - 1] == '\n')) input[--len] = '\0';
                    if (len > 0) snprintf(output_file, sizeof(output_file), "%s", input);
                }
                printf("\033[?25l");
            } else if (focused == WID_ACTION_BACK) {
                stego_secure_zero(password, sizeof(password));
                return SCREEN_MAIN;
            } else if (focused == WID_ACTION_REVEAL) {
                has_revealed_text = false;
                revealed_text[0] = '\0';

                if (!tui_file_exists(stego_path)) {
                    snprintf(status_msg, sizeof(status_msg), "[-] Error: Stego image '%s' not found.", stego_path);
                    status_type = 3;
                    continue;
                }

                tui_render_progress("Revealing secret payload");

                StegoCarrier *carrier = NULL;
                StegoResult res = stego_carrier_open(stego_path, false, &carrier);
                if (res != STEGO_OK) {
                    snprintf(status_msg, sizeof(status_msg), "The password is incorrect, or the image was changed or damaged.");
                    status_type = 3;
                    continue;
                }

                uint8_t *payload = NULL;
                size_t payload_len = 0;
                const char *pass_arg = (password[0] != '\0') ? password : NULL;

                res = carrier->extract_secure(carrier, pass_arg, &payload, &payload_len);
                stego_carrier_close(carrier);

                /* Clear password buffer */
                stego_secure_zero(password, sizeof(password));

                if (res != STEGO_OK) {
                    /* Required error message on wrong password, corrupt, or tampered payload */
                    snprintf(status_msg, sizeof(status_msg), "The password is incorrect, or the image was changed or damaged.");
                    status_type = 3;
                } else {
                    if (save_to_file) {
                        FILE *ofp = fopen(output_file, "wb");
                        if (ofp) {
                            if (payload_len > 0) fwrite(payload, 1, payload_len, ofp);
                            fclose(ofp);
                            snprintf(status_msg, sizeof(status_msg),
                                     "[+] Success: Recovered %zu bytes and saved to '%s'.",
                                     payload_len, output_file);
                            status_type = 1;
                        } else {
                            snprintf(status_msg, sizeof(status_msg), "[-] Error: Failed to write output file '%s'.", output_file);
                            status_type = 3;
                        }
                    } else {
                        snprintf(status_msg, sizeof(status_msg), "[+] Success: Recovered %zu bytes from stego image.", payload_len);
                        status_type = 1;
                        size_t copy_len = (payload_len < sizeof(revealed_text) - 1) ? payload_len : sizeof(revealed_text) - 1;
                        memcpy(revealed_text, payload, copy_len);
                        revealed_text[copy_len] = '\0';
                        has_revealed_text = true;
                    }

                    if (payload) {
                        stego_secure_zero(payload, payload_len);
                        free(payload);
                    }
                }
            }
        }
    }
}

/* ========================================================================= */
/* Screen: Check Image                                                       */
/* ========================================================================= */

static TuiScreenId tui_screen_check(void) {
    char image_path[512] = "samples/cover.png";
    char result_buffer[2048] = "";

    enum {
        WID_CHOOSE_IMAGE = 0,
        WID_VERIFY,
        WID_CAPACITY,
        WID_INSPECT_META,
        WID_REMOVE_META,
        WID_REPORT,
        WID_BACK,
        WID_TOTAL
    };

    int focused = WID_VERIFY;

    while (true) {
        tui_clear_screen();
        printf("+--------------------------------------------+\n");
        printf("|                CHECK IMAGE                 |\n");
        printf("+--------------------------------------------+\n\n");

        int line = 4;

        /* Target image */
        printf("  Image Path: %-32s ", image_path);
        if (focused == WID_CHOOSE_IMAGE) {
            printf("%s> [ Choose Image ]%s\n\n", TUI_CYAN, TUI_RESET);
        } else {
            printf("  [ Choose Image ]\n\n");
        }
        tui_register_hit_rect(WID_CHOOSE_IMAGE, line, 45, 63);
        line += 2;

        /* Actions */
        const char *actions[] = {
            "Verify hidden secret",
            "Check capacity",
            "Inspect metadata",
            "Remove metadata",
            "Create privacy report"
        };

        for (int i = 0; i < 5; i++) {
            int wid = WID_VERIFY + i;
            if (focused == wid) {
                printf("  %s> [ %-27s ]%s\n", TUI_CYAN, actions[i], TUI_RESET);
            } else {
                printf("    [ %-27s ]\n", actions[i]);
            }
            tui_register_hit_rect(wid, line, 4, 35);
            line++;
        }

        printf("\n");
        line++;

        if (focused == WID_BACK) {
            printf("  %s> [ Back ]%s\n\n", TUI_YELLOW, TUI_RESET);
        } else {
            printf("    [ Back ]\n\n");
        }
        tui_register_hit_rect(WID_BACK, line, 4, 12);
        line += 2;

        /* Results Box */
        if (result_buffer[0] != '\0') {
            printf("+--------------------- RESULTS ---------------------+\n");
            printf("%s\n", result_buffer);
            printf("+---------------------------------------------------+\n\n");
        }

        printf("  %s^ v Move   Enter Select   Esc Back%s\n", TUI_DIM, TUI_RESET);

        char ch = 0;
        int mx = -1, my = -1;
        TuiKey k = tui_get_key(&ch, &mx, &my);

        if (k == KEY_UP) {
            focused = (focused > 0) ? focused - 1 : WID_TOTAL - 1;
        } else if (k == KEY_DOWN || k == KEY_TAB) {
            focused = (focused < WID_TOTAL - 1) ? focused + 1 : 0;
        } else if (k == KEY_ESC) {
            return SCREEN_MAIN;
        } else if (k == KEY_MOUSE_CLICK) {
            int clicked = tui_find_widget_by_coords(mx, my);
            if (clicked >= 0 && clicked < WID_TOTAL) {
                focused = clicked;
                k = KEY_ENTER;
            }
        }

        if (k == KEY_ENTER) {
            if (focused == WID_CHOOSE_IMAGE) {
                tui_choose_file_dialog(image_path, sizeof(image_path), "Select Image to Check");
            } else if (focused == WID_BACK) {
                return SCREEN_MAIN;
            } else {
                if (!tui_file_exists(image_path)) {
                    snprintf(result_buffer, sizeof(result_buffer), "[-] Error: Image '%s' not found.", image_path);
                    continue;
                }

                if (focused == WID_VERIFY) {
                    StegoCarrier *carrier = NULL;
                    if (stego_carrier_open(image_path, false, &carrier) == STEGO_OK) {
                        uint32_t payload_len = 0;
                        StegoEnvelopeType env = carrier->detect_envelope(carrier, &payload_len);
                        stego_carrier_close(carrier);

                        if (env == STEGO_ENVELOPE_CMC2) {
                            snprintf(result_buffer, sizeof(result_buffer),
                                     "  Secret Found   : YES\n"
                                     "  Payload Length : %u bytes\n"
                                     "  Protection     : Password protected (Argon2id + AES-256-GCM)",
                                     payload_len);
                        } else if (env == STEGO_ENVELOPE_CMC1) {
                            snprintf(result_buffer, sizeof(result_buffer),
                                     "  Secret Found   : YES\n"
                                     "  Payload Length : %u bytes\n"
                                     "  Protection     : Not password protected",
                                     payload_len);
                        } else {
                            snprintf(result_buffer, sizeof(result_buffer),
                                     "  No hidden secret detected in this image.");
                        }
                    } else {
                        snprintf(result_buffer, sizeof(result_buffer), "  [-] Error: Unable to open image carrier.");
                    }
                } else if (focused == WID_CAPACITY) {
                    StegoImage *img = NULL;
                    if (stego_image_load(image_path, &img) == STEGO_OK) {
                        size_t raw_cap = (size_t)img->width * img->height * 3 / 8;
                        size_t cmc1_cap = (raw_cap > 8) ? raw_cap - 8 : 0;
                        size_t cmc2_cap = (raw_cap > 52) ? raw_cap - 52 : 0;

                        snprintf(result_buffer, sizeof(result_buffer),
                                 "  Detected Format : %s\n"
                                 "  Dimensions      : %u x %u pixels\n"
                                 "  Original Mode   : %s (%d-bit)\n"
                                 "  Usable Channels : 3 (R, G, B used; alpha preserved)\n"
                                 "  Capacity (No Pwd): %zu bytes (%.2f KB)\n"
                                 "  Capacity (With Pwd): %zu bytes (%.2f KB)",
                                 stego_format_name(img->format),
                                 img->width, img->height,
                                 img->orig_color_mode, img->orig_bit_depth,
                                 cmc1_cap, (double)cmc1_cap / 1024.0,
                                 cmc2_cap, (double)cmc2_cap / 1024.0);
                        stego_image_free(img);
                    } else {
                        snprintf(result_buffer, sizeof(result_buffer), "  [-] Error: Could not load image.");
                    }
                } else if (focused == WID_INSPECT_META) {
                    StegoMetadataInfo rep;
                    if (stego_metadata_scan(image_path, &rep) == STEGO_OK) {
                        snprintf(result_buffer, sizeof(result_buffer),
                                 "  EXIF Header  : %s\n"
                                 "  Camera Make  : %s\n"
                                 "  Camera Model : %s\n"
                                 "  Software     : %s\n"
                                 "  GPS Location : %s\n"
                                 "  Date / Time  : %s\n"
                                 "  Metadata Size: %zu bytes",
                                 rep.has_exif ? "Detected" : "Not detected",
                                 rep.camera_make[0] ? rep.camera_make : "None found",
                                 rep.camera_model[0] ? rep.camera_model : "None found",
                                 rep.software[0] ? rep.software : "None found",
                                 rep.has_gps ? "Detected (Privacy Risk!)" : "None detected",
                                 rep.datetime[0] ? rep.datetime : "None found",
                                 rep.metadata_bytes);
                    } else {
                        snprintf(result_buffer, sizeof(result_buffer), "  [-] Error: Metadata inspection failed.");
                    }
                } else if (focused == WID_REMOVE_META) {
                    tui_ensure_image_dirs();
                    char clean_path[512];
                    const char *slash = strrchr(image_path, '/');
                    if (!slash) slash = strrchr(image_path, '\\');
                    const char *fname = slash ? slash + 1 : image_path;
                    snprintf(clean_path, sizeof(clean_path), "images/output/cleaned_%s", fname);
                    if (stego_metadata_strip(image_path, clean_path) == STEGO_OK) {
                        snprintf(result_buffer, sizeof(result_buffer),
                                 "  [+] Success: Metadata stripped safely.\n"
                                 "  Cleaned copy saved to: %s\n"
                                 "  Original image was preserved untouched.",
                                 clean_path);
                    } else {
                        snprintf(result_buffer, sizeof(result_buffer), "  [-] Error: Metadata stripping failed.");
                    }
                } else if (focused == WID_REPORT) {
                    /* Create privacy report in plain English */
                    StegoMetadataInfo rep;
                    if (stego_metadata_scan(image_path, &rep) == STEGO_OK) {
                        const char *risk = "LOW";
                        if (rep.has_gps) risk = "CRITICAL (GPS coordinates present!)";
                        else if (rep.has_exif) risk = "MEDIUM";

                        snprintf(result_buffer, sizeof(result_buffer),
                                 "  Privacy Assessment Report for '%s':\n"
                                 "  - Overall Risk  : %s\n"
                                 "  - GPS Tracking  : %s\n"
                                 "  - EXIF / Details: %s\n"
                                 "  Recommendation  : %s",
                                 image_path,
                                 risk,
                                 rep.has_gps ? "EXPOSED" : "Protected",
                                 rep.has_exif ? "Present" : "Clean",
                                 rep.has_gps ? "Use 'Remove metadata' before sharing publicly." : "Safe to share.");
                    } else {
                        snprintf(result_buffer, sizeof(result_buffer), "  [-] Error: Failed to generate report.");
                    }
                }
            }
        }
    }
}

/* ========================================================================= */
/* Screen: Privacy Tools                                                     */
/* ========================================================================= */

static TuiScreenId tui_screen_privacy(void) {
    char target_path[512] = "samples/cover.png";
    char result_buffer[1024] = "";

    enum {
        WID_CHOOSE_FILE = 0,
        WID_SAFE_SHARE,
        WID_SHRED,
        WID_REPORT,
        WID_BACK,
        WID_TOTAL
    };

    int focused = WID_SAFE_SHARE;

    while (true) {
        tui_clear_screen();
        printf("+--------------------------------------------+\n");
        printf("|                PRIVACY TOOLS               |\n");
        printf("+--------------------------------------------+\n\n");

        int line = 4;

        printf("  Target File: %-32s ", target_path);
        if (focused == WID_CHOOSE_FILE) {
            printf("%s> [ Choose File ]%s\n\n", TUI_CYAN, TUI_RESET);
        } else {
            printf("  [ Choose File ]\n\n");
        }
        tui_register_hit_rect(WID_CHOOSE_FILE, line, 46, 63);
        line += 2;

        const char *buttons[] = {
            "Remove Metadata / Safe-Share",
            "Secure Delete / Shred File",
            "Privacy Risk Report"
        };

        for (int i = 0; i < 3; i++) {
            int wid = WID_SAFE_SHARE + i;
            if (focused == wid) {
                printf("  %s> [ %-30s ]%s\n", TUI_CYAN, buttons[i], TUI_RESET);
            } else {
                printf("    [ %-30s ]\n", buttons[i]);
            }
            tui_register_hit_rect(wid, line, 4, 38);
            line++;
        }

        printf("\n");
        line++;

        if (focused == WID_BACK) {
            printf("  %s> [ Back ]%s\n\n", TUI_YELLOW, TUI_RESET);
        } else {
            printf("    [ Back ]\n\n");
        }
        tui_register_hit_rect(WID_BACK, line, 4, 12);
        line += 2;

        if (result_buffer[0] != '\0') {
            printf("+--------------------- RESULTS ---------------------+\n");
            printf("%s\n", result_buffer);
            printf("+---------------------------------------------------+\n\n");
        }

        printf("  %s^ v Move   Enter Select   Esc Back%s\n", TUI_DIM, TUI_RESET);

        char ch = 0;
        int mx = -1, my = -1;
        TuiKey k = tui_get_key(&ch, &mx, &my);

        if (k == KEY_UP) {
            focused = (focused > 0) ? focused - 1 : WID_TOTAL - 1;
        } else if (k == KEY_DOWN || k == KEY_TAB) {
            focused = (focused < WID_TOTAL - 1) ? focused + 1 : 0;
        } else if (k == KEY_ESC) {
            return SCREEN_MAIN;
        } else if (k == KEY_MOUSE_CLICK) {
            int clicked = tui_find_widget_by_coords(mx, my);
            if (clicked >= 0 && clicked < WID_TOTAL) {
                focused = clicked;
                k = KEY_ENTER;
            }
        }

        if (k == KEY_ENTER) {
            if (focused == WID_CHOOSE_FILE) {
                tui_choose_file_dialog(target_path, sizeof(target_path), "Select Target File for Privacy Operations");
            } else if (focused == WID_BACK) {
                return SCREEN_MAIN;
            } else {
                if (!tui_file_exists(target_path)) {
                    snprintf(result_buffer, sizeof(result_buffer), "[-] Error: File '%s' not found.", target_path);
                    continue;
                }

                if (focused == WID_SAFE_SHARE) {
                    tui_ensure_image_dirs();
                    char clean_name[512];
                    const char *slash = strrchr(target_path, '/');
                    if (!slash) slash = strrchr(target_path, '\\');
                    const char *fname = slash ? slash + 1 : target_path;
                    snprintf(clean_name, sizeof(clean_name), "images/output/safe_shared_%s", fname);
                    if (stego_safe_share(target_path, clean_name) == STEGO_OK) {
                        snprintf(result_buffer, sizeof(result_buffer),
                                 "  [+] Safe-Share Created: '%s'\n"
                                 "  Metadata purged. Original file remains untouched.",
                                 clean_name);
                    } else {
                        snprintf(result_buffer, sizeof(result_buffer), "  [-] Error: Safe-share copying failed.");
                    }
                } else if (focused == WID_SHRED) {
                    char prompt[600];
                    snprintf(prompt, sizeof(prompt), "Are you sure you want to securely shred '%s'? This CANNOT be undone!", target_path);
                    if (tui_confirm_dialog(prompt)) {
                        tui_render_progress("Securely zero-overwriting and shredding file");
                        if (stego_secure_delete_file(target_path) == STEGO_OK) {
                            snprintf(result_buffer, sizeof(result_buffer),
                                     "  [+] Success: '%s' securely zero-overwritten and shredded.",
                                     target_path);
                        } else {
                            snprintf(result_buffer, sizeof(result_buffer), "  [-] Error: Secure delete failed.");
                        }
                    } else {
                        snprintf(result_buffer, sizeof(result_buffer), "  [*] Shredding cancelled.");
                    }
                } else if (focused == WID_REPORT) {
                    StegoMetadataInfo rep;
                    if (stego_metadata_scan(target_path, &rep) == STEGO_OK) {
                        snprintf(result_buffer, sizeof(result_buffer),
                                 "  Privacy Audit Report for '%s':\n"
                                 "  - EXIF Present : %s\n"
                                 "  - GPS Location : %s\n"
                                 "  - Camera Model : %s\n"
                                 "  - Software     : %s",
                                 target_path,
                                 rep.has_exif ? "YES" : "None",
                                 rep.has_gps ? "YES (Location coordinates exposed!)" : "None detected",
                                 rep.camera_model[0] ? rep.camera_model : (rep.camera_make[0] ? rep.camera_make : "None"),
                                 rep.software[0] ? rep.software : "None");
                    } else {
                        snprintf(result_buffer, sizeof(result_buffer), "  [-] Error: Privacy report generation failed.");
                    }
                }
            }
        }
    }
}

/* ========================================================================= */
/* Screen: Help & Controls Guide                                             */
/* ========================================================================= */

static TuiScreenId tui_screen_help(void) {
    while (true) {
        tui_clear_screen();
        printf("+--------------------------------------------+\n");
        printf("|                    HELP                    |\n");
        printf("+--------------------------------------------+\n\n");

        printf("  %sNAVIGATION & CONTROLS:%s\n", TUI_BOLD, TUI_RESET);
        printf("  - %s^ / v (Arrow Keys)%s: Move selection up and down\n", TUI_CYAN, TUI_RESET);
        printf("  - %sEnter%s             : Activate selected button or edit field\n", TUI_CYAN, TUI_RESET);
        printf("  - %sTab / Shift+Tab%s   : Jump forward or backward between items\n", TUI_CYAN, TUI_RESET);
        printf("  - %sEsc%s               : Go back to previous screen or exit\n", TUI_CYAN, TUI_RESET);
        printf("  - %sMouse Click%s       : Left-click any button or field to select it\n\n", TUI_CYAN, TUI_RESET);

        printf("  %sKEY CONCEPTS IN PLAIN ENGLISH:%s\n", TUI_BOLD, TUI_RESET);
        printf("  - %sHide a Secret%s     : Embeds confidential text or a file into the\n"
               "                          pixels of an image without changing its appearance.\n", TUI_GREEN, TUI_RESET);
        printf("  - %sReveal a Secret%s   : Extracts the hidden data from an image.\n", TUI_GREEN, TUI_RESET);
        printf("  - %sPassword protected%s: Data is encrypted using Argon2id key derivation\n"
               "                          and AES-256-GCM authenticated encryption.\n", TUI_GREEN, TUI_RESET);
        printf("  - %sNot password protected%s: Standard envelope without encryption.\n\n", TUI_YELLOW, TUI_RESET);

        printf("  %sNON-INTERACTIVE CLI EQUIVALENTS:%s\n", TUI_BOLD, TUI_RESET);
        printf("  - Hide:   hushframe embed cover.png stego.png -m \"Secret\" --passphrase \"pwd\"\n");
        printf("  - Reveal: hushframe extract stego.png --passphrase \"pwd\"\n");
        printf("  - Verify: hushframe verify stego.png\n");
        printf("  - Report: hushframe privacy-report photo.jpg\n\n");

        printf("  %s> [ Back to Main Menu ]%s\n\n", TUI_CYAN, TUI_RESET);
        tui_register_hit_rect(0, 24, 4, 27);

        printf("  %sPress Enter or Esc to return to Main Menu%s\n", TUI_DIM, TUI_RESET);

        char ch = 0;
        int mx = -1, my = -1;
        TuiKey k = tui_get_key(&ch, &mx, &my);

        if (k == KEY_ENTER || k == KEY_ESC) {
            return SCREEN_MAIN;
        } else if (k == KEY_MOUSE_CLICK) {
            int clicked = tui_find_widget_by_coords(mx, my);
            if (clicked == 0) return SCREEN_MAIN;
        }
    }
}

/* ========================================================================= */
/* TUI Main Loop Dispatcher                                                  */
/* ========================================================================= */

int tui_main(void) {
    if (!tui_init_terminal()) {
        fprintf(stderr, "[-] Error: Failed to initialize interactive terminal console.\n");
        return 1;
    }

    TuiScreenId current_screen = SCREEN_MAIN;

    while (current_screen != SCREEN_EXIT) {
        switch (current_screen) {
            case SCREEN_MAIN:
                current_screen = tui_screen_main();
                break;
            case SCREEN_HIDE:
                current_screen = tui_screen_hide();
                break;
            case SCREEN_REVEAL:
                current_screen = tui_screen_reveal();
                break;
            case SCREEN_CHECK:
                current_screen = tui_screen_check();
                break;
            case SCREEN_PRIVACY:
                current_screen = tui_screen_privacy();
                break;
            case SCREEN_HELP:
                current_screen = tui_screen_help();
                break;
            case SCREEN_EXIT:
            default:
                break;
        }
    }

    tui_clear_screen();
    printf("+--------------------------------------------+\n");
    printf("|       THANK YOU FOR USING HUSHFRAME        |\n");
    printf("+--------------------------------------------+\n\n");
    printf("  Terminal state restored cleanly. Goodbye!\n\n");
    tui_restore_terminal();
    return 0;
}
