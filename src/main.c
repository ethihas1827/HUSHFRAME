/**
 * @file main.c
 * @brief Entry point for privacy-focused multi-format steganography CLI & TUI.
 */

#include "stego/cli.h"
#include "ui_tui.h"
#include <stdio.h>

#if defined(_WIN32)
#include <io.h>
#define isatty_compat _isatty
#define fileno_compat _fileno
#else
#include <unistd.h>
#define isatty_compat isatty
#define fileno_compat fileno
#endif

int main(int argc, char **argv) {
    if (argc <= 1) {
        if (!isatty_compat(fileno_compat(stdin))) {
            fprintf(stderr, "[-] Error: Standard input is not an interactive terminal.\n");
            fprintf(stderr, "[-] Please provide command-line arguments. Run '%s --help' for usage.\n", argv[0]);
            return 1;
        }
        return tui_main();
    }
    return stego_cli_run(argc, argv);
}
