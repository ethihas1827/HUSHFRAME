/**
 * @file ui_tui.h
 * @brief Interactive Terminal User Interface (TUI) for bmp-stego.
 *
 * Provides a beginner-friendly interactive terminal application with
 * pressable, selectable buttons, keyboard and optional mouse navigation,
 * progress feedback, and plain-English workflows.
 */

#ifndef STEGO_UI_TUI_H
#define STEGO_UI_TUI_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Launch the interactive Terminal User Interface (TUI).
 * 
 * Sets up the terminal into interactive mode, renders screens with
 * selectable button-style items, handles keyboard (arrow keys, Enter, Esc)
 * and mouse click events, restores terminal state on exit or Ctrl+C,
 * and calls the underlying secure C core functions.
 * 
 * @return 0 on normal exit, non-zero on error.
 */
int tui_main(void);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_UI_TUI_H */

