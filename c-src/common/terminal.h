/*
 * terminal.h - Terminal utilities for raw mode and signal handling
 */

#ifndef SSHELL_TERMINAL_H
#define SSHELL_TERMINAL_H

#include <termios.h>
#include <stdbool.h>

/* Terminal state management */
typedef struct {
    struct termios original_attrs;
    bool is_raw;
    int saved_rows;
    int saved_cols;
} terminal_state_t;

/* Initialize terminal state */
void terminal_init(terminal_state_t *state);

/* Enter raw mode */
int terminal_enter_raw_mode(terminal_state_t *state, int fd);

/* Restore original mode */
int terminal_restore(terminal_state_t *state, int fd);

/* Get terminal size */
int terminal_get_size(int fd, int *rows, int *cols);

/* Set terminal size */
int terminal_set_size(int fd, int rows, int cols);

/* Make FD non-blocking */
int terminal_set_nonblocking(int fd);

#endif /* SSHELL_TERMINAL_H */
