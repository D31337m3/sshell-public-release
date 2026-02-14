/*
 * terminal.c - Terminal utilities implementation
 */

#include "terminal.h"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>

void terminal_init(terminal_state_t *state) {
    memset(state, 0, sizeof(terminal_state_t));
    state->is_raw = false;
    state->saved_rows = 24;
    state->saved_cols = 80;
}

int terminal_enter_raw_mode(terminal_state_t *state, int fd) {
    if (state->is_raw) return 0;
    
    /* Save original attributes */
    if (tcgetattr(fd, &state->original_attrs) < 0) {
        return -1;
    }
    
    /* Create raw mode attributes */
    struct termios raw = state->original_attrs;
    
    /* Input modes: no break, CR to NL, no parity check, no strip char,
     * no start/stop output control */
    raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    
    /* Output modes: disable post processing */
    raw.c_oflag &= ~(OPOST);
    
    /* Control modes: set 8 bit chars */
    raw.c_cflag |= (CS8);
    
    /* Local modes: echo off, canonical off, no extended functions,
     * no signal chars (^Z,^C) */
    raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    
    /* Control chars: set return condition */
    raw.c_cc[VMIN] = 0;   /* Return each byte, or zero for timeout */
    raw.c_cc[VTIME] = 1;  /* 100 ms timeout */
    
    /* Apply raw mode */
    if (tcsetattr(fd, TCSAFLUSH, &raw) < 0) {
        return -1;
    }
    
    state->is_raw = true;
    return 0;
}

int terminal_restore(terminal_state_t *state, int fd) {
    if (!state->is_raw) return 0;
    
    if (tcsetattr(fd, TCSAFLUSH, &state->original_attrs) < 0) {
        return -1;
    }
    
    state->is_raw = false;
    return 0;
}

int terminal_get_size(int fd, int *rows, int *cols) {
    struct winsize ws;
    
    if (ioctl(fd, TIOCGWINSZ, &ws) < 0) {
        *rows = 24;
        *cols = 80;
        return -1;
    }
    
    *rows = ws.ws_row;
    *cols = ws.ws_col;
    return 0;
}

int terminal_set_size(int fd, int rows, int cols) {
    struct winsize ws = {
        .ws_row = rows,
        .ws_col = cols,
        .ws_xpixel = 0,
        .ws_ypixel = 0
    };
    
    return ioctl(fd, TIOCSWINSZ, &ws);
}

int terminal_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return -1;
    
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
