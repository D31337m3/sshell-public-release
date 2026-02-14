/*
 * pty_manager.h - PTY management for sessions
 */

#ifndef SSHELL_PTY_MANAGER_H
#define SSHELL_PTY_MANAGER_H

#include "../common/session.h"
#include <stdbool.h>

/* Create PTY session */
int pty_create_session(session_t *session);

/* Set window size */
int pty_set_window_size(int fd, int rows, int cols);

/* Proxy I/O between PTY and client */
bool pty_proxy_io(int master_fd, int client_fd, double timeout);

/* Kill session */
void pty_kill_session(session_t *session);

#endif /* SSHELL_PTY_MANAGER_H */
