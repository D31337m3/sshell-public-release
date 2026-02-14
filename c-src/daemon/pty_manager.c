/*
 * pty_manager.c - PTY management implementation
 */

#include "pty_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pty.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <signal.h>
#include <errno.h>

int pty_create_session(session_t *session) {
    int master_fd, slave_fd;
    pid_t pid = forkpty(&master_fd, NULL, NULL, NULL);
    
    if (pid < 0) {
        return -1;
    }
    
    if (pid == 0) {
        /* Child process - execute shell */
        char *argv[] = {session->shell, NULL};
        char *envp[] = {"TERM=xterm-256color", NULL};
        
        execve(session->shell, argv, envp);
        _exit(1);  /* If exec fails */
    }
    
    /* Parent process */
    /* Set non-blocking */
    int flags = fcntl(master_fd, F_GETFL);
    fcntl(master_fd, F_SETFL, flags | O_NONBLOCK);
    
    session->pid = pid;
    session->master_fd = master_fd;
    session->status = SESSION_STATUS_RUNNING;
    
    return 0;
}

int pty_set_window_size(int fd, int rows, int cols) {
    struct winsize ws = {
        .ws_row = rows,
        .ws_col = cols,
        .ws_xpixel = 0,
        .ws_ypixel = 0
    };
    
    return ioctl(fd, TIOCSWINSZ, &ws);
}

bool pty_proxy_io(int master_fd, int client_fd, double timeout) {
    fd_set readfds;
    struct timeval tv;
    char buffer[4096];
    ssize_t n;
    
    FD_ZERO(&readfds);
    FD_SET(master_fd, &readfds);
    FD_SET(client_fd, &readfds);
    
    tv.tv_sec = (long)timeout;
    tv.tv_usec = (long)((timeout - tv.tv_sec) * 1000000);
    
    int maxfd = (master_fd > client_fd) ? master_fd : client_fd;
    int ret = select(maxfd + 1, &readfds, NULL, NULL, &tv);
    
    if (ret < 0) {
        if (errno == EINTR) return true;
        return false;
    }
    
    if (ret == 0) return true;  /* Timeout */
    
    /* Data from PTY to client */
    if (FD_ISSET(master_fd, &readfds)) {
        n = read(master_fd, buffer, sizeof(buffer));
        if (n <= 0) return false;
        if (write(client_fd, buffer, n) != n) return false;
    }
    
    /* Data from client to PTY */
    if (FD_ISSET(client_fd, &readfds)) {
        n = read(client_fd, buffer, sizeof(buffer));
        if (n <= 0) return false;
        if (write(master_fd, buffer, n) != n) return false;
    }
    
    return true;
}

void pty_kill_session(session_t *session) {
    if (session->pid > 0) {
        kill(session->pid, SIGTERM);
        usleep(100000);  /* 100ms */
        kill(session->pid, SIGKILL);
    }
    
    if (session->master_fd >= 0) {
        close(session->master_fd);
        session->master_fd = -1;
    }
    
    session->status = SESSION_STATUS_DEAD;
    session->pid = 0;
}
