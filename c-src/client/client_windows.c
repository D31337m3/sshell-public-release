/*
 * client_windows.c - SShell Windows client
 * 
 * Windows-compatible client using named pipes instead of Unix sockets
 * Due to Windows limitations, this client only supports basic commands
 * Wsl and unix client should be used for full functionality
 */

#ifdef _WIN32

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PIPE_NAME "\\\\.\\pipe\\sshell"
#define BUFFER_SIZE 4096

typedef enum {
    CMD_CREATE,
    CMD_ATTACH,
    CMD_LIST,
    CMD_KILL,
    CMD_RENAME,
    CMD_STATUS
} command_t;

static int send_command(HANDLE pipe, command_t cmd, const char *session_id) {
    char buffer[BUFFER_SIZE];
    DWORD written, read;
    
    snprintf(buffer, sizeof(buffer), "%d:%s", cmd, session_id ? session_id : "");
    
    if (!WriteFile(pipe, buffer, strlen(buffer), &written, NULL)) {
        fprintf(stderr, "Failed to send command: %lu\n", GetLastError());
        return -1;
    }
    
    if (!ReadFile(pipe, buffer, sizeof(buffer) - 1, &read, NULL)) {
        fprintf(stderr, "Failed to read response: %lu\n", GetLastError());
        return -1;
    }
    
    buffer[read] = '\0';
    printf("%s\n", buffer);
    
    return 0;
}

static HANDLE connect_daemon(void) {
    HANDLE pipe;
    
    /* Try to connect to daemon */
    pipe = CreateFile(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (pipe == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_PIPE_BUSY) {
            fprintf(stderr, "Daemon is busy, please try again\n");
        } else {
            fprintf(stderr, "Daemon not running. Please start sshell-daemon first.\n");
        }
        return INVALID_HANDLE_VALUE;
    }
    
    return pipe;
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("SSHell v1.6.1  -  (C) - D31337m3.com\n");
        return 0;
    }
    
    HANDLE pipe = connect_daemon();
    if (pipe == INVALID_HANDLE_VALUE) {
        return 1;
    }
    
    int ret = 0;
    
    if (argc < 2) {
        /* Default: create and attach */
        ret = send_command(pipe, CMD_CREATE, "default");
    } else if (strcmp(argv[1], "new") == 0) {
        const char *name = argc > 2 ? argv[2] : "default";
        ret = send_command(pipe, CMD_CREATE, name);
    } else if (strcmp(argv[1], "list") == 0) {
        ret = send_command(pipe, CMD_LIST, NULL);
    } else if (strcmp(argv[1], "attach") == 0) {
        const char *name = argc > 2 ? argv[2] : "default";
        ret = send_command(pipe, CMD_ATTACH, name);
    } else if (strcmp(argv[1], "kill") == 0) {
        const char *name = argc > 2 ? argv[2] : NULL;
        if (!name) {
            fprintf(stderr, "Usage: sshell kill <session-name>\n");
            ret = 1;
        } else {
            ret = send_command(pipe, CMD_KILL, name);
        }
    } else if (strcmp(argv[1], "status") == 0) {
        const char *name = argc > 2 ? argv[2] : NULL;
        if (!name) {
            fprintf(stderr, "Usage: sshell status <session-name>\n");
            ret = 1;
        } else {
            ret = send_command(pipe, CMD_STATUS, name);
        }
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        fprintf(stderr, "Usage: sshell [new|list|attach|kill|status] [session-name]\n");
        ret = 1;
    }
    
    CloseHandle(pipe);
    return ret;
}

#endif /* _WIN32 */
