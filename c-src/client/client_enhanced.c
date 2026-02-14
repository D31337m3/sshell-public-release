/*
 * client_enhanced.c - Enhanced SShell client with full functionality
 */

#include "../common/config.h"
#include "../common/protocol.h"
#include "../common/session.h"
#include "../common/terminal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

static volatile sig_atomic_t g_window_resized = 0;
static volatile sig_atomic_t g_interrupted = 0;

static void sigwinch_handler(int sig) {
    (void)sig;
    g_window_resized = 1;
}

static void sigint_handler(int sig) {
    (void)sig;
    g_interrupted = 1;
}

static int connect_daemon(void) {
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_config.socket_path, sizeof(addr.sun_path) - 1);
    
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

static int start_daemon(void) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    
    if (pid == 0) {
        /* Child process */
        setsid();
        
        /* Close standard file descriptors */
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        
        /* Execute daemon */
        execl("/usr/local/bin/sshell-daemon-c", "sshell-daemon-c", NULL);
        execl("./build/sshell-daemon", "sshell-daemon", NULL);
        _exit(1);
    }
    
    /* Parent process - wait for daemon to start */
    sleep(1);
    return 0;
}

static int ensure_daemon_running(void) {
    int sockfd = connect_daemon();
    if (sockfd >= 0) {
        close(sockfd);
        return 0;
    }
    
    /* Daemon not running, start it */
    printf("Starting SShell daemon...\n");
    if (start_daemon() < 0) {
        fprintf(stderr, "Error: Failed to start daemon\n");
        return -1;
    }
    
    /* Try connecting again */
    for (int i = 0; i < 5; i++) {
        sleep(1);
        sockfd = connect_daemon();
        if (sockfd >= 0) {
            close(sockfd);
            return 0;
        }
    }
    
    fprintf(stderr, "Error: Daemon did not start successfully\n");
    return -1;
}

static void send_resize(const char *session_id) {
    int sockfd = connect_daemon();
    if (sockfd < 0) return;
    
    int rows, cols;
    terminal_get_size(STDIN_FILENO, &rows, &cols);
    
    message_t msg = {0};
    msg.command = CMD_RESIZE;
    strncpy(msg.session_id, session_id, sizeof(msg.session_id) - 1);
    msg.rows = rows;
    msg.cols = cols;
    
    send_message(sockfd, &msg);
    
    response_t resp;
    recv_response(sockfd, &resp);
    
    close(sockfd);
}

static void cmd_attach(const char *target) {
    if (ensure_daemon_running() < 0) return;
    
    int sockfd = connect_daemon();
    if (sockfd < 0) {
        fprintf(stderr, "Error: Cannot connect to daemon\n");
        exit(1);
    }
    
    /* Get terminal size */
    int rows, cols;
    terminal_get_size(STDIN_FILENO, &rows, &cols);
    
    /* Send attach request */
    message_t msg = {0};
    msg.command = CMD_ATTACH;
    strncpy(msg.session_name, target, sizeof(msg.session_name) - 1);
    msg.rows = rows;
    msg.cols = cols;
    
    if (send_message(sockfd, &msg) < 0) {
        perror("send_message");
        close(sockfd);
        exit(1);
    }
    
    /* Receive response */
    response_t resp;
    if (recv_response(sockfd, &resp) < 0) {
        perror("recv_response");
        close(sockfd);
        exit(1);
    }
    
    if (resp.status != STATUS_OK) {
        fprintf(stderr, "Error: %s\n", resp.message);
        close(sockfd);
        exit(1);
    }
    
    /* Extract session ID from target for resize notifications */
    char session_id[64] = {0};
    strncpy(session_id, target, sizeof(session_id) - 1);
    
    /* Enter raw mode and attach */
    terminal_state_t term_state;
    terminal_init(&term_state);
    
    if (terminal_enter_raw_mode(&term_state, STDIN_FILENO) < 0) {
        fprintf(stderr, "Error: Failed to enter raw mode\n");
        close(sockfd);
        exit(1);
    }
    
    /* Set up signal handlers */
    signal(SIGWINCH, sigwinch_handler);
    signal(SIGINT, sigint_handler);
    
    /* Make stdin and socket non-blocking */
    terminal_set_nonblocking(STDIN_FILENO);
    terminal_set_nonblocking(sockfd);
    
    /* I/O loop with detach key detection */
    char detach_state = 0;  /* 0 = normal, 1 = saw Ctrl+B */
    bool detaching = false;
    
    while (!detaching && !g_interrupted) {
        /* Handle window resize */
        if (g_window_resized) {
            g_window_resized = 0;
            send_resize(session_id);
        }
        
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sockfd, &readfds);
        
        struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};
        
        int ret = select(sockfd + 1, &readfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        
        /* Data from stdin to session */
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            char buf[4096];
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0) break;
            
            /* Check for detach key sequence: Ctrl+B then 'd' */
            for (ssize_t i = 0; i < n; i++) {
                if (detach_state == 0 && buf[i] == 0x02) {  /* Ctrl+B */
                    detach_state = 1;
                    continue;  /* Don't send Ctrl+B */
                } else if (detach_state == 1) {
                    if (buf[i] == 'd' || buf[i] == 'D') {
                        detaching = true;
                        break;
                    } else {
                        /* False alarm, send Ctrl+B and continue */
                        write(sockfd, "\x02", 1);
                        detach_state = 0;
                    }
                }
                
                /* Send character */
                if (write(sockfd, &buf[i], 1) < 0) {
                    detaching = true;
                    break;
                }
            }
        }
        
        /* Data from session to stdout */
        if (FD_ISSET(sockfd, &readfds)) {
            char buf[4096];
            ssize_t n = read(sockfd, buf, sizeof(buf));
            if (n <= 0) break;
            
            if (write(STDOUT_FILENO, buf, n) < 0) {
                break;
            }
        }
    }
    
    /* Restore terminal */
    terminal_restore(&term_state, STDIN_FILENO);
    close(sockfd);
    
    if (detaching) {
        printf("\n[detached]\n");
    }
}

static void cmd_new(const char *name, const char *shell, bool no_attach) {
    if (ensure_daemon_running() < 0) return;
    
    int sockfd = connect_daemon();
    if (sockfd < 0) {
        fprintf(stderr, "Error: Cannot connect to daemon\n");
        exit(1);
    }
    
    message_t msg = {0};
    msg.command = CMD_CREATE;
    if (name) {
        strncpy(msg.session_name, name, sizeof(msg.session_name) - 1);
    }
    if (shell) {
        strncpy(msg.shell, shell, sizeof(msg.shell) - 1);
    }
    msg.no_attach = no_attach;
    
    if (send_message(sockfd, &msg) < 0) {
        perror("send_message");
        close(sockfd);
        exit(1);
    }
    
    response_t resp;
    if (recv_response(sockfd, &resp) < 0) {
        perror("recv_response");
        close(sockfd);
        exit(1);
    }
    
    if (resp.status == STATUS_OK) {
        printf("%s\n", resp.message);
        
        /* If not no_attach and we have a name, attach to it */
        if (!no_attach && name) {
            close(sockfd);
            cmd_attach(name);
        }
    } else {
        fprintf(stderr, "Error: %s\n", resp.message);
        exit(1);
    }
    
    close(sockfd);
}

static void cmd_list(void) {
    if (ensure_daemon_running() < 0) return;
    
    int sockfd = connect_daemon();
    if (sockfd < 0) {
        fprintf(stderr, "Error: Cannot connect to daemon\n");
        exit(1);
    }
    
    message_t msg = {0};
    msg.command = CMD_LIST;
    
    if (send_message(sockfd, &msg) < 0) {
        perror("send_message");
        close(sockfd);
        exit(1);
    }
    
    response_t resp;
    if (recv_response(sockfd, &resp) < 0) {
        perror("recv_response");
        close(sockfd);
        exit(1);
    }
    
    printf("%-10s %-20s %-10s %-8s %s\n", "ID", "Name", "Status", "PID", "Created");
    printf("----------------------------------------------------------------------\n");
    
    /* Read session JSON strings */
    for (int i = 0; i < 100; i++) {
        uint32_t len;
        if (read(sockfd, &len, sizeof(len)) != sizeof(len)) break;
        
        char *json = malloc(len);
        if (!json) break;
        
        if (read(sockfd, json, len) != (ssize_t)len) {
            free(json);
            break;
        }
        
        session_t *session = session_from_json(json);
        free(json);
        
        if (session) {
            const char *status_str = "unknown";
            switch (session->status) {
                case SESSION_STATUS_CREATED: status_str = "created"; break;
                case SESSION_STATUS_RUNNING: status_str = "running"; break;
                case SESSION_STATUS_ATTACHED: status_str = "attached"; break;
                case SESSION_STATUS_DEAD: status_str = "dead"; break;
            }
            
            char created[32];
            struct tm *tm_info = localtime(&session->created);
            strftime(created, sizeof(created), "%Y-%m-%d %H:%M:%S", tm_info);
            
            printf("%-10s %-20s %-10s %-8d %s\n",
                   session->id, session->name, status_str, session->pid, created);
            
            session_free(session);
        }
    }
    
    close(sockfd);
}

static void cmd_kill(const char *target) {
    if (ensure_daemon_running() < 0) return;
    
    int sockfd = connect_daemon();
    if (sockfd < 0) {
        fprintf(stderr, "Error: Cannot connect to daemon\n");
        exit(1);
    }
    
    message_t msg = {0};
    msg.command = CMD_KILL;
    strncpy(msg.session_name, target, sizeof(msg.session_name) - 1);
    
    if (send_message(sockfd, &msg) < 0) {
        perror("send_message");
        close(sockfd);
        exit(1);
    }
    
    response_t resp;
    if (recv_response(sockfd, &resp) < 0) {
        perror("recv_response");
        close(sockfd);
        exit(1);
    }
    
    if (resp.status == STATUS_OK) {
        printf("%s\n", resp.message);
    } else {
        fprintf(stderr, "Error: %s\n", resp.message);
        exit(1);
    }
    
    close(sockfd);
}

static void cmd_rename(const char *old_name, const char *new_name) {
    if (ensure_daemon_running() < 0) return;
    
    int sockfd = connect_daemon();
    if (sockfd < 0) {
        fprintf(stderr, "Error: Cannot connect to daemon\n");
        exit(1);
    }
    
    message_t msg = {0};
    msg.command = CMD_RENAME;
    strncpy(msg.session_name, old_name, sizeof(msg.session_name) - 1);
    strncpy(msg.new_name, new_name, sizeof(msg.new_name) - 1);
    
    if (send_message(sockfd, &msg) < 0) {
        perror("send_message");
        close(sockfd);
        exit(1);
    }
    
    response_t resp;
    if (recv_response(sockfd, &resp) < 0) {
        perror("recv_response");
        close(sockfd);
        exit(1);
    }
    
    if (resp.status == STATUS_OK) {
        printf("%s\n", resp.message);
    } else {
        fprintf(stderr, "Error: %s\n", resp.message);
        exit(1);
    }
    
    close(sockfd);
}

static void print_usage(const char *progname) {
    printf("Usage: %s [COMMAND] [OPTIONS]\n\n", progname);
    printf("Commands:\n");
    printf("  new [NAME]              Create a new session\n");
    printf("    -s, --shell SHELL     Specify shell to use\n");
    printf("    --no-attach           Don't attach after creating\n");
    printf("\n");
    printf("  attach TARGET           Attach to a session\n");
    printf("  list, ls                List all sessions\n");
    printf("  kill TARGET             Kill a session\n");
    printf("  rename OLD NEW          Rename a session\n");
    printf("\n");
    printf("  --version               Show version\n");
    printf("  --help                  Show this help\n");
    printf("\n");
    printf("Detaching:\n");
    printf("  While attached, press Ctrl+B then 'd' to detach.\n");
    printf("\n");
}

int main(int argc, char **argv) {
    srand(time(NULL));
    config_init();
    
    if (argc < 2) {
        /* Default: create new session and attach */
        cmd_new(NULL, NULL, false);
        return 0;
    }
    
    const char *command = argv[1];
    
    if (strcmp(command, "new") == 0) {
        const char *name = NULL;
        const char *shell = NULL;
        bool no_attach = false;
        
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--shell") == 0) {
                if (i + 1 < argc) {
                    shell = argv[++i];
                }
            } else if (strcmp(argv[i], "--no-attach") == 0) {
                no_attach = true;
            } else if (!name) {
                name = argv[i];
            }
        }
        
        cmd_new(name, shell, no_attach);
        
    } else if (strcmp(command, "attach") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: attach requires a session name or ID\n");
            return 1;
        }
        cmd_attach(argv[2]);
        
    } else if (strcmp(command, "list") == 0 || strcmp(command, "ls") == 0) {
        cmd_list();
        
    } else if (strcmp(command, "kill") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: kill requires a session name or ID\n");
            return 1;
        }
        cmd_kill(argv[2]);
        
    } else if (strcmp(command, "rename") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: rename requires old and new names\n");
            return 1;
        }
        cmd_rename(argv[2], argv[3]);
        
    } else if (strcmp(command, "--version") == 0 || strcmp(command, "-v") == 0) {
        printf("SShell (C) version 1.0 - Enhanced\n");
        return 0;
        
    } else if (strcmp(command, "--help") == 0 || strcmp(command, "-h") == 0) {
        print_usage(argv[0]);
        return 0;
        
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(argv[0]);
        return 1;
    }
    
    return 0;
}
