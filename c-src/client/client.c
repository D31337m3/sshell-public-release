/*
 * client.c - SShell client version 1.6
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
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <openssl/rand.h>

static volatile sig_atomic_t g_window_resized = 0;
static volatile sig_atomic_t g_interrupted = 0;
static bool g_use_unix_socket = false;
static char g_remote_host[256] = "127.0.0.1";
static int g_remote_port = 7444;
static char g_unix_socket_path[512] = {0};
static char g_auth_wallet_address[128] = {0};
static char g_auth_wallet_message[256] = {0};
static char g_auth_wallet_signature[256] = {0};
static char g_auth_ssh_key_id[128] = {0};

static void ensure_wallet_signature_or_print_instructions(const char *operation) {
    if (g_use_unix_socket) {
        return;
    }

    if (!g_auth_wallet_address[0]) {
        return;
    }

    if (g_auth_wallet_message[0] && g_auth_wallet_signature[0]) {
        return;
    }

    time_t now = time(NULL);
    char message[256];
    snprintf(message,
             sizeof(message),
             "SSHell v1.6.1 auth %ld %.96s:%d %.64s",
             (long)now,
             g_remote_host,
             g_remote_port,
             operation ? operation : "");

    fprintf(stderr, "Wallet auth requested but missing message/signature.\n\n");
    fprintf(stderr, "1) In MetaMask, sign this message (personal_sign):\n\n");
    fprintf(stderr, "%s\n\n", message);
    fprintf(stderr, "2) Re-run with:\n");
    fprintf(stderr,
            "   sshell --wallet %s --wallet-message \"%s\" --wallet-signature 0x... <command>\n\n",
            g_auth_wallet_address,
            message);
    exit(2);
}

static void apply_auth(message_t *msg) {
    if (!msg) {
        return;
    }

    if (g_auth_wallet_address[0]) {
        snprintf(msg->auth_wallet_address,
                 sizeof(msg->auth_wallet_address),
                 "%s",
                 g_auth_wallet_address);
    }
    if (g_auth_wallet_message[0]) {
        snprintf(msg->auth_wallet_message,
                 sizeof(msg->auth_wallet_message),
                 "%s",
                 g_auth_wallet_message);
    }
    if (g_auth_wallet_signature[0]) {
        snprintf(msg->auth_wallet_signature,
                 sizeof(msg->auth_wallet_signature),
                 "%s",
                 g_auth_wallet_signature);
    }
    if (g_auth_ssh_key_id[0]) {
        snprintf(msg->auth_ssh_key_id,
                 sizeof(msg->auth_ssh_key_id),
                 "%s",
                 g_auth_ssh_key_id);
    }
}

static void sigwinch_handler(int sig) {
    (void)sig;
    g_window_resized = 1;
}

static void sigint_handler(int sig) {
    (void)sig;
    g_interrupted = 1;
}

static bool is_local_host(const char *host) {
    return strcmp(host, "127.0.0.1") == 0 ||
           strcmp(host, "localhost") == 0 ||
           strcmp(host, "::1") == 0;
}

static bool parse_session_host_target(const char *input,
                                      char *session_out,
                                      size_t session_out_size,
                                      char *host_out,
                                      size_t host_out_size,
                                      int *port_out) {
    const char *at = strchr(input, '@');
    if (!at || at == input || *(at + 1) == '\0') {
        return false;
    }

    size_t session_len = (size_t)(at - input);
    if (session_len >= session_out_size) {
        return false;
    }

    memcpy(session_out, input, session_len);
    session_out[session_len] = '\0';

    const char *host_part = at + 1;
    const char *colon = strrchr(host_part, ':');
    if (colon && *(colon + 1) != '\0') {
        size_t host_len = (size_t)(colon - host_part);
        if (host_len == 0 || host_len >= host_out_size) {
            return false;
        }
        memcpy(host_out, host_part, host_len);
        host_out[host_len] = '\0';

        int port_value = atoi(colon + 1);
        if (port_value <= 0 || port_value > 65535) {
            return false;
        }
        *port_out = port_value;
        return true;
    }

    snprintf(host_out, host_out_size, "%s", host_part);
    return true;
}

static bool is_share_token(const char *value) {
    return value && strncmp(value, "share-", 6) == 0;
}

static void generate_share_token(char *out, size_t out_size) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    if (!out || out_size < 16) {
        return;
    }

    unsigned char random_bytes[24];
    if (RAND_bytes(random_bytes, (int)sizeof(random_bytes)) != 1) {
        srand((unsigned int)time(NULL));
        for (size_t i = 0; i < sizeof(random_bytes); i++) {
            random_bytes[i] = (unsigned char)(rand() & 0xff);
        }
    }

    char suffix[33];
    size_t suffix_len = 22;
    if (suffix_len >= sizeof(suffix)) {
        suffix_len = sizeof(suffix) - 1;
    }
    for (size_t i = 0; i < suffix_len; i++) {
        suffix[i] = charset[random_bytes[i] % (sizeof(charset) - 1)];
    }
    suffix[suffix_len] = '\0';

    snprintf(out, out_size, "share-%s", suffix);
}

static int connect_daemon(void) {
    if (!g_use_unix_socket) {
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", g_remote_port);

        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        struct addrinfo *result = NULL;
        if (getaddrinfo(g_remote_host, port_str, &hints, &result) != 0) {
            return -1;
        }

        int sockfd = -1;
        for (struct addrinfo *entry = result; entry != NULL; entry = entry->ai_next) {
            sockfd = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
            if (sockfd < 0) {
                continue;
            }

            if (connect(sockfd, entry->ai_addr, entry->ai_addrlen) == 0) {
                break;
            }

            close(sockfd);
            sockfd = -1;
        }

        freeaddrinfo(result);
        return sockfd;
    }

    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    const char *socket_path = g_unix_socket_path[0] ? g_unix_socket_path : g_config.socket_path;
    if (strlen(socket_path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "Socket path too long: %s\n", socket_path);
        close(sockfd);
        return -1;
    }
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
    
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
        if (g_use_unix_socket) {
            execl("/usr/local/bin/sshell-daemon-c", "sshell-daemon-c", "--unix", NULL);
            execl("./build/sshell-daemon", "sshell-daemon", "--unix", NULL);
        } else {
            char port_text[16];
            snprintf(port_text, sizeof(port_text), "%d", g_remote_port);
            execl("/usr/local/bin/sshell-daemon-c",
                  "sshell-daemon-c",
                  "--tcp",
                  "--port",
                  port_text,
                  NULL);
            execl("./build/sshell-daemon",
                  "sshell-daemon",
                  "--tcp",
                  "--port",
                  port_text,
                  NULL);
        }
        _exit(1);
    }
    
    /* Parent process - wait for daemon to start */
    sleep(1);
    return 0;
}

static int ensure_daemon_running(void) {
    if (!g_use_unix_socket) {
        int sockfd = connect_daemon();
        if (sockfd >= 0) {
            close(sockfd);
            return 0;
        }

        if (is_local_host(g_remote_host)) {
            printf("Starting SShell daemon (tcp://%s:%d)...\n", g_remote_host, g_remote_port);
            if (start_daemon() < 0) {
                fprintf(stderr, "Error: Failed to start daemon\n");
                return -1;
            }

            for (int i = 0; i < 5; i++) {
                sleep(1);
                sockfd = connect_daemon();
                if (sockfd >= 0) {
                    close(sockfd);
                    return 0;
                }
            }
        }

        fprintf(stderr,
                "Error: Cannot connect to remote daemon at %s:%d\n",
                g_remote_host,
                g_remote_port);
        return -1;
    }

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
    ensure_wallet_signature_or_print_instructions("resize");
    int sockfd = connect_daemon();
    if (sockfd < 0) return;
    
    int rows, cols;
    terminal_get_size(STDIN_FILENO, &rows, &cols);
    
    message_t msg = {0};
    msg.command = CMD_RESIZE;
    snprintf(msg.session_id, sizeof(msg.session_id), "%s", session_id);
    msg.rows = rows;
    msg.cols = cols;
    apply_auth(&msg);
    
    send_message(sockfd, &msg);
    
    response_t resp;
    recv_response(sockfd, &resp);
    
    close(sockfd);
}

static void cmd_attach(const char *target) {
    ensure_wallet_signature_or_print_instructions("attach");
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
    apply_auth(&msg);
    
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

static void cmd_join(const char *token) {
    if (ensure_daemon_running() < 0) return;

    int sockfd = connect_daemon();
    if (sockfd < 0) {
        fprintf(stderr, "Error: Cannot connect to daemon\n");
        exit(1);
    }

    int rows, cols;
    terminal_get_size(STDIN_FILENO, &rows, &cols);

    message_t msg = {0};
    msg.command = CMD_JOIN;
    snprintf(msg.share_token, sizeof(msg.share_token), "%s", token);
    msg.rows = rows;
    msg.cols = cols;

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

    if (resp.status != STATUS_OK) {
        fprintf(stderr, "Error: %s\n", resp.message);
        close(sockfd);
        exit(1);
    }

    terminal_state_t term_state;
    terminal_init(&term_state);

    if (terminal_enter_raw_mode(&term_state, STDIN_FILENO) < 0) {
        fprintf(stderr, "Error: Failed to enter raw mode\n");
        close(sockfd);
        exit(1);
    }

    signal(SIGWINCH, sigwinch_handler);
    signal(SIGINT, sigint_handler);

    terminal_set_nonblocking(STDIN_FILENO);
    terminal_set_nonblocking(sockfd);

    char detach_state = 0;
    bool detaching = false;

    while (!detaching && !g_interrupted) {
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

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            char buf[4096];
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0) break;

            for (ssize_t i = 0; i < n; i++) {
                if (detach_state == 0 && buf[i] == 0x02) {
                    detach_state = 1;
                    continue;
                } else if (detach_state == 1) {
                    if (buf[i] == 'd' || buf[i] == 'D') {
                        detaching = true;
                        break;
                    } else {
                        write(sockfd, "\x02", 1);
                        detach_state = 0;
                    }
                }

                if (write(sockfd, &buf[i], 1) < 0) {
                    detaching = true;
                    break;
                }
            }
        }

        if (FD_ISSET(sockfd, &readfds)) {
            char buf[4096];
            ssize_t n = read(sockfd, buf, sizeof(buf));
            if (n <= 0) break;

            if (write(STDOUT_FILENO, buf, n) < 0) {
                break;
            }
        }
    }

    terminal_restore(&term_state, STDIN_FILENO);
    close(sockfd);

    if (detaching) {
        printf("\n[detached]\n");
    }
}

static void cmd_share(const char *session_name) {
    ensure_wallet_signature_or_print_instructions("share");
    if (ensure_daemon_running() < 0) return;

    int sockfd = connect_daemon();
    if (sockfd < 0) {
        fprintf(stderr, "Error: Cannot connect to daemon\n");
        exit(1);
    }

    char token[128];
    memset(token, 0, sizeof(token));
    generate_share_token(token, sizeof(token));

    message_t msg = {0};
    msg.command = CMD_SHARE;
    snprintf(msg.session_name, sizeof(msg.session_name), "%s", session_name);
    snprintf(msg.share_token, sizeof(msg.share_token), "%s", token);
    apply_auth(&msg);

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

    if (resp.status != STATUS_OK) {
        fprintf(stderr, "Error: %s\n", resp.message);
        close(sockfd);
        exit(1);
    }

    printf("%s\n", token);
    close(sockfd);
}

static void cmd_stopshare(const char *session_name_or_null) {
    ensure_wallet_signature_or_print_instructions("stopshare");
    if (ensure_daemon_running() < 0) return;

    int sockfd = connect_daemon();
    if (sockfd < 0) {
        fprintf(stderr, "Error: Cannot connect to daemon\n");
        exit(1);
    }

    message_t msg = {0};
    msg.command = CMD_STOPSHARE;
    if (session_name_or_null && session_name_or_null[0]) {
        snprintf(msg.session_name, sizeof(msg.session_name), "%s", session_name_or_null);
    }
    apply_auth(&msg);

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

    if (resp.status != STATUS_OK) {
        fprintf(stderr, "Error: %s\n", resp.message);
        close(sockfd);
        exit(1);
    }

    printf("%s\n", resp.message);
    close(sockfd);
}

static void cmd_new(const char *name, const char *shell, bool no_attach) {
    ensure_wallet_signature_or_print_instructions("new");
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
    apply_auth(&msg);
    
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
    ensure_wallet_signature_or_print_instructions("list");
    if (ensure_daemon_running() < 0) return;
    
    int sockfd = connect_daemon();
    if (sockfd < 0) {
        fprintf(stderr, "Error: Cannot connect to daemon\n");
        exit(1);
    }
    
    message_t msg = {0};
    msg.command = CMD_LIST;
    apply_auth(&msg);
    
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

    if (resp.status != STATUS_OK) {
        fprintf(stderr, "Error: %s\n", resp.message);
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
    ensure_wallet_signature_or_print_instructions("kill");
    if (ensure_daemon_running() < 0) return;
    
    int sockfd = connect_daemon();
    if (sockfd < 0) {
        fprintf(stderr, "Error: Cannot connect to daemon\n");
        exit(1);
    }
    
    message_t msg = {0};
    msg.command = CMD_KILL;
    strncpy(msg.session_name, target, sizeof(msg.session_name) - 1);
    apply_auth(&msg);
    
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
    ensure_wallet_signature_or_print_instructions("rename");
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
    apply_auth(&msg);
    
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
    printf("Global options:\n");
    printf("  --host HOST              Daemon host for TCP mode (default: 127.0.0.1)\n");
    printf("  --port PORT              Daemon TCP port (default: 7444)\n");
    printf("  --unix                   Use Unix socket mode (optional legacy mode)\n");
    printf("  --socket PATH            Unix socket path override\n");
    printf("  --wallet-address ADDR    Wallet address for auth\n");
    printf("  --wallet ADDR            Alias for --wallet-address\n");
    printf("  --wallet-message MSG     Wallet signed message text\n");
    printf("  --wallet-signature SIG   Wallet signature (0x...)\n");
    printf("  --ssh-key-id ID          SSH-key style fallback identity\n");
    printf("\n");
    printf("Quick connect:\n");
    printf("  %s SESSION@HOST[:PORT]   Attach to session on remote host\n\n", progname);
    printf("  %s share-TOKEN@HOST[:PORT]  Join a shared session (guest)\n\n", progname);
    printf("Commands:\n");
    printf("  --new [NAME]             Alias for new\n");
    printf("  new [NAME]              Create a new session\n");
    printf("    -s, --shell SHELL     Specify shell to use\n");
    printf("    --no-attach           Don't attach after creating\n");
    printf("\n");
    printf("  attach TARGET           Attach to a session\n");
    printf("  --share TARGET          Enable sharing (prints share token)\n");
    printf("  --stopshare [TARGET]    Disable sharing (disconnect guests)\n");
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

    int command_index = 1;
    while (command_index < argc) {
        if (strcmp(argv[command_index], "--unix") == 0) {
            g_use_unix_socket = true;
            command_index++;
            continue;
        }

        if (strcmp(argv[command_index], "--socket") == 0) {
            if (command_index + 1 >= argc) {
                fprintf(stderr, "Error: --socket requires a value\n");
                return 1;
            }
            g_use_unix_socket = true;
            snprintf(g_unix_socket_path, sizeof(g_unix_socket_path), "%s", argv[command_index + 1]);
            command_index += 2;
            continue;
        }

        if (strcmp(argv[command_index], "--host") == 0) {
            if (command_index + 1 >= argc) {
                fprintf(stderr, "Error: --host requires a value\n");
                return 1;
            }
            g_use_unix_socket = false;
            snprintf(g_remote_host, sizeof(g_remote_host), "%s", argv[command_index + 1]);
            command_index += 2;
            continue;
        }

        if (strcmp(argv[command_index], "--port") == 0) {
            if (command_index + 1 >= argc) {
                fprintf(stderr, "Error: --port requires a value\n");
                return 1;
            }
            g_use_unix_socket = false;
            g_remote_port = atoi(argv[command_index + 1]);
            if (g_remote_port <= 0 || g_remote_port > 65535) {
                fprintf(stderr, "Error: invalid port: %s\n", argv[command_index + 1]);
                return 1;
            }
            command_index += 2;
            continue;
        }

        if (strcmp(argv[command_index], "--wallet-address") == 0) {
            if (command_index + 1 >= argc) {
                fprintf(stderr, "Error: --wallet-address requires a value\n");
                return 1;
            }
            snprintf(g_auth_wallet_address,
                     sizeof(g_auth_wallet_address),
                     "%s",
                     argv[command_index + 1]);
            command_index += 2;
            continue;
        }

        if (strcmp(argv[command_index], "--wallet") == 0) {
            if (command_index + 1 >= argc) {
                fprintf(stderr, "Error: --wallet requires a value\n");
                return 1;
            }
            snprintf(g_auth_wallet_address,
                     sizeof(g_auth_wallet_address),
                     "%s",
                     argv[command_index + 1]);
            command_index += 2;
            continue;
        }

        if (strcmp(argv[command_index], "--wallet-message") == 0) {
            if (command_index + 1 >= argc) {
                fprintf(stderr, "Error: --wallet-message requires a value\n");
                return 1;
            }
            snprintf(g_auth_wallet_message,
                     sizeof(g_auth_wallet_message),
                     "%s",
                     argv[command_index + 1]);
            command_index += 2;
            continue;
        }

        if (strcmp(argv[command_index], "--wallet-signature") == 0) {
            if (command_index + 1 >= argc) {
                fprintf(stderr, "Error: --wallet-signature requires a value\n");
                return 1;
            }
            snprintf(g_auth_wallet_signature,
                     sizeof(g_auth_wallet_signature),
                     "%s",
                     argv[command_index + 1]);
            command_index += 2;
            continue;
        }

        if (strcmp(argv[command_index], "--ssh-key-id") == 0) {
            if (command_index + 1 >= argc) {
                fprintf(stderr, "Error: --ssh-key-id requires a value\n");
                return 1;
            }
            snprintf(g_auth_ssh_key_id,
                     sizeof(g_auth_ssh_key_id),
                     "%s",
                     argv[command_index + 1]);
            command_index += 2;
            continue;
        }

        break;
    }

    if (command_index >= argc) {
        /* Default: create new session and attach */
        cmd_new(NULL, NULL, false);
        return 0;
    }
    
    const char *command = argv[command_index];

    if (strcmp(command, "--share") == 0) {
        if (command_index + 1 >= argc) {
            fprintf(stderr, "Error: --share requires a session name or SESSION@HOST[:PORT]\n");
            return 1;
        }

        char parsed_session[256] = {0};
        char parsed_host[256] = {0};
        int parsed_port = g_remote_port;
        if (parse_session_host_target(argv[command_index + 1],
                                      parsed_session,
                                      sizeof(parsed_session),
                                      parsed_host,
                                      sizeof(parsed_host),
                                      &parsed_port)) {
            g_use_unix_socket = false;
            snprintf(g_remote_host, sizeof(g_remote_host), "%s", parsed_host);
            g_remote_port = parsed_port;
            cmd_share(parsed_session);
        } else {
            cmd_share(argv[command_index + 1]);
        }
        return 0;
    }

    if (strcmp(command, "--stopshare") == 0) {
        const char *session = NULL;
        char parsed_session[256] = {0};
        char parsed_host[256] = {0};
        int parsed_port = g_remote_port;

        if (command_index + 1 < argc) {
            if (parse_session_host_target(argv[command_index + 1],
                                          parsed_session,
                                          sizeof(parsed_session),
                                          parsed_host,
                                          sizeof(parsed_host),
                                          &parsed_port)) {
                g_use_unix_socket = false;
                snprintf(g_remote_host, sizeof(g_remote_host), "%s", parsed_host);
                g_remote_port = parsed_port;
                session = parsed_session;
            } else {
                session = argv[command_index + 1];
            }
        }

        cmd_stopshare(session);
        return 0;
    }
    
    if (strcmp(command, "new") == 0 || strcmp(command, "--new") == 0 || strcmp(command, "-new") == 0) {
        const char *name = NULL;
        char name_buf[256] = {0};
        const char *shell = NULL;
        bool no_attach = false;
        
        for (int i = command_index + 1; i < argc; i++) {
            if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--shell") == 0) {
                if (i + 1 < argc) {
                    shell = argv[++i];
                }
            } else if (strcmp(argv[i], "--no-attach") == 0) {
                no_attach = true;
            } else if (!name) {
                char parsed_session[256] = {0};
                char parsed_host[256] = {0};
                int parsed_port = g_remote_port;
                if (parse_session_host_target(argv[i],
                                              parsed_session,
                                              sizeof(parsed_session),
                                              parsed_host,
                                              sizeof(parsed_host),
                                              &parsed_port)) {
                    g_use_unix_socket = false;
                    snprintf(g_remote_host, sizeof(g_remote_host), "%s", parsed_host);
                    g_remote_port = parsed_port;
                    snprintf(name_buf, sizeof(name_buf), "%s", parsed_session);
                    name = name_buf;
                } else {
                    name = argv[i];
                }
            }
        }
        
        cmd_new(name, shell, no_attach);
        
    } else if (strcmp(command, "attach") == 0) {
        if (command_index + 1 >= argc) {
            fprintf(stderr, "Error: attach requires a session name or ID\n");
            return 1;
        }

        char parsed_session[256] = {0};
        char parsed_host[256] = {0};
        int parsed_port = g_remote_port;
        if (parse_session_host_target(argv[command_index + 1],
                                      parsed_session,
                                      sizeof(parsed_session),
                                      parsed_host,
                                      sizeof(parsed_host),
                                      &parsed_port)) {
            g_use_unix_socket = false;
            snprintf(g_remote_host, sizeof(g_remote_host), "%s", parsed_host);
            g_remote_port = parsed_port;
            if (is_share_token(parsed_session)) {
                cmd_join(parsed_session);
            } else {
                cmd_attach(parsed_session);
            }
        } else {
            cmd_attach(argv[command_index + 1]);
        }
        
    } else if (strcmp(command, "list") == 0 || strcmp(command, "ls") == 0) {
        cmd_list();
        
    } else if (strcmp(command, "kill") == 0) {
        if (command_index + 1 >= argc) {
            fprintf(stderr, "Error: kill requires a session name or ID\n");
            return 1;
        }
        cmd_kill(argv[command_index + 1]);
        
    } else if (strcmp(command, "rename") == 0) {
        if (command_index + 2 >= argc) {
            fprintf(stderr, "Error: rename requires old and new names\n");
            return 1;
        }
        cmd_rename(argv[command_index + 1], argv[command_index + 2]);
        
    } else if (strcmp(command, "--version") == 0 || strcmp(command, "-v") == 0) {
        printf("SSHell v1.6.1  -  (C) - D31337m3.com\n");
        return 0;
        
    } else if (strcmp(command, "--help") == 0 || strcmp(command, "-h") == 0) {
        print_usage(argv[0]);
        return 0;
        
    } else {
        char parsed_session[256] = {0};
        char parsed_host[256] = {0};
        int parsed_port = g_remote_port;
        if (parse_session_host_target(command,
                                      parsed_session,
                                      sizeof(parsed_session),
                                      parsed_host,
                                      sizeof(parsed_host),
                                      &parsed_port)) {
            g_use_unix_socket = false;
            snprintf(g_remote_host, sizeof(g_remote_host), "%s", parsed_host);
            g_remote_port = parsed_port;
            if (is_share_token(parsed_session)) {
                cmd_join(parsed_session);
            } else {
                cmd_attach(parsed_session);
            }
            return 0;
        }

        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(argv[0]);
        return 1;
    }
    
    return 0;
}
