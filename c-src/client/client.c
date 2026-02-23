/*
 * client.c - SShell client version 1.6
 */

#include "../common/config.h"
#include "../common/daemon_preset.h"
#include "../common/network_roaming.h"
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
#include <limits.h>
#include <pthread.h>
#include <openssl/rand.h>
#include <json-c/json.h>

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

/* Forward declarations used by UI helpers (defined later). */
static int connect_daemon(void);
static void apply_auth(message_t *msg);
static void send_resize(const char *session_id);
static bool is_local_host(const char *host);

static void print_usage(const char *prog);

static bool g_cli_set_host = false;

/* ── Network roaming heartbeat ────────────────────────────────────────────── */

typedef struct {
    char session_id[64];
    char host[256];
    int  roaming_port;
    volatile bool stop;
} heartbeat_args_t;

static pthread_t       g_heartbeat_tid;
static bool            g_heartbeat_running = false;
static heartbeat_args_t g_heartbeat_args;

static void *heartbeat_thread(void *arg) {
    heartbeat_args_t *a = (heartbeat_args_t *)arg;
    uint32_t seq = 0;

    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) {
        return NULL;
    }

    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", a->roaming_port);
    if (getaddrinfo(a->host, port_str, &hints, &result) != 0 || !result) {
        close(udp_fd);
        return NULL;
    }

    while (!a->stop) {
        /* Format: "session_id:seq_num" */
        char pkt[96];
        snprintf(pkt, sizeof(pkt), "%s:%u", a->session_id, seq++);
        sendto(udp_fd, pkt, strlen(pkt), 0, result->ai_addr, result->ai_addrlen);

        /* Sleep HEARTBEAT_INTERVAL seconds in 200 ms chunks to check stop flag. */
        int sleep_chunks = (HEARTBEAT_INTERVAL * 1000) / 200;
        for (int i = 0; i < sleep_chunks && !a->stop; i++) {
            usleep(200000);
        }
    }

    freeaddrinfo(result);
    close(udp_fd);
    return NULL;
}

static void start_heartbeat(const char *session_id, const char *host, int roaming_port) {
    if (g_heartbeat_running) return;
    memset(&g_heartbeat_args, 0, sizeof(g_heartbeat_args));
    snprintf(g_heartbeat_args.session_id, sizeof(g_heartbeat_args.session_id), "%s", session_id);
    snprintf(g_heartbeat_args.host, sizeof(g_heartbeat_args.host), "%s", host);
    g_heartbeat_args.roaming_port = roaming_port;
    g_heartbeat_args.stop = false;
    if (pthread_create(&g_heartbeat_tid, NULL, heartbeat_thread, &g_heartbeat_args) == 0) {
        g_heartbeat_running = true;
    }
}

static void stop_heartbeat(void) {
    if (!g_heartbeat_running) return;
    g_heartbeat_args.stop = true;
    pthread_join(g_heartbeat_tid, NULL);
    g_heartbeat_running = false;
}

/* ── end roaming heartbeat ────────────────────────────────────────────────── */

static bool g_cli_set_port = false;
static bool g_cli_set_mode = false;

static void daemon_preset_path(char *out, size_t out_size) {
    if (!out || out_size == 0) {
        return;
    }
    snprintf(out, out_size, "%s/daemon.json", g_config.config_dir);
}

static bool is_unspecified_bind_host(const char *host) {
    if (!host) {
        return false;
    }
    return strcmp(host, "0.0.0.0") == 0 || strcmp(host, "::") == 0;
}

static void apply_daemon_preset_defaults_if_needed(void) {
    /* Only apply presets if user did not explicitly choose host/port/mode.
       This helps keep client+daemon in sync when ~/.sshell/daemon.json changes defaults. */
    if (g_cli_set_mode || g_cli_set_host || g_cli_set_port) {
        return;
    }

    /* Presets are local-daemon defaults; don't rewrite remote connection targets. */
    if (!is_local_host(g_remote_host)) {
        return;
    }

    char preset_path[1024] = {0};
    daemon_preset_path(preset_path, sizeof(preset_path));

    daemon_preset_t preset;
    if (!daemon_preset_load(preset_path, &preset)) {
        return;
    }

    if (preset.has_tcp_mode) {
        g_use_unix_socket = !preset.tcp_mode;
    }

    if (!g_use_unix_socket) {
        if (preset.has_host && preset.host[0]) {
            if (is_unspecified_bind_host(preset.host)) {
                snprintf(g_remote_host, sizeof(g_remote_host), "%s", "127.0.0.1");
            } else {
                snprintf(g_remote_host, sizeof(g_remote_host), "%s", preset.host);
            }
        }
        if (preset.has_port) {
            g_remote_port = preset.port;
        }
    }
}

typedef enum {
    IR_EXIT = 0,
    IR_DETACH,
    IR_SWITCH_LEFT,
    IR_SWITCH_RIGHT
} interactive_result_t;

typedef struct {
    bool is_join;
    char host[256];
    int port;
    char target[256]; /* session name or share token */
} client_session_entry_t;

#define MAX_CLIENT_SESSIONS 16
static client_session_entry_t g_client_sessions[MAX_CLIENT_SESSIONS];
static int g_client_session_count = 0;
static int g_client_session_index = -1;

static void add_client_session(bool is_join, const char *host, int port, const char *target) {
    if (!host || !target || !target[0]) {
        return;
    }

    for (int i = 0; i < g_client_session_count; i++) {
        if (g_client_sessions[i].is_join == is_join &&
            g_client_sessions[i].port == port &&
            strcmp(g_client_sessions[i].host, host) == 0 &&
            strcmp(g_client_sessions[i].target, target) == 0) {
            g_client_session_index = i;
            return;
        }
    }

    if (g_client_session_count >= MAX_CLIENT_SESSIONS) {
        /* Drop oldest */
        for (int i = 0; i < MAX_CLIENT_SESSIONS - 1; i++) {
            g_client_sessions[i] = g_client_sessions[i + 1];
        }
        g_client_session_count = MAX_CLIENT_SESSIONS - 1;
    }

    client_session_entry_t *entry = &g_client_sessions[g_client_session_count];
    memset(entry, 0, sizeof(*entry));
    entry->is_join = is_join;
    snprintf(entry->host, sizeof(entry->host), "%s", host);
    entry->port = port;
    snprintf(entry->target, sizeof(entry->target), "%s", target);
    g_client_session_index = g_client_session_count;
    g_client_session_count++;
}

static bool select_next_client_session(int direction) {
    if (g_client_session_count < 2) {
        return false;
    }

    if (g_client_session_index < 0 || g_client_session_index >= g_client_session_count) {
        g_client_session_index = 0;
        return true;
    }

    int next = g_client_session_index + direction;
    if (next < 0) {
        next = g_client_session_count - 1;
    } else if (next >= g_client_session_count) {
        next = 0;
    }

    g_client_session_index = next;
    return true;
}

typedef struct {
    char session_id[64];
    char session_name[256];
    int user_count;
    bool recording_active;
    char recording_file[512];
    long daemon_uptime_seconds;
} ui_status_t;

static bool ui_fetch_status(const char *session_name, const char *share_token, ui_status_t *out);

static bool g_ui_active = false;
static int g_ui_rows = 0;
static int g_ui_cols = 0;
static char g_ui_host[256] = {0};
static int g_ui_port = 0;
static char g_ui_session_name[256] = {0};
static char g_ui_session_id[64] = {0};
static char g_ui_share_token[128] = {0};
static time_t g_ui_attached_at = 0;
static size_t g_ui_rx_bytes = 0;
static size_t g_ui_tx_bytes = 0;

static void ui_write(const char *s) {
    if (!s) return;
    (void)write(STDOUT_FILENO, s, strlen(s));
}

static void ui_move_abs(int row, int col) {
    char buf[64];
    snprintf(buf, sizeof(buf), "\x1b[%d;%dH", row, col);
    ui_write(buf);
}

static void ui_fill_line(int row, int cols) {
    ui_move_abs(row, 1);
    for (int i = 0; i < cols; i++) {
        ui_write(" ");
    }
}

static void ui_set_scroll_region(int rows) {
    if (rows < 3) {
        return;
    }

    char buf[64];
    /* Scroll region excludes top bar (1) and bottom bar (rows). */
    snprintf(buf, sizeof(buf), "\x1b[2;%dr", rows - 1);
    ui_write(buf);
}

static void ui_enter(int rows, int cols) {
    g_ui_active = true;
    g_ui_rows = rows;
    g_ui_cols = cols;
    g_ui_attached_at = time(NULL);
    g_ui_rx_bytes = 0;
    g_ui_tx_bytes = 0;

    ui_write("\x1b[?1049h\x1b[?25l\x1b[H\x1b[2J");

    /* Use a scroll region for the main terminal area, origin mode makes CUP relative to it. */
    ui_set_scroll_region(rows);
    ui_write("\x1b[?6h");

    /* Clear scroll region by temporarily disabling origin mode. */
    ui_write("\x1b[?6l");
    ui_move_abs(2, 1);
    ui_write("\x1b[J");
    ui_write("\x1b[?6h");
}

static void ui_leave(void) {
    if (!g_ui_active) {
        return;
    }

    /* Absolute addressing + reset scroll region + show cursor + leave alt screen */
    ui_write("\x1b[?6l\x1b[r\x1b[?25h\x1b[?1049l");
    g_ui_active = false;
}

static void ui_draw_bars(const ui_status_t *status) {
    if (!g_ui_active || g_ui_rows < 3 || g_ui_cols < 10) {
        return;
    }

    bool recording = status ? status->recording_active : false;

    const char *bg = recording ? "\x1b[48;5;200m\x1b[38;5;0m" : "\x1b[48;5;54m\x1b[38;5;231m";
    const char *reset = "\x1b[0m";

    /* Save cursor, disable origin mode for absolute positioning */
    ui_write("\x1b" "7" "\x1b[?6l");

    ui_write(bg);
    ui_fill_line(1, g_ui_cols);
    ui_fill_line(g_ui_rows, g_ui_cols);

    char top[1024];
    char bottom[1024];

    long attached_for = (long)(time(NULL) - g_ui_attached_at);
    long daemon_up = status ? status->daemon_uptime_seconds : -1;
    int users = status ? status->user_count : -1;

    const char *sid = (status && status->session_id[0]) ? status->session_id : (g_ui_session_id[0] ? g_ui_session_id : "?");
    const char *sname = (status && status->session_name[0]) ? status->session_name : (g_ui_session_name[0] ? g_ui_session_name : "?");

    snprintf(top,
             sizeof(top),
             " SShell  host:%s:%d  session:%s  id:%s  users:%d  up:%lds  attached:%lds ",
             g_ui_host[0] ? g_ui_host : "?",
             g_ui_port,
             sname,
             sid,
             users,
             daemon_up,
             attached_for);

    snprintf(bottom,
             sizeof(bottom),
             " Ctrl+C exit | Ctrl+B d detach | Shift+\xE2\x86\x90/\xE2\x86\x92 switch | rec-start/rec-stop | rx:%zukB tx:%zukB ",
             g_ui_rx_bytes / 1024,
             g_ui_tx_bytes / 1024);

    ui_move_abs(1, 1);
    (void)write(STDOUT_FILENO, top, (size_t)((int)strlen(top) > g_ui_cols ? g_ui_cols : (int)strlen(top)));
    ui_move_abs(g_ui_rows, 1);
    (void)write(STDOUT_FILENO, bottom, (size_t)((int)strlen(bottom) > g_ui_cols ? g_ui_cols : (int)strlen(bottom)));

    ui_write(reset);

    /* Restore origin mode and cursor */
    ui_write("\x1b[?6h\x1b" "8");
}

static int open_attach_socket(const char *session_name, int pty_rows, int cols) {
    int sockfd = connect_daemon();
    if (sockfd < 0) {
        return -1;
    }

    message_t msg = {0};
    msg.command = CMD_ATTACH;
    snprintf(msg.session_name, sizeof(msg.session_name), "%s", session_name);
    msg.rows = pty_rows;
    msg.cols = cols;
    apply_auth(&msg);

    if (send_message(sockfd, &msg) < 0) {
        close(sockfd);
        return -1;
    }

    response_t resp;
    if (recv_response(sockfd, &resp) < 0) {
        close(sockfd);
        return -1;
    }

    if (resp.status != STATUS_OK) {
        close(sockfd);
        return -2;
    }

    terminal_set_nonblocking(sockfd);
    return sockfd;
}

static int open_join_socket(const char *share_token, int pty_rows, int cols) {
    int sockfd = connect_daemon();
    if (sockfd < 0) {
        return -1;
    }

    message_t msg = {0};
    msg.command = CMD_JOIN;
    snprintf(msg.share_token, sizeof(msg.share_token), "%s", share_token);
    msg.rows = pty_rows;
    msg.cols = cols;

    if (send_message(sockfd, &msg) < 0) {
        close(sockfd);
        return -1;
    }

    response_t resp;
    if (recv_response(sockfd, &resp) < 0) {
        close(sockfd);
        return -1;
    }

    if (resp.status != STATUS_OK) {
        close(sockfd);
        return -2;
    }

    terminal_set_nonblocking(sockfd);
    return sockfd;
}

static interactive_result_t interactive_io_loop(int sockfd,
                                                const char *status_session,
                                                const char *status_token,
                                                const char *resize_session_id,
                                                bool allow_resize) {
    char detach_state = 0;
    bool detaching = false;

    char esc_pending[16];
    size_t esc_len = 0;

    time_t last_ui = 0;
    ui_status_t last_status = {0};
    (void)ui_fetch_status(status_session, status_token, &last_status);
    ui_draw_bars(&last_status);

    while (!detaching && !g_interrupted) {
        if (g_window_resized) {
            g_window_resized = 0;
            if (allow_resize && resize_session_id && resize_session_id[0]) {
                send_resize(resize_session_id);
            }

            int rows, cols;
            terminal_get_size(STDIN_FILENO, &rows, &cols);
            g_ui_rows = rows;
            g_ui_cols = cols;
            ui_set_scroll_region(rows);
        }

        time_t now = time(NULL);
        if (g_ui_active && now != last_ui) {
            last_ui = now;
            ui_status_t st;
            if (ui_fetch_status(status_session, status_token, &st)) {
                last_status = st;
            }
            ui_draw_bars(&last_status);
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

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            char buf[4096];
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0) break;

            for (ssize_t i = 0; i < n; i++) {
                unsigned char c = (unsigned char)buf[i];

                if (c == 0x03) {
                    /* Ctrl+C exits client UI */
                    g_interrupted = 1;
                    detaching = true;
                    break;
                }

                /* Handle detach key sequence: Ctrl+B then 'd' */
                if (detach_state == 0 && c == 0x02) {
                    detach_state = 1;
                    continue;
                } else if (detach_state == 1) {
                    if (c == 'd' || c == 'D') {
                        detaching = true;
                        break;
                    }

                    (void)write(sockfd, "\x02", 1);
                    detach_state = 0;
                }

                /* Shift+Left/Right detection (xterm-style CSI 1;2D/C) */
                if (esc_len == 0 && c == 0x1b) {
                    esc_pending[esc_len++] = (char)c;
                    continue;
                }

                if (esc_len > 0) {
                    if (esc_len < sizeof(esc_pending)) {
                        esc_pending[esc_len++] = (char)c;
                    }

                    if (esc_len >= 6 &&
                        memcmp(esc_pending, "\x1b[1;2", 5) == 0 &&
                        (esc_pending[5] == 'D' || esc_pending[5] == 'C')) {
                        if (g_client_session_count > 1) {
                            esc_len = 0;
                            return (esc_pending[5] == 'D') ? IR_SWITCH_LEFT : IR_SWITCH_RIGHT;
                        }
                    }

                    /* If it's not a CSI modifier sequence, flush after a few bytes */
                    if (esc_len >= 6) {
                        (void)write(sockfd, esc_pending, esc_len);
                        g_ui_tx_bytes += esc_len;
                        esc_len = 0;
                    }
                    continue;
                }

                if (write(sockfd, &buf[i], 1) < 0) {
                    detaching = true;
                    break;
                }
                g_ui_tx_bytes += 1;
            }
        }

        if (FD_ISSET(sockfd, &readfds)) {
            char buf[4096];
            ssize_t n = read(sockfd, buf, sizeof(buf));
            if (n <= 0) break;

            if (write(STDOUT_FILENO, buf, n) < 0) {
                break;
            }
            g_ui_rx_bytes += (size_t)n;
        }
    }

    return IR_DETACH;
}

static bool ui_fetch_status(const char *session_name, const char *share_token, ui_status_t *out) {
    if (!out) {
        return false;
    }

    memset(out, 0, sizeof(*out));

    int sockfd = connect_daemon();
    if (sockfd < 0) {
        return false;
    }

    message_t msg = {0};
    msg.command = CMD_STATUS;
    if (session_name && session_name[0]) {
        snprintf(msg.session_name, sizeof(msg.session_name), "%s", session_name);
        apply_auth(&msg);
    } else if (share_token && share_token[0]) {
        snprintf(msg.share_token, sizeof(msg.share_token), "%s", share_token);
        /* token-based status queries are allowed without auth */
    } else {
        close(sockfd);
        return false;
    }

    if (send_message(sockfd, &msg) < 0) {
        close(sockfd);
        return false;
    }

    response_t resp;
    if (recv_response(sockfd, &resp) < 0) {
        close(sockfd);
        return false;
    }

    if (resp.status != STATUS_OK) {
        close(sockfd);
        return false;
    }

    uint32_t len = 0;
    if (read(sockfd, &len, sizeof(len)) != sizeof(len) || len == 0 || len > 1024 * 1024) {
        close(sockfd);
        return false;
    }

    char *json = (char *)malloc(len);
    if (!json) {
        close(sockfd);
        return false;
    }

    ssize_t got = read(sockfd, json, len);
    close(sockfd);
    if (got != (ssize_t)len) {
        free(json);
        return false;
    }

    struct json_object *root = json_tokener_parse(json);
    free(json);
    if (!root) {
        return false;
    }

    struct json_object *tmp = NULL;
    if (json_object_object_get_ex(root, "id", &tmp) && json_object_is_type(tmp, json_type_string)) {
        snprintf(out->session_id, sizeof(out->session_id), "%s", json_object_get_string(tmp));
    }
    if (json_object_object_get_ex(root, "name", &tmp) && json_object_is_type(tmp, json_type_string)) {
        snprintf(out->session_name, sizeof(out->session_name), "%s", json_object_get_string(tmp));
    }
    if (json_object_object_get_ex(root, "user_count", &tmp) && json_object_is_type(tmp, json_type_int)) {
        out->user_count = json_object_get_int(tmp);
    }
    if (json_object_object_get_ex(root, "recording_active", &tmp) && json_object_is_type(tmp, json_type_boolean)) {
        out->recording_active = json_object_get_boolean(tmp);
    }
    if (json_object_object_get_ex(root, "recording_file", &tmp) && json_object_is_type(tmp, json_type_string)) {
        snprintf(out->recording_file, sizeof(out->recording_file), "%s", json_object_get_string(tmp));
    }
    if (json_object_object_get_ex(root, "daemon_uptime_seconds", &tmp) && json_object_is_type(tmp, json_type_int)) {
        out->daemon_uptime_seconds = (long)json_object_get_int(tmp);
    }

    json_object_put(root);
    return true;
}

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
             "SSHell v1.6.3 auth %ld %.96s:%d %.64s",
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
        
        /* Execute daemon (best-effort; try common install and release locations).
         * Note: parent will verify by attempting to connect.
         */
        char port_text[16];
        snprintf(port_text, sizeof(port_text), "%d", g_remote_port);

        /* 1) Prefer a daemon shipped alongside this client binary (release bundle). */
        {
            char self_path[PATH_MAX];
            ssize_t n = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
            if (n > 0) {
                self_path[n] = '\0';
                char *slash = strrchr(self_path, '/');
                if (slash) {
                    *slash = '\0';
                    char daemon_path[PATH_MAX];
                    int wrote = snprintf(daemon_path, sizeof(daemon_path), "%s/sshell-daemon", self_path);
                    if (wrote > 0 && (size_t)wrote < sizeof(daemon_path)) {
                        if (g_use_unix_socket) {
                            execl(daemon_path, "sshell-daemon", "--unix", NULL);
                        } else {
                            execl(daemon_path, "sshell-daemon", "--tcp", "--port", port_text, NULL);
                        }
                    }
                }
            }
        }

        /* 2) PATH lookup (typical install). */
        if (g_use_unix_socket) {
            execlp("sshell-daemon", "sshell-daemon", "--unix", NULL);
        } else {
            execlp("sshell-daemon", "sshell-daemon", "--tcp", "--port", port_text, NULL);
        }

        /* 3) Legacy name used by some builds. */
        if (g_use_unix_socket) {
            execlp("sshell-daemon-c", "sshell-daemon-c", "--unix", NULL);
            execl("/usr/local/bin/sshell-daemon-c", "sshell-daemon-c", "--unix", NULL);
        } else {
            execlp("sshell-daemon-c", "sshell-daemon-c", "--tcp", "--port", port_text, NULL);
            execl("/usr/local/bin/sshell-daemon-c", "sshell-daemon-c", "--tcp", "--port", port_text, NULL);
        }

        /* 4) Common absolute/relative fallbacks. */
        if (g_use_unix_socket) {
            execl("/usr/local/bin/sshell-daemon", "sshell-daemon", "--unix", NULL);
            execl("/usr/bin/sshell-daemon", "sshell-daemon", "--unix", NULL);
            execl("./sshell-daemon", "sshell-daemon", "--unix", NULL);
            execl("./.build/sshell-daemon", "sshell-daemon", "--unix", NULL);
        } else {
            execl("/usr/local/bin/sshell-daemon", "sshell-daemon", "--tcp", "--port", port_text, NULL);
            execl("/usr/bin/sshell-daemon", "sshell-daemon", "--tcp", "--port", port_text, NULL);
            execl("./sshell-daemon", "sshell-daemon", "--tcp", "--port", port_text, NULL);
            execl("./.build/sshell-daemon", "sshell-daemon", "--tcp", "--port", port_text, NULL);
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
        if (is_local_host(g_remote_host)) {
            fprintf(stderr,
                "Tip: start the daemon manually, then retry. Example:\n"
                "  sshell-daemon --tcp --port %d\n"
                "  (or from an extracted release folder: ./sshell-daemon --tcp --port %d)\n",
                g_remote_port,
                g_remote_port);
        }
        return -1;
    }

    int sockfd = connect_daemon();
    if (sockfd >= 0) {
        close(sockfd);
        return 0;
    }

    fprintf(stderr, "SShell: No local daemon found. Attempting to start daemon...\n");
    if (start_daemon() < 0) {
        fprintf(stderr, "SShell: Error - Failed to start daemon.\n");
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

    fprintf(stderr, "SShell: Error - Daemon did not start successfully.\n");
    return -1;
}

static void send_resize(const char *session_id) {
    ensure_wallet_signature_or_print_instructions("resize");
    int sockfd = connect_daemon();
    if (sockfd < 0) return;
    
    int rows, cols;
    terminal_get_size(STDIN_FILENO, &rows, &cols);

    /* Reserve top/bottom UI bars when active */
    if (g_ui_active && rows > 4) {
        rows -= 2;
    }
    
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

static void run_multisession_ui(void) {
    terminal_state_t term_state;
    terminal_init(&term_state);

    if (terminal_enter_raw_mode(&term_state, STDIN_FILENO) < 0) {
        fprintf(stderr, "Error: Failed to enter raw mode\n");
        exit(1);
    }

    signal(SIGWINCH, sigwinch_handler);
    signal(SIGINT, sigint_handler);

    int rows, cols;
    terminal_get_size(STDIN_FILENO, &rows, &cols);
    ui_enter(rows, cols);
    terminal_set_nonblocking(STDIN_FILENO);

    interactive_result_t result = IR_DETACH;

    while (!g_interrupted) {
        if (g_client_session_index < 0 || g_client_session_index >= g_client_session_count) {
            break;
        }

        client_session_entry_t *entry = &g_client_sessions[g_client_session_index];
        snprintf(g_remote_host, sizeof(g_remote_host), "%s", entry->host);
        g_remote_port = entry->port;

        terminal_get_size(STDIN_FILENO, &rows, &cols);
        int pty_rows = (rows > 4) ? (rows - 2) : rows;

        int sockfd = entry->is_join ? open_join_socket(entry->target, pty_rows, cols)
                                    : open_attach_socket(entry->target, pty_rows, cols);
        if (sockfd == -2) {
            fprintf(stderr, "Error: %s failed\n", entry->is_join ? "join" : "attach");
            result = IR_EXIT;
            break;
        }
        if (sockfd < 0) {
            fprintf(stderr, "Error: Cannot connect to daemon\n");
            result = IR_EXIT;
            break;
        }

        snprintf(g_ui_host, sizeof(g_ui_host), "%s", g_remote_host);
        g_ui_port = g_remote_port;
        g_ui_session_id[0] = '\0';
        if (entry->is_join) {
            snprintf(g_ui_share_token, sizeof(g_ui_share_token), "%s", entry->target);
            g_ui_session_name[0] = '\0';
        } else {
            snprintf(g_ui_session_name, sizeof(g_ui_session_name), "%s", entry->target);
            g_ui_share_token[0] = '\0';
        }

        ui_status_t st = {0};
        (void)ui_fetch_status(entry->is_join ? NULL : entry->target,
                              entry->is_join ? entry->target : NULL,
                              &st);
        if (st.session_name[0]) {
            snprintf(g_ui_session_name, sizeof(g_ui_session_name), "%s", st.session_name);
        }
        if (st.session_id[0]) {
            snprintf(g_ui_session_id, sizeof(g_ui_session_id), "%s", st.session_id);
        }
        ui_draw_bars(&st);

        /* Start UDP roaming heartbeat when connected over TCP to a non-loopback host. */
        if (!g_use_unix_socket && !is_local_host(g_ui_host) && g_ui_session_id[0]) {
            start_heartbeat(g_ui_session_id, g_ui_host, ROAMING_PORT);
        }

        char resize_id[64] = {0};
        snprintf(resize_id, sizeof(resize_id), "%s", g_ui_session_id[0] ? g_ui_session_id : entry->target);

        bool allow_resize = !entry->is_join;
        result = interactive_io_loop(sockfd,
                                     entry->is_join ? NULL : entry->target,
                                     entry->is_join ? entry->target : NULL,
                                     resize_id,
                                     allow_resize);
        close(sockfd);
        stop_heartbeat();

        if (result == IR_SWITCH_LEFT || result == IR_SWITCH_RIGHT) {
            int dir = (result == IR_SWITCH_LEFT) ? -1 : 1;
            if (!select_next_client_session(dir)) {
                result = IR_DETACH;
                break;
            }
            ui_write("\x1b[?6l\x1b[2;1H\x1b[J\x1b[?6h");
            continue;
        }

        break;
    }

    ui_leave();
    terminal_restore(&term_state, STDIN_FILENO);

    if (result == IR_DETACH && !g_interrupted) {
        printf("\n[detached]\n");
    }
}

static void cmd_attach(const char *target) {
    ensure_wallet_signature_or_print_instructions("attach");
    if (ensure_daemon_running() < 0) return;

    add_client_session(false, g_remote_host, g_remote_port, target);

    run_multisession_ui();
}

static void cmd_join(const char *token) {
    if (ensure_daemon_running() < 0) return;

    add_client_session(true, g_remote_host, g_remote_port, token);
    run_multisession_ui();
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

static void cmd_rec_start(const char *target) {
    ensure_wallet_signature_or_print_instructions("rec-start");
    if (ensure_daemon_running() < 0) return;

    int sockfd = connect_daemon();
    if (sockfd < 0) {
        fprintf(stderr, "Error: Cannot connect to daemon\n");
        exit(1);
    }

    int rows, cols;
    terminal_get_size(STDIN_FILENO, &rows, &cols);

    message_t msg = {0};
    msg.command = CMD_REC_START;
    snprintf(msg.session_name, sizeof(msg.session_name), "%s", target);
    msg.rows = rows;
    msg.cols = cols;
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

static void cmd_rec_stop(const char *target) {
    ensure_wallet_signature_or_print_instructions("rec-stop");
    if (ensure_daemon_running() < 0) return;

    int sockfd = connect_daemon();
    if (sockfd < 0) {
        fprintf(stderr, "Error: Cannot connect to daemon\n");
        exit(1);
    }

    message_t msg = {0};
    msg.command = CMD_REC_STOP;
    snprintf(msg.session_name, sizeof(msg.session_name), "%s", target);
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

static void print_usage(const char *prog) {
    if (!prog) {
        prog = "sshell";
    }

    printf("Usage:\n");
    printf("  %s [COMMAND] [OPTIONS]\n", prog);
    printf("  %s SESSION@HOST[:PORT]\n", prog);
    printf("  %s share-TOKEN@HOST[:PORT]\n\n", prog);
    printf("Commands:\n");
    printf("  new [NAME] [-s SHELL] [--no-attach]\n");
    printf("  attach TARGET\n");
    printf("  list | ls\n");
    printf("  kill TARGET\n");
    printf("  rename TARGET NEW_NAME\n");
    printf("  --share SESSION@HOST[:PORT]\n");
    printf("  --stopshare [SESSION@HOST[:PORT]]\n");
    printf("  rec-start TARGET\n");
    printf("  rec-stop TARGET\n\n");
    printf("Options:\n");
    printf("  --host HOST\n");
    printf("  --port PORT\n");
    printf("  --unix\n");
    printf("  --socket PATH\n");
    printf("  --wallet ADDRESS\n");
    printf("  --wallet-message MESSAGE\n");
    printf("  --wallet-signature SIGNATURE\n");
    printf("  --ssh-key-id ID\n");
    printf("  --help\n");
    printf("  --version\n");
}

int main(int argc, char *argv[]) {
    config_init();
    (void)config_ensure_directories();

    int command_index = 1;
    while (command_index < argc) {
        const char *arg = argv[command_index];
        if (!arg) {
            command_index++;
            continue;
        }

        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (strcmp(arg, "--version") == 0 || strcmp(arg, "-v") == 0) {
            printf("SSHell v1.6.3  -  (C) - D31337m3.com\n");
            return 0;
        }

        /* --window: launch this client in a separate xterm window (X11 only).
         * All remaining arguments (minus --window) are forwarded.
         * Uses fork+execvp to avoid shell injection vulnerabilities. */
        if (strcmp(arg, "--window") == 0) {
            const char *display = getenv("DISPLAY");
            if (!display || !display[0]) {
                fprintf(stderr, "--window mode requires X11 (DISPLAY set) and xterm installed.\n");
                return 1;
            }

            /* Build argv: xterm -title "SShell" -e <self> [all args except --window]
             * Worst-case size: 5 fixed slots + (argc-1) forwarded args + 1 NULL = argc+5.
             * Allocate argc+6 to keep one slot of margin. */
            char **xterm_argv = malloc(((size_t)argc + 6) * sizeof(char *));
            if (!xterm_argv) {
                fprintf(stderr, "sshell: --window: failed to allocate argument list: %s\n",
                        strerror(errno));
                return 1;
            }

            int xi = 0;
            xterm_argv[xi++] = "xterm";
            xterm_argv[xi++] = "-title";
            xterm_argv[xi++] = "SShell";
            xterm_argv[xi++] = "-e";
            xterm_argv[xi++] = argv[0];  /* self path */
            for (int j = 1; j < argc; j++) {
                if (strcmp(argv[j], "--window") != 0) {
                    xterm_argv[xi++] = argv[j];
                }
            }
            xterm_argv[xi] = NULL;

            pid_t win_pid = fork();
            if (win_pid < 0) {
                perror("fork");
                free(xterm_argv);
                return 1;
            }
            if (win_pid == 0) {
                /* Child: detach from parent session and exec xterm */
                setsid();
                execvp("xterm", xterm_argv);
                _exit(1);
            }
            free(xterm_argv);
            return 0;
        }

        if (strcmp(arg, "--host") == 0) {
            if (command_index + 1 >= argc) {
                fprintf(stderr, "Error: --host requires a value\n");
                return 1;
            }
            g_use_unix_socket = false;
            g_cli_set_host = true;
            snprintf(g_remote_host, sizeof(g_remote_host), "%s", argv[command_index + 1]);
            command_index += 2;
            continue;
        }

        if (strcmp(arg, "--port") == 0) {
            if (command_index + 1 >= argc) {
                fprintf(stderr, "Error: --port requires a value\n");
                return 1;
            }
            int p = atoi(argv[command_index + 1]);
            if (p <= 0 || p > 65535) {
                fprintf(stderr, "Error: invalid --port value\n");
                return 1;
            }
            g_use_unix_socket = false;
            g_remote_port = p;
            g_cli_set_port = true;
            command_index += 2;
            continue;
        }

        if (strcmp(arg, "--unix") == 0) {
            g_use_unix_socket = true;
            g_cli_set_mode = true;
            command_index += 1;
            continue;
        }

        if (strcmp(arg, "--socket") == 0) {
            if (command_index + 1 >= argc) {
                fprintf(stderr, "Error: --socket requires a value\n");
                return 1;
            }
            snprintf(g_unix_socket_path, sizeof(g_unix_socket_path), "%s", argv[command_index + 1]);
            g_cli_set_mode = true;
            command_index += 2;
            continue;
        }

        if (strcmp(arg, "--wallet") == 0) {
            if (command_index + 1 >= argc) {
                fprintf(stderr, "Error: --wallet requires a value\n");
                return 1;
            }
            snprintf(g_auth_wallet_address, sizeof(g_auth_wallet_address), "%s", argv[command_index + 1]);
            command_index += 2;
            continue;
        }

        if (strcmp(arg, "--wallet-message") == 0) {
            if (command_index + 1 >= argc) {
                fprintf(stderr, "Error: --wallet-message requires a value\n");
                return 1;
            }
            snprintf(g_auth_wallet_message, sizeof(g_auth_wallet_message), "%s", argv[command_index + 1]);
            command_index += 2;
            continue;
        }

        if (strcmp(arg, "--wallet-signature") == 0) {
            if (command_index + 1 >= argc) {
                fprintf(stderr, "Error: --wallet-signature requires a value\n");
                return 1;
            }
            snprintf(g_auth_wallet_signature, sizeof(g_auth_wallet_signature), "%s", argv[command_index + 1]);
            command_index += 2;
            continue;
        }

        if (strcmp(arg, "--ssh-key-id") == 0) {
            if (command_index + 1 >= argc) {
                fprintf(stderr, "Error: --ssh-key-id requires a value\n");
                return 1;
            }
            snprintf(g_auth_ssh_key_id, sizeof(g_auth_ssh_key_id), "%s", argv[command_index + 1]);
            command_index += 2;
            continue;
        }

        break;
    }

    apply_daemon_preset_defaults_if_needed();

    if (command_index >= argc) {
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
        return 0;
    }

    if (strcmp(command, "attach") == 0) {
        if (command_index + 1 >= argc) {
            fprintf(stderr, "Error: attach requires a session name or ID\n");
            return 1;
        }

        /* Multi-session: allow `sshell attach a b c` and switch with Shift+Left/Right */
        if (command_index + 2 < argc) {
            g_client_session_count = 0;
            g_client_session_index = -1;

            bool has_attach = false;

            for (int i = command_index + 1; i < argc; i++) {
                const char *t = argv[i];
                if (!t || !t[0]) {
                    continue;
                }

                char s[256] = {0};
                char h[256] = {0};
                int p = g_remote_port;
                if (parse_session_host_target(t, s, sizeof(s), h, sizeof(h), &p)) {
                    bool is_join = is_share_token(s);
                    has_attach = has_attach || !is_join;
                    add_client_session(is_join, h, p, s);
                } else {
                    bool is_join = is_share_token(t);
                    has_attach = has_attach || !is_join;
                    add_client_session(is_join, g_remote_host, g_remote_port, t);
                }
            }

            if (g_client_session_count == 0) {
                fprintf(stderr, "Error: no targets provided\n");
                return 1;
            }

            g_client_session_index = 0;

            if (has_attach) {
                ensure_wallet_signature_or_print_instructions("attach");
            }
            if (ensure_daemon_running() < 0) {
                return 1;
            }

            run_multisession_ui();
            return 0;
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
        return 0;
    }

    if (strcmp(command, "list") == 0 || strcmp(command, "ls") == 0) {
        cmd_list();
        return 0;
    }

    if (strcmp(command, "rec-start") == 0) {
        if (command_index + 1 >= argc) {
            fprintf(stderr, "Error: rec-start requires a session name or ID\n");
            return 1;
        }
        cmd_rec_start(argv[command_index + 1]);
        return 0;
    }

    if (strcmp(command, "rec-stop") == 0) {
        if (command_index + 1 >= argc) {
            fprintf(stderr, "Error: rec-stop requires a session name or ID\n");
            return 1;
        }
        cmd_rec_stop(argv[command_index + 1]);
        return 0;
    }

    if (strcmp(command, "kill") == 0) {
        if (command_index + 1 >= argc) {
            fprintf(stderr, "Error: kill requires a session name or ID\n");
            return 1;
        }
        cmd_kill(argv[command_index + 1]);
        return 0;
    }

    if (strcmp(command, "rename") == 0) {
        if (command_index + 2 >= argc) {
            fprintf(stderr, "Error: rename requires old and new names\n");
            return 1;
        }
        cmd_rename(argv[command_index + 1], argv[command_index + 2]);
        return 0;
    }

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
