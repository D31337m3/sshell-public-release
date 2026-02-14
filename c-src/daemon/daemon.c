/*
 * daemon.c - Main daemon implementation
 */

#include "daemon.h"
#include "pty_manager.h"
#include "../common/config.h"
#include "../common/logger.h"
#include "../common/metamask_auth.h"
#include "../common/daemon_preset.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/select.h>
#include <ctype.h>
#include <json-c/json.h>

static daemon_t *g_daemon = NULL;
static bool g_tcp_mode = true;
static char g_bind_host[256] = "0.0.0.0";
static int g_bind_port = 7444;
static bool g_ufw_auto = false;
static bool g_auth_required = true;
static char g_wallet_allowlist_path[512] = {0};
static char g_ssh_allowlist_path[512] = {0};
static char g_single_wallet[128] = {0};
static log_level_t g_log_level = LOG_LEVEL_INFO;
static time_t g_daemon_started_at = 0;

static void signal_handler(int sig) {
    (void)sig;
    if (g_daemon) {
        g_daemon->running = false;
    }
}

static void sigchld_handler(int sig) {
    (void)sig;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
    errno = saved_errno;
}

int daemon_init(daemon_t *daemon) {
    memset(daemon, 0, sizeof(*daemon));
    daemon->server_fd = -1;
    daemon->running = false;

    for (int i = 0; i < MAX_SESSIONS; i++) {
        multiuser_init(&daemon->multiuser[i]);
        memset(&daemon->recordings[i], 0, sizeof(daemon->recordings[i]));
        daemon->recording_paths[i][0] = '\0';
    }
    return 0;
}

static void daemon_preset_path(char *out, size_t out_size) {
    if (!out || out_size == 0) {
        return;
    }
    snprintf(out, out_size, "%s/daemon.json", g_config.config_dir);
}

static void apply_daemon_preset_if_present(void) {
    char path[1024];
    daemon_preset_path(path, sizeof(path));

    if (access(path, R_OK) != 0) {
        return;
    }

    daemon_preset_t preset;
    if (!daemon_preset_load(path, &preset)) {
        return;
    }

    if (preset.has_tcp_mode) {
        g_tcp_mode = preset.tcp_mode;
    }
    if (preset.has_host) {
        snprintf(g_bind_host, sizeof(g_bind_host), "%s", preset.host);
        g_tcp_mode = true;
    }
    if (preset.has_port) {
        g_bind_port = preset.port;
        g_tcp_mode = true;
    }
    if (preset.has_ufw_auto) {
        g_ufw_auto = preset.ufw_auto;
    }
    if (preset.has_auth_required) {
        g_auth_required = preset.auth_required;
    }
    if (preset.has_wallet) {
        snprintf(g_single_wallet, sizeof(g_single_wallet), "%s", preset.wallet);
        g_auth_required = true;
    }
    if (preset.has_wallet_allowlist) {
        snprintf(g_wallet_allowlist_path, sizeof(g_wallet_allowlist_path), "%s", preset.wallet_allowlist_path);
    }
    if (preset.has_ssh_allowlist) {
        snprintf(g_ssh_allowlist_path, sizeof(g_ssh_allowlist_path), "%s", preset.ssh_allowlist_path);
    }
    if (preset.has_log_level) {
        g_log_level = preset.log_level;
    }
}

static bool parse_log_level_arg(const char *value, log_level_t *out) {
    if (!value || !out) {
        return false;
    }
    if (strcasecmp(value, "debug") == 0) {
        *out = LOG_LEVEL_DEBUG;
        return true;
    }
    if (strcasecmp(value, "info") == 0) {
        *out = LOG_LEVEL_INFO;
        return true;
    }
    if (strcasecmp(value, "warn") == 0 || strcasecmp(value, "warning") == 0) {
        *out = LOG_LEVEL_WARN;
        return true;
    }
    if (strcasecmp(value, "error") == 0) {
        *out = LOG_LEVEL_ERROR;
        return true;
    }
    return false;
}

static int find_session_index_by_ptr(daemon_t *daemon, session_t *session) {
    if (!daemon || !session) {
        return -1;
    }
    for (int i = 0; i < daemon->session_count; i++) {
        if (daemon->sessions[i] == session) {
            return i;
        }
    }
    return -1;
}

static multiuser_session_t *multiuser_for_session(daemon_t *daemon, session_t *session) {
    int index = find_session_index_by_ptr(daemon, session);
    if (index < 0) {
        return NULL;
    }
    return &daemon->multiuser[index];
}

static void make_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return;
    }
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void get_requester_identity(const message_t *msg,
                                   bool peer_is_localhost,
                                   char *out,
                                   size_t out_size) {
    if (!out || out_size == 0) {
        return;
    }
    out[0] = '\0';

    if (msg && msg->auth_wallet_address[0]) {
        snprintf(out, out_size, "wallet:%.110s", msg->auth_wallet_address);
        return;
    }

    if (msg && msg->auth_ssh_key_id[0]) {
        snprintf(out, out_size, "ssh:%.120s", msg->auth_ssh_key_id);
        return;
    }

    snprintf(out, out_size, peer_is_localhost ? "localhost" : "anonymous");
}

static session_t *find_session_by_name(daemon_t *daemon, const char *name) {
    for (int i = 0; i < daemon->session_count; i++) {
        if (strcmp(daemon->sessions[i]->name, name) == 0) {
            return daemon->sessions[i];
        }
    }
    return NULL;
}

static session_t *find_session_by_id(daemon_t *daemon, const char *id) {
    for (int i = 0; i < daemon->session_count; i++) {
        if (strcmp(daemon->sessions[i]->id, id) == 0) {
            return daemon->sessions[i];
        }
    }
    return NULL;
}

static void load_existing_sessions(daemon_t *daemon) {
    DIR *dir = opendir(g_config.session_dir);
    if (!dir) {
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!strstr(entry->d_name, ".json")) {
            continue;
        }

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", g_config.session_dir, entry->d_name);

        session_t *session = session_load(path);
        if (!session) {
            continue;
        }

        if (session_is_alive(session)) {
            if (daemon->session_count < MAX_SESSIONS) {
                int index = daemon->session_count;
                daemon->sessions[index] = session;
                multiuser_init(&daemon->multiuser[index]);
                recording_init(&daemon->recordings[index], session->id, 80, 24);
                daemon->recording_paths[index][0] = '\0';
                daemon->session_count++;
            } else {
                session_free(session);
            }
            continue;
        }

        session->status = SESSION_STATUS_DEAD;
        if (g_config.auto_cleanup_dead) {
            unlink(path);
            session_free(session);
        } else {
            session_save(session, g_config.session_dir);
            if (daemon->session_count < MAX_SESSIONS) {
                int index = daemon->session_count;
                daemon->sessions[index] = session;
                multiuser_init(&daemon->multiuser[index]);
                recording_init(&daemon->recordings[index], session->id, 80, 24);
                daemon->recording_paths[index][0] = '\0';
                daemon->session_count++;
            } else {
                session_free(session);
            }
        }
    }

    closedir(dir);
}

static int create_socket(daemon_t *daemon) {
    if (g_tcp_mode) {
        char port_text[16];
        snprintf(port_text, sizeof(port_text), "%d", g_bind_port);

        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        struct addrinfo *result = NULL;
        int gai = getaddrinfo(g_bind_host, port_text, &hints, &result);
        if (gai != 0) {
            log_error("Failed to resolve bind address %s:%s", g_bind_host, port_text);
            return -1;
        }

        daemon->server_fd = -1;
        for (struct addrinfo *entry = result; entry != NULL; entry = entry->ai_next) {
            int server_fd = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
            if (server_fd < 0) {
                continue;
            }

            int one = 1;
            setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

            if (bind(server_fd, entry->ai_addr, entry->ai_addrlen) == 0) {
                daemon->server_fd = server_fd;
                break;
            }

            close(server_fd);
        }

        freeaddrinfo(result);

        if (daemon->server_fd < 0) {
            log_error("Failed to bind TCP listener on %s:%d", g_bind_host, g_bind_port);
            return -1;
        }

        if (listen(daemon->server_fd, 16) < 0) {
            log_error("Failed to listen on TCP socket: %s", strerror(errno));
            close(daemon->server_fd);
            daemon->server_fd = -1;
            return -1;
        }

        return 0;
    }

    struct sockaddr_un addr;

    daemon->server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (daemon->server_fd < 0) {
        log_error("Failed to create socket: %s", strerror(errno));
        return -1;
    }

    unlink(g_config.socket_path);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(g_config.socket_path) >= sizeof(addr.sun_path)) {
        log_error("Socket path too long: %s", g_config.socket_path);
        close(daemon->server_fd);
        daemon->server_fd = -1;
        return -1;
    }
    strncpy(addr.sun_path, g_config.socket_path, sizeof(addr.sun_path) - 1);

    if (bind(daemon->server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("Failed to bind socket: %s", strerror(errno));
        close(daemon->server_fd);
        daemon->server_fd = -1;
        return -1;
    }

    if (listen(daemon->server_fd, 10) < 0) {
        log_error("Failed to listen: %s", strerror(errno));
        close(daemon->server_fd);
        daemon->server_fd = -1;
        return -1;
    }

    chmod(g_config.socket_path, 0600);
    return 0;
}

static void configure_ufw_if_enabled(void) {
    if (!g_tcp_mode || !g_ufw_auto) {
        return;
    }

    if (geteuid() != 0) {
        log_warn("UFW auto-config requested but daemon is not running as root");
        return;
    }

    if (access("/usr/sbin/ufw", X_OK) != 0 && access("/usr/bin/ufw", X_OK) != 0) {
        log_warn("UFW auto-config requested but ufw is not installed");
        return;
    }

    char command[128];
    snprintf(command, sizeof(command), "ufw allow %d/tcp >/dev/null 2>&1", g_bind_port);
    int result = system(command);
    if (result == 0) {
        log_info("UFW rule added for TCP port %d", g_bind_port);
    } else {
        log_warn("Failed to apply UFW rule for TCP port %d", g_bind_port);
    }
}

static bool allowlist_contains_line(const char *path, const char *value) {
    if (!path || !path[0] || !value || !value[0]) {
        return false;
    }

    FILE *file = fopen(path, "r");
    if (!file) {
        return false;
    }

    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), file) != NULL) {
        char *newline = strchr(line, '\n');
        if (newline) {
            *newline = '\0';
        }

        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        if (strcmp(line, value) == 0) {
            found = true;
            break;
        }
    }

    fclose(file);
    return found;
}

static bool is_authorized_request(const message_t *msg, bool peer_is_localhost) {
    if (!g_tcp_mode || !g_auth_required) {
        return true;
    }

    if (g_single_wallet[0] != '\0') {
        if (msg->auth_wallet_address[0] == '\0' ||
            msg->auth_wallet_message[0] == '\0' ||
            msg->auth_wallet_signature[0] == '\0') {
            log_warn("Wallet auth required but credentials missing");
            return false;
        }

        if (strcmp(msg->auth_wallet_address, g_single_wallet) != 0) {
            log_warn("Wallet address mismatch");
            return false;
        }

        return metamask_verify_signature(msg->auth_wallet_address,
                                         msg->auth_wallet_message,
                                         msg->auth_wallet_signature);
    }

    if (peer_is_localhost && g_wallet_allowlist_path[0] == '\0' && g_ssh_allowlist_path[0] == '\0') {
        return true;
    }

    if (g_wallet_allowlist_path[0] == '\0' && g_ssh_allowlist_path[0] == '\0') {
        log_warn("Remote auth required but no allowlist configured");
        return false;
    }

    if (g_wallet_allowlist_path[0] != '\0' && msg->auth_wallet_address[0] != '\0') {
        if (!allowlist_contains_line(g_wallet_allowlist_path, msg->auth_wallet_address)) {
            log_warn("Wallet address not authorized: %s", msg->auth_wallet_address);
            return false;
        }

        if (!metamask_verify_signature(msg->auth_wallet_address,
                                       msg->auth_wallet_message,
                                       msg->auth_wallet_signature)) {
            log_warn("Wallet signature rejected for: %s", msg->auth_wallet_address);
            return false;
        }

        return true;
    }

    if (g_ssh_allowlist_path[0] != '\0' && msg->auth_ssh_key_id[0] != '\0') {
        if (allowlist_contains_line(g_ssh_allowlist_path, msg->auth_ssh_key_id)) {
            return true;
        }

        log_warn("SSH key id not authorized: %s", msg->auth_ssh_key_id);
        return false;
    }

    log_warn("Auth required but no credentials provided");
    return false;
}

static void send_basic_response(int client_fd, status_t status, const char *text) {
    response_t resp = {0};
    resp.status = status;
    strncpy(resp.message, text, sizeof(resp.message) - 1);
    send_response(client_fd, &resp);
}

static void handle_create(daemon_t *daemon, const message_t *msg, int client_fd) {
    if (daemon->session_count >= MAX_SESSIONS) {
        send_basic_response(client_fd, STATUS_ERROR, "Maximum session limit reached");
        return;
    }

    if (msg->session_name[0] && find_session_by_name(daemon, msg->session_name)) {
        send_basic_response(client_fd, STATUS_ALREADY_EXISTS, "Session already exists");
        return;
    }

    const char *name = msg->session_name[0] ? msg->session_name : NULL;
    const char *shell = msg->shell[0] ? msg->shell : g_config.default_shell;

    session_t *session = session_create(name, shell);
    if (!session) {
        send_basic_response(client_fd, STATUS_ERROR, "Failed to create session");
        return;
    }

    if (pty_create_session(session) < 0) {
        session_free(session);
        send_basic_response(client_fd, STATUS_ERROR, "Failed to create PTY");
        return;
    }

    int index = daemon->session_count;
    daemon->sessions[index] = session;
    multiuser_init(&daemon->multiuser[index]);
    recording_init(&daemon->recordings[index], session->id, 80, 24);
    daemon->recording_paths[index][0] = '\0';
    daemon->session_count++;
    session_save(session, g_config.session_dir);

    response_t resp = {0};
    resp.status = STATUS_OK;
    snprintf(resp.message, sizeof(resp.message), "Session '%s' created (id: %s)", session->name, session->id);
    send_response(client_fd, &resp);
}

static bool handle_attach_register(daemon_t *daemon,
                                  const message_t *msg,
                                  int client_fd,
                                  bool peer_is_localhost,
                                  bool is_guest) {
    session_t *session = NULL;

    if (msg->session_id[0]) {
        session = find_session_by_id(daemon, msg->session_id);
    }
    if (!session && msg->session_name[0]) {
        session = find_session_by_name(daemon, msg->session_name);
    }

    if (!session) {
        send_basic_response(client_fd, STATUS_NOT_FOUND, "Session not found");
        return false;
    }

    if (!session_is_alive(session)) {
        session->status = SESSION_STATUS_DEAD;
        session_save(session, g_config.session_dir);
        send_basic_response(client_fd, STATUS_ERROR, "Session process is dead");
        return false;
    }

    if (session->master_fd < 0) {
        send_basic_response(client_fd, STATUS_ERROR, "Session PTY is not available (restart required)");
        return false;
    }

    multiuser_session_t *mu = multiuser_for_session(daemon, session);
    if (!mu) {
        send_basic_response(client_fd, STATUS_ERROR, "Internal error");
        return false;
    }

    char who[128];
    get_requester_identity(msg, peer_is_localhost, who, sizeof(who));

    if (multiuser_add_user(mu,
                           client_fd,
                           who,
                           ACCESS_READ_WRITE,
                           is_guest) < 0) {
        send_basic_response(client_fd, STATUS_ERROR, "Too many attached users");
        return false;
    }

    response_t resp = {0};
    resp.status = STATUS_OK;

    int session_index = find_session_index_by_ptr(daemon, session);
    int users = 0;
    bool recording_active = false;
    if (session_index >= 0) {
        users = daemon->multiuser[session_index].user_count;
        recording_active = recording_is_active(&daemon->recordings[session_index]);
    }

    snprintf(resp.message,
             sizeof(resp.message),
             "Attached to session '%s' (id:%s users:%d rec:%s)",
             session->name,
             session->id,
             users,
             recording_active ? "on" : "off");
    send_response(client_fd, &resp);

    make_nonblocking(client_fd);

    session->status = SESSION_STATUS_ATTACHED;
    session_update_attached(session);
    session_save(session, g_config.session_dir);

    if (msg->rows > 0 && msg->cols > 0) {
        pty_set_window_size(session->master_fd, msg->rows, msg->cols);
    }

    return true;
}

static session_t *find_session_by_share_token(daemon_t *daemon, const char *token) {
    if (!daemon || !token || !token[0]) {
        return NULL;
    }

    for (int i = 0; i < daemon->session_count; i++) {
        if (!daemon->multiuser[i].sharing_enabled) {
            continue;
        }
        if (strcmp(daemon->multiuser[i].share_token, token) == 0) {
            return daemon->sessions[i];
        }
    }

    return NULL;
}

static void disconnect_guest_users(daemon_t *daemon, session_t *session) {
    multiuser_session_t *mu = multiuser_for_session(daemon, session);
    if (!mu) {
        return;
    }

    int index = 0;
    while (index < mu->user_count) {
        attached_user_t *user = &mu->users[index];
        if (user->active && user->is_guest) {
            close(user->fd);
            multiuser_remove_user(mu, user->fd);
            continue;
        }
        index++;
    }
}

static void handle_list(daemon_t *daemon, int client_fd) {
    response_t resp = {0};
    resp.status = STATUS_OK;
    snprintf(resp.message, sizeof(resp.message), "Found %d sessions", daemon->session_count);
    send_response(client_fd, &resp);

    for (int index = 0; index < daemon->session_count; index++) {
        session_t *session = daemon->sessions[index];
        if (!session_is_alive(session) && session->status != SESSION_STATUS_DEAD) {
            session->status = SESSION_STATUS_DEAD;
        }

        char *json = session_to_json(session);
        if (!json) {
            continue;
        }

        uint32_t len = (uint32_t)strlen(json) + 1;
        if (write(client_fd, &len, sizeof(len)) == sizeof(len)) {
            write(client_fd, json, len);
        }
        free(json);
    }
}

static void handle_kill(daemon_t *daemon, const message_t *msg, int client_fd) {
    session_t *session = NULL;

    if (msg->session_id[0]) {
        session = find_session_by_id(daemon, msg->session_id);
    }
    if (!session && msg->session_name[0]) {
        session = find_session_by_name(daemon, msg->session_name);
    }

    if (!session) {
        send_basic_response(client_fd, STATUS_NOT_FOUND, "Session not found");
        return;
    }

    pty_kill_session(session);

    for (int index = 0; index < daemon->session_count; index++) {
        if (daemon->sessions[index] == session) {
            for (int shift = index; shift < daemon->session_count - 1; shift++) {
                daemon->sessions[shift] = daemon->sessions[shift + 1];
                daemon->multiuser[shift] = daemon->multiuser[shift + 1];
                daemon->recordings[shift] = daemon->recordings[shift + 1];
                snprintf(daemon->recording_paths[shift],
                         sizeof(daemon->recording_paths[shift]),
                         "%s",
                         daemon->recording_paths[shift + 1]);
            }
            daemon->session_count--;
            break;
        }
    }

    char path[1024];
    config_get_session_file(session->id, path, sizeof(path));
    unlink(path);

    response_t resp = {0};
    resp.status = STATUS_OK;
    snprintf(resp.message, sizeof(resp.message), "Session '%s' killed", session->name);
    send_response(client_fd, &resp);

    session_free(session);
}

static void handle_rename(daemon_t *daemon, const message_t *msg, int client_fd) {
    if (!msg->new_name[0]) {
        send_basic_response(client_fd, STATUS_ERROR, "New name is required");
        return;
    }

    if (find_session_by_name(daemon, msg->new_name)) {
        send_basic_response(client_fd, STATUS_ALREADY_EXISTS, "Session name already exists");
        return;
    }

    session_t *session = NULL;

    if (msg->session_id[0]) {
        session = find_session_by_id(daemon, msg->session_id);
    }
    if (!session && msg->session_name[0]) {
        session = find_session_by_name(daemon, msg->session_name);
    }

    if (!session) {
        send_basic_response(client_fd, STATUS_NOT_FOUND, "Session not found");
        return;
    }

    char old_name[SESSION_NAME_LEN];
    strncpy(old_name, session->name, sizeof(old_name) - 1);
    old_name[sizeof(old_name) - 1] = '\0';

    strncpy(session->name, msg->new_name, sizeof(session->name) - 1);
    session->name[sizeof(session->name) - 1] = '\0';
    session_save(session, g_config.session_dir);

    response_t resp = {0};
    resp.status = STATUS_OK;
    snprintf(resp.message,
             sizeof(resp.message),
             "Session renamed from '%.200s' to '%.200s'",
             old_name,
             session->name);
    send_response(client_fd, &resp);
}

static void handle_resize(daemon_t *daemon, const message_t *msg, int client_fd) {
    session_t *session = NULL;
    if (msg->session_id[0]) {
        session = find_session_by_id(daemon, msg->session_id);
    }

    if (!session) {
        send_basic_response(client_fd, STATUS_NOT_FOUND, "Session not found");
        return;
    }

    if (session->master_fd < 0) {
        send_basic_response(client_fd, STATUS_ERROR, "Session has no active PTY");
        return;
    }

    if (pty_set_window_size(session->master_fd, msg->rows, msg->cols) < 0) {
        send_basic_response(client_fd, STATUS_ERROR, "Failed to resize session");
        return;
    }

    response_t resp = {0};
    resp.status = STATUS_OK;
    snprintf(resp.message, sizeof(resp.message), "Session resized to %dx%d", msg->rows, msg->cols);
    send_response(client_fd, &resp);
}

static void handle_status(daemon_t *daemon, const message_t *msg, int client_fd) {
    session_t *session = NULL;

    if (msg->session_id[0]) {
        session = find_session_by_id(daemon, msg->session_id);
    }
    if (!session && msg->session_name[0]) {
        session = find_session_by_name(daemon, msg->session_name);
    }
    if (!session && msg->share_token[0]) {
        session = find_session_by_share_token(daemon, msg->share_token);
    }

    if (!session) {
        send_basic_response(client_fd, STATUS_NOT_FOUND, "Session not found");
        return;
    }

    if (!session_is_alive(session)) {
        session->status = SESSION_STATUS_DEAD;
    }

    response_t resp = {0};
    resp.status = STATUS_OK;
    snprintf(resp.message, sizeof(resp.message), "Session info");
    send_response(client_fd, &resp);

    int session_index = find_session_index_by_ptr(daemon, session);

    char *base_json = session_to_json(session);
    if (!base_json) {
        return;
    }

    struct json_object *root = json_tokener_parse(base_json);
    free(base_json);
    if (!root) {
        return;
    }

    int users = 0;
    bool sharing_enabled = false;
    bool recording_active = false;
    const char *recording_file = "";
    if (session_index >= 0) {
        users = daemon->multiuser[session_index].user_count;
        sharing_enabled = daemon->multiuser[session_index].sharing_enabled;
        recording_active = recording_is_active(&daemon->recordings[session_index]);
        recording_file = daemon->recording_paths[session_index];
    }

    json_object_object_add(root, "user_count", json_object_new_int(users));
    json_object_object_add(root, "sharing_enabled", json_object_new_boolean(sharing_enabled));
    json_object_object_add(root, "recording_active", json_object_new_boolean(recording_active));
    if (recording_file && recording_file[0]) {
        json_object_object_add(root, "recording_file", json_object_new_string(recording_file));
    }
    if (g_daemon_started_at > 0) {
        time_t now = time(NULL);
        json_object_object_add(root,
                               "daemon_uptime_seconds",
                               json_object_new_int64((int64_t)(now - g_daemon_started_at)));
    }

    const char *out_str = json_object_to_json_string(root);
    if (out_str) {
        uint32_t len = (uint32_t)strlen(out_str) + 1;
        if (write(client_fd, &len, sizeof(len)) == sizeof(len)) {
            write(client_fd, out_str, len);
        }
    }
    json_object_put(root);
}

static void handle_share(daemon_t *daemon, const message_t *msg, int client_fd, bool peer_is_localhost) {
    session_t *session = NULL;

    if (msg->session_id[0]) {
        session = find_session_by_id(daemon, msg->session_id);
    }
    if (!session && msg->session_name[0]) {
        session = find_session_by_name(daemon, msg->session_name);
    }

    if (!session) {
        send_basic_response(client_fd, STATUS_NOT_FOUND, "Session not found");
        return;
    }

    multiuser_session_t *mu = multiuser_for_session(daemon, session);
    if (!mu) {
        send_basic_response(client_fd, STATUS_ERROR, "Internal error");
        return;
    }

    char owner[128];
    get_requester_identity(msg, peer_is_localhost, owner, sizeof(owner));
    snprintf(mu->share_owner_id, sizeof(mu->share_owner_id), "%s", owner);

    if (msg->share_token[0]) {
        if (strlen(msg->share_token) > TOKEN_LENGTH) {
            send_basic_response(client_fd, STATUS_ERROR, "Share token too long");
            return;
        }
        snprintf(mu->share_token, sizeof(mu->share_token), "%s", msg->share_token);
        mu->sharing_enabled = true;
    } else {
        multiuser_enable_sharing(mu, NULL);
    }

    response_t resp = {0};
    resp.status = STATUS_OK;
    snprintf(resp.message,
             sizeof(resp.message),
             "Sharing enabled for '%s' token=%s",
             session->name,
             mu->share_token);
    send_response(client_fd, &resp);

    log_info("share enabled session=%s owner=%s", session->name, mu->share_owner_id);
}

static bool handle_join(daemon_t *daemon, const message_t *msg, int client_fd) {
    if (!msg->share_token[0]) {
        send_basic_response(client_fd, STATUS_ERROR, "Share token required");
        return false;
    }

    session_t *session = find_session_by_share_token(daemon, msg->share_token);
    if (!session) {
        send_basic_response(client_fd, STATUS_NOT_FOUND, "Invalid share token");
        return false;
    }

    return handle_attach_register(daemon, msg, client_fd, false, true);
}

static void handle_stopshare(daemon_t *daemon, const message_t *msg, int client_fd, bool peer_is_localhost) {
    char owner[128];
    get_requester_identity(msg, peer_is_localhost, owner, sizeof(owner));

    int sessions_disabled = 0;

    for (int i = 0; i < daemon->session_count; i++) {
        session_t *session = daemon->sessions[i];
        multiuser_session_t *mu = &daemon->multiuser[i];
        if (!mu->sharing_enabled) {
            continue;
        }

        if (strcmp(mu->share_owner_id, owner) != 0) {
            continue;
        }

        if (msg->session_name[0] && strcmp(session->name, msg->session_name) != 0) {
            continue;
        }

        disconnect_guest_users(daemon, session);
        multiuser_disable_sharing(mu);
        sessions_disabled++;
    }

    response_t resp = {0};
    resp.status = STATUS_OK;
    snprintf(resp.message,
             sizeof(resp.message),
             "Sharing stopped for %d session(s)",
             sessions_disabled);
    send_response(client_fd, &resp);

    log_info("share disabled owner=%s count=%d", owner, sessions_disabled);
}

static void handle_rec_start(daemon_t *daemon, const message_t *msg, int client_fd) {
    session_t *session = NULL;
    if (msg->session_id[0]) {
        session = find_session_by_id(daemon, msg->session_id);
    }
    if (!session && msg->session_name[0]) {
        session = find_session_by_name(daemon, msg->session_name);
    }
    if (!session) {
        send_basic_response(client_fd, STATUS_NOT_FOUND, "Session not found");
        return;
    }

    int index = find_session_index_by_ptr(daemon, session);
    if (index < 0) {
        send_basic_response(client_fd, STATUS_ERROR, "Internal error");
        return;
    }

    if (recording_is_active(&daemon->recordings[index])) {
        send_basic_response(client_fd, STATUS_ERROR, "Recording already active");
        return;
    }

    int width = (msg->cols > 0) ? msg->cols : 80;
    int height = (msg->rows > 0) ? msg->rows : 24;

    char rec_dir[1024];
    snprintf(rec_dir, sizeof(rec_dir), "%s/recordings", g_config.config_dir);
    mkdir(rec_dir, 0700);

    time_t now = time(NULL);
    int wrote = snprintf(daemon->recording_paths[index],
                         sizeof(daemon->recording_paths[index]),
                         "%s/%s-%ld.cast",
                         rec_dir,
                         session->id,
                         (long)now);
    if (wrote < 0 || (size_t)wrote >= sizeof(daemon->recording_paths[index])) {
        send_basic_response(client_fd, STATUS_ERROR, "Recording path too long");
        daemon->recording_paths[index][0] = '\0';
        return;
    }

    if (recording_start(&daemon->recordings[index], daemon->recording_paths[index], width, height) < 0) {
        daemon->recording_paths[index][0] = '\0';
        send_basic_response(client_fd, STATUS_ERROR, "Failed to start recording");
        return;
    }

    response_t resp = {0};
    resp.status = STATUS_OK;
    snprintf(resp.message, sizeof(resp.message), "%s", daemon->recording_paths[index]);
    send_response(client_fd, &resp);

    log_info("recording started session=%s file=%s", session->name, daemon->recording_paths[index]);
}

static void handle_rec_stop(daemon_t *daemon, const message_t *msg, int client_fd) {
    session_t *session = NULL;
    if (msg->session_id[0]) {
        session = find_session_by_id(daemon, msg->session_id);
    }
    if (!session && msg->session_name[0]) {
        session = find_session_by_name(daemon, msg->session_name);
    }
    if (!session) {
        send_basic_response(client_fd, STATUS_NOT_FOUND, "Session not found");
        return;
    }

    int index = find_session_index_by_ptr(daemon, session);
    if (index < 0) {
        send_basic_response(client_fd, STATUS_ERROR, "Internal error");
        return;
    }

    if (!recording_is_active(&daemon->recordings[index])) {
        send_basic_response(client_fd, STATUS_ERROR, "Recording not active");
        return;
    }

    if (recording_stop(&daemon->recordings[index]) < 0) {
        send_basic_response(client_fd, STATUS_ERROR, "Failed to stop recording");
        return;
    }

    response_t resp = {0};
    resp.status = STATUS_OK;
    snprintf(resp.message,
             sizeof(resp.message),
             "%s",
             daemon->recording_paths[index][0] ? daemon->recording_paths[index] : "Recording stopped");
    send_response(client_fd, &resp);

    log_info("recording stopped session=%s", session->name);
}

static bool handle_client(daemon_t *daemon, int client_fd, bool peer_is_localhost) {
    message_t msg;
    if (recv_message(client_fd, &msg) < 0) {
        close(client_fd);
        return false;
    }

    bool allow_unauth = (msg.command == CMD_JOIN) || (msg.command == CMD_STATUS && msg.share_token[0] != '\0');
    if (!allow_unauth && !is_authorized_request(&msg, peer_is_localhost)) {
        send_basic_response(client_fd, STATUS_ERROR, "Unauthorized");
        close(client_fd);
        return false;
    }

    bool keep_open = false;

    switch (msg.command) {
        case CMD_CREATE:
            handle_create(daemon, &msg, client_fd);
            break;
        case CMD_ATTACH:
            keep_open = handle_attach_register(daemon, &msg, client_fd, peer_is_localhost, false);
            break;
        case CMD_LIST:
            handle_list(daemon, client_fd);
            break;
        case CMD_KILL:
            handle_kill(daemon, &msg, client_fd);
            break;
        case CMD_RENAME:
            handle_rename(daemon, &msg, client_fd);
            break;
        case CMD_RESIZE:
            handle_resize(daemon, &msg, client_fd);
            break;
        case CMD_STATUS:
            handle_status(daemon, &msg, client_fd);
            break;
        case CMD_PING:
            send_basic_response(client_fd, STATUS_OK, "pong");
            break;
        case CMD_SHUTDOWN:
            send_basic_response(client_fd, STATUS_OK, "Daemon shutting down");
            daemon->running = false;
            break;
        case CMD_SHARE:
            handle_share(daemon, &msg, client_fd, peer_is_localhost);
            break;
        case CMD_JOIN:
            keep_open = handle_join(daemon, &msg, client_fd);
            break;
        case CMD_STOPSHARE:
            handle_stopshare(daemon, &msg, client_fd, peer_is_localhost);
            break;
        case CMD_REC_START:
            handle_rec_start(daemon, &msg, client_fd);
            break;
        case CMD_REC_STOP:
            handle_rec_stop(daemon, &msg, client_fd);
            break;
        default:
            send_basic_response(client_fd, STATUS_ERROR, "Command not implemented");
            break;
    }

    if (!keep_open) {
        close(client_fd);
    }

    return keep_open;
}

static void daemon_event_loop(daemon_t *daemon) {
    while (daemon->running) {
        fd_set readfds;
        FD_ZERO(&readfds);

        int maxfd = daemon->server_fd;
        FD_SET(daemon->server_fd, &readfds);

        for (int i = 0; i < daemon->session_count; i++) {
            session_t *session = daemon->sessions[i];
            multiuser_session_t *mu = &daemon->multiuser[i];
            if (session->master_fd < 0) {
                continue;
            }

            bool watch_pty = (mu->user_count > 0) || recording_is_active(&daemon->recordings[i]);
            if (!watch_pty) {
                continue;
            }

            FD_SET(session->master_fd, &readfds);
            if (session->master_fd > maxfd) {
                maxfd = session->master_fd;
            }

            if (mu->user_count > 0) {
                for (int u = 0; u < mu->user_count; u++) {
                    if (!mu->users[u].active) {
                        continue;
                    }
                    FD_SET(mu->users[u].fd, &readfds);
                    if (mu->users[u].fd > maxfd) {
                        maxfd = mu->users[u].fd;
                    }
                }
            }
        }

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200000;

        int ret = select(maxfd + 1, &readfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        if (FD_ISSET(daemon->server_fd, &readfds)) {
            int client_fd = accept(daemon->server_fd, NULL, NULL);
            if (client_fd >= 0) {
                bool peer_is_localhost = !g_tcp_mode;
                if (g_tcp_mode) {
                    struct sockaddr_storage addr;
                    socklen_t addr_len = sizeof(addr);
                    if (getpeername(client_fd, (struct sockaddr *)&addr, &addr_len) == 0) {
                        if (addr.ss_family == AF_INET) {
                            struct sockaddr_in *in = (struct sockaddr_in *)&addr;
                            peer_is_localhost = ((ntohl(in->sin_addr.s_addr) & 0xff000000u) == 0x7f000000u);
                        } else if (addr.ss_family == AF_INET6) {
                            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&addr;
                            static const unsigned char loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
                            peer_is_localhost = (memcmp(in6->sin6_addr.s6_addr, loopback, 16) == 0);
                        }
                    }
                }
                (void)handle_client(daemon, client_fd, peer_is_localhost);
            }
        }

        for (int i = 0; i < daemon->session_count; i++) {
            session_t *session = daemon->sessions[i];
            multiuser_session_t *mu = &daemon->multiuser[i];
            if (session->master_fd < 0) {
                continue;
            }

            bool watch_pty = (mu->user_count > 0) || recording_is_active(&daemon->recordings[i]);
            if (!watch_pty) {
                continue;
            }

            if (FD_ISSET(session->master_fd, &readfds)) {
                char buffer[4096];
                ssize_t n = read(session->master_fd, buffer, sizeof(buffer));
                if (n > 0) {
                    session_update_activity(session);

                    if (recording_is_active(&daemon->recordings[i])) {
                        recording_write(&daemon->recordings[i], buffer, (size_t)n);
                    }

                    for (int u = 0; u < mu->user_count; ) {
                        attached_user_t *user = &mu->users[u];
                        if (!user->active) {
                            u++;
                            continue;
                        }

                        ssize_t w = write(user->fd, buffer, (size_t)n);
                        if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                            close(user->fd);
                            multiuser_remove_user(mu, user->fd);
                            continue;
                        }
                        u++;
                    }
                } else if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                    for (int u = 0; u < mu->user_count; u++) {
                        if (mu->users[u].active) {
                            close(mu->users[u].fd);
                        }
                    }
                    mu->user_count = 0;
                    if (session_is_alive(session)) {
                        session->status = SESSION_STATUS_RUNNING;
                    } else {
                        session->status = SESSION_STATUS_DEAD;
                    }
                    session_save(session, g_config.session_dir);
                }
            }

            for (int u = 0; u < mu->user_count; ) {
                attached_user_t *user = &mu->users[u];
                if (!user->active) {
                    u++;
                    continue;
                }

                if (!FD_ISSET(user->fd, &readfds)) {
                    u++;
                    continue;
                }

                char buffer[4096];
                ssize_t n = read(user->fd, buffer, sizeof(buffer));
                if (n <= 0) {
                    close(user->fd);
                    multiuser_remove_user(mu, user->fd);
                    continue;
                }

                if (multiuser_has_write_access(mu, user->fd)) {
                    ssize_t w = write(session->master_fd, buffer, (size_t)n);
                    if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        close(user->fd);
                        multiuser_remove_user(mu, user->fd);
                        continue;
                    }
                    session_update_activity(session);
                }

                u++;
            }

            if (mu->user_count == 0) {
                if (session_is_alive(session)) {
                    session->status = SESSION_STATUS_RUNNING;
                } else {
                    session->status = SESSION_STATUS_DEAD;
                }
                session_save(session, g_config.session_dir);
            }
        }
    }
}

int daemon_start(daemon_t *daemon) {
    g_daemon = daemon;

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, sigchld_handler);

    load_existing_sessions(daemon);

    if (create_socket(daemon) < 0) {
        return -1;
    }

    configure_ufw_if_enabled();

    daemon->running = true;
    daemon_event_loop(daemon);

    return 0;
}

void daemon_cleanup(daemon_t *daemon) {
    if (daemon->server_fd >= 0) {
        close(daemon->server_fd);
        if (!g_tcp_mode) {
            unlink(g_config.socket_path);
        }
    }

    for (int i = 0; i < daemon->session_count; i++) {
        if (daemon->sessions[i]) {
            for (int u = 0; u < daemon->multiuser[i].user_count; u++) {
                if (daemon->multiuser[i].users[u].active) {
                    close(daemon->multiuser[i].users[u].fd);
                    daemon->multiuser[i].users[u].active = false;
                }
            }
            daemon->multiuser[i].user_count = 0;

            if (recording_is_active(&daemon->recordings[i])) {
                recording_stop(&daemon->recordings[i]);
            }

            session_save(daemon->sessions[i], g_config.session_dir);
            session_free(daemon->sessions[i]);
            daemon->sessions[i] = NULL;
        }
    }
}

int main(int argc, char **argv) {
    bool foreground = false;

    config_init();
    apply_daemon_preset_if_present();

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-fork") == 0 || strcmp(argv[i], "-f") == 0) {
            foreground = true;
        } else if (strcmp(argv[i], "--tcp") == 0) {
            g_tcp_mode = true;
        } else if (strcmp(argv[i], "--unix") == 0) {
            g_tcp_mode = false;
        } else if (strcmp(argv[i], "--host") == 0 || strcmp(argv[i], "--bind") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --host requires a host/IP\n");
                return 1;
            }
            snprintf(g_bind_host, sizeof(g_bind_host), "%s", argv[++i]);
            g_tcp_mode = true;
        } else if (strcmp(argv[i], "--port") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --port requires a value\n");
                return 1;
            }
            g_bind_port = atoi(argv[++i]);
            if (g_bind_port <= 0 || g_bind_port > 65535) {
                fprintf(stderr, "Error: invalid --port value\n");
                return 1;
            }
            g_tcp_mode = true;
        } else if (strcmp(argv[i], "--ufw-auto") == 0) {
            g_ufw_auto = true;
        } else if (strcmp(argv[i], "--wallet-allowlist") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --wallet-allowlist requires a path\n");
                return 1;
            }
            snprintf(g_wallet_allowlist_path, sizeof(g_wallet_allowlist_path), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--ssh-allowlist") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --ssh-allowlist requires a path\n");
                return 1;
            }
            snprintf(g_ssh_allowlist_path, sizeof(g_ssh_allowlist_path), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--insecure-no-auth") == 0) {
            g_auth_required = false;
        } else if (strcmp(argv[i], "--wallet") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --wallet requires an address\n");
                return 1;
            }
            snprintf(g_single_wallet, sizeof(g_single_wallet), "%s", argv[++i]);
            g_auth_required = true;
        } else if (strcmp(argv[i], "--log-level") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --log-level requires a value (debug|info|warn|error)\n");
                return 1;
            }
            log_level_t level;
            if (!parse_log_level_arg(argv[++i], &level)) {
                fprintf(stderr, "Error: invalid --log-level value\n");
                return 1;
            }
            g_log_level = level;
        } else if (strcmp(argv[i], "--debug") == 0) {
            g_log_level = LOG_LEVEL_DEBUG;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("  -f, --no-fork    Run in foreground\n");
            printf("  --tcp            Listen on TCP mode (default)\n");
            printf("  --unix           Listen on Unix socket mode\n");
            printf("  --host HOST      Bind host/IP for TCP mode (default: 0.0.0.0)\n");
            printf("  --port PORT      Bind TCP port (default: 7444)\n");
            printf("  --ufw-auto       Auto-open TCP port in UFW (requires root)\n");
            printf("  --wallet-allowlist PATH  Authorized wallet addresses (one per line)\n");
            printf("  --wallet ADDRESS         Single authorized wallet address\n");
            printf("  --ssh-allowlist PATH     Authorized ssh-key IDs (one per line)\n");
            printf("  --insecure-no-auth       Disable auth checks (NOT recommended)\n");
            printf("  --log-level LEVEL        Log verbosity (debug|info|warn|error)\n");
            printf("  --debug                  Alias for --log-level debug\n");
            printf("  -h, --help       Show this help\n");
            printf("  -v, --version    Show version\n");
            return 0;
        } else if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0) {
            printf("SSHell v1.6.2  -  (C) - D31337m3.com\n");
            return 0;
        }
    }

    if (config_ensure_directories() < 0) {
        fprintf(stderr, "Failed to create config directories\n");
        return 1;
    }

    if (logger_init(g_config.log_file, g_log_level, foreground) < 0) {
        fprintf(stderr, "Failed to initialize logger\n");
        return 1;
    }

    g_daemon_started_at = time(NULL);

    daemon_t daemon;
    daemon_init(&daemon);

    if (g_tcp_mode) {
        log_info("TCP mode enabled: %s:%d", g_bind_host, g_bind_port);
    } else {
        log_info("Unix socket mode enabled: %s", g_config.socket_path);
    }

    int result = daemon_start(&daemon);

    daemon_cleanup(&daemon);
    logger_close();

    return result;
}