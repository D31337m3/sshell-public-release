/*
 * daemon_enhanced.c - Enhanced daemon with full functionality
 */

#include "daemon.h"
#include "pty_manager.h"
#include "../common/config.h"
#include "../common/logger.h"
#include "../common/terminal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>

static daemon_t *g_daemon = NULL;

static void signal_handler(int sig) {
    (void)sig;
    if (g_daemon) {
        g_daemon->running = false;
    }
}

static void sigchld_handler(int sig) {
    (void)sig;
    /* Reap child processes */
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

int daemon_init(daemon_t *daemon) {
    memset(daemon, 0, sizeof(daemon_t));
    daemon->server_fd = -1;
    daemon->running = false;
    daemon->session_count = 0;
    return 0;
}

static session_t* find_session_by_name(daemon_t *daemon, const char *name) {
    for (int i = 0; i < daemon->session_count; i++) {
        if (strcmp(daemon->sessions[i]->name, name) == 0) {
            return daemon->sessions[i];
        }
    }
    return NULL;
}

static session_t* find_session_by_id(daemon_t *daemon, const char *id) {
    for (int i = 0; i < daemon->session_count; i++) {
        if (strcmp(daemon->sessions[i]->id, id) == 0) {
            return daemon->sessions[i];
        }
    }
    return NULL;
}

static void load_existing_sessions(daemon_t *daemon) {
    DIR *dir = opendir(g_config.session_dir);
    if (!dir) return;
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".json")) {
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", g_config.session_dir, entry->d_name);
            
            session_t *session = session_load(path);
            if (session) {
                /* Check if process is still alive */
                if (session_is_alive(session)) {
                    daemon->sessions[daemon->session_count++] = session;
                    log_info("Loaded session %s (pid: %d)", session->name, session->pid);
                } else {
                    /* Clean up dead session */
                    session->status = SESSION_STATUS_DEAD;
                    if (g_config.auto_cleanup_dead) {
                        unlink(path);
                        log_info("Cleaned up dead session %s", session->name);
                    } else {
                        session_save(session, g_config.session_dir);
                    }
                    session_free(session);
                }
            }
        }
    }
    closedir(dir);
    
    log_info("Loaded %d existing sessions", daemon->session_count);
}

static int create_socket(daemon_t *daemon) {
    struct sockaddr_un addr;
    
    daemon->server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (daemon->server_fd < 0) {
        log_error("Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    unlink(g_config.socket_path);
    
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_config.socket_path, sizeof(addr.sun_path) - 1);
    
    if (bind(daemon->server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_error("Failed to bind socket: %s", strerror(errno));
        close(daemon->server_fd);
        return -1;
    }
    
    if (listen(daemon->server_fd, 10) < 0) {
        log_error("Failed to listen: %s", strerror(errno));
        close(daemon->server_fd);
        return -1;
    }
    
    chmod(g_config.socket_path, 0600);
    log_info("Listening on %s", g_config.socket_path);
    
    return 0;
}

static void handle_create(daemon_t *daemon, const message_t *msg, int client_fd) {
    response_t resp = {0};
    
    if (daemon->session_count >= MAX_SESSIONS) {
        resp.status = STATUS_ERROR;
        snprintf(resp.message, sizeof(resp.message), 
                "Maximum session limit (%d) reached", MAX_SESSIONS);
        send_response(client_fd, &resp);
        return;
    }
    
    /* Check for duplicate name */
    if (msg->session_name[0]) {
        if (find_session_by_name(daemon, msg->session_name)) {
            resp.status = STATUS_ALREADY_EXISTS;
            snprintf(resp.message, sizeof(resp.message), 
                    "Session '%s' already exists", msg->session_name);
            send_response(client_fd, &resp);
            return;
        }
    }
    
    const char *name = msg->session_name[0] ? msg->session_name : NULL;
    const char *shell = msg->shell[0] ? msg->shell : g_config.default_shell;
    
    session_t *session = session_create(name, shell);
    if (!session) {
        resp.status = STATUS_ERROR;
        snprintf(resp.message, sizeof(resp.message), "Failed to allocate session");
        send_response(client_fd, &resp);
        return;
    }
    
    if (pty_create_session(session) < 0) {
        resp.status = STATUS_ERROR;
        snprintf(resp.message, sizeof(resp.message), "Failed to create PTY");
        session_free(session);
        send_response(client_fd, &resp);
        return;
    }
    
    daemon->sessions[daemon->session_count++] = session;
    session_save(session, g_config.session_dir);
    
    log_info("Created session %s (id: %s, pid: %d)", 
             session->name, session->id, session->pid);
    
    resp.status = STATUS_OK;
    snprintf(resp.message, sizeof(resp.message), 
            "Session '%s' created (id: %s)", session->name, session->id);
    send_response(client_fd, &resp);
}

static void handle_attach(daemon_t *daemon, const message_t *msg, int client_fd) {
    response_t resp = {0};
    
    session_t *session = NULL;
    if (msg->session_id[0]) {
        session = find_session_by_id(daemon, msg->session_id);
    } else if (msg->session_name[0]) {
        session = find_session_by_name(daemon, msg->session_name);
    }
    
    if (!session) {
        resp.status = STATUS_NOT_FOUND;
        snprintf(resp.message, sizeof(resp.message), "Session not found");
        send_response(client_fd, &resp);
        return;
    }
    
    if (!session_is_alive(session)) {
        resp.status = STATUS_ERROR;
        snprintf(resp.message, sizeof(resp.message), "Session process is dead");
        send_response(client_fd, &resp);
        return;
    }
    
    /* Send OK response */
    resp.status = STATUS_OK;
    snprintf(resp.message, sizeof(resp.message), 
            "Attached to session '%s'", session->name);
    send_response(client_fd, &resp);
    
    /* Update session state */
    session->status = SESSION_STATUS_ATTACHED;
    session_update_attached(session);
    session_save(session, g_config.session_dir);
    
    /* Set window size */
    if (msg->rows > 0 && msg->cols > 0) {
        pty_set_window_size(session->master_fd, msg->rows, msg->cols);
    }
    
    log_info("Client attached to session %s", session->name);
    
    /* Proxy I/O until client disconnects */
    while (pty_proxy_io(session->master_fd, client_fd, 0.1)) {
        session_update_activity(session);
    }
    
    session->status = SESSION_STATUS_RUNNING;
    session_save(session, g_config.session_dir);
    
    log_info("Client detached from session %s", session->name);
}

static void handle_list(daemon_t *daemon, int client_fd) {
    response_t resp = {0};
    resp.status = STATUS_OK;
    snprintf(resp.message, sizeof(resp.message), "Found %d sessions", daemon->session_count);
    send_response(client_fd, &resp);
    
    /* Send each session as JSON */
    for (int i = 0; i < daemon->session_count; i++) {
        /* Update status */
        if (!session_is_alive(daemon->sessions[i]) && 
            daemon->sessions[i]->status != SESSION_STATUS_DEAD) {
            daemon->sessions[i]->status = SESSION_STATUS_DEAD;
        }
        
        char *json = session_to_json(daemon->sessions[i]);
        if (json) {
            uint32_t len = strlen(json) + 1;
            write(client_fd, &len, sizeof(len));
            write(client_fd, json, len);
            free(json);
        }
    }
}

static void handle_kill(daemon_t *daemon, const message_t *msg, int client_fd) {
    response_t resp = {0};
    
    session_t *session = NULL;
    if (msg->session_id[0]) {
        session = find_session_by_id(daemon, msg->session_id);
    } else if (msg->session_name[0]) {
        session = find_session_by_name(daemon, msg->session_name);
    }
    
    if (!session) {
        resp.status = STATUS_NOT_FOUND;
        snprintf(resp.message, sizeof(resp.message), "Session not found");
        send_response(client_fd, &resp);
        return;
    }
    
    pty_kill_session(session);
    
    /* Remove from session list */
    for (int i = 0; i < daemon->session_count; i++) {
        if (daemon->sessions[i] == session) {
            /* Shift remaining sessions */
            for (int j = i; j < daemon->session_count - 1; j++) {
                daemon->sessions[j] = daemon->sessions[j + 1];
            }
            daemon->session_count--;
            break;
        }
    }
    
    /* Delete session file */
    char path[1024];
    config_get_session_file(session->id, path, sizeof(path));
    unlink(path);
    
    log_info("Killed session %s", session->name);
    
    resp.status = STATUS_OK;
    snprintf(resp.message, sizeof(resp.message), 
            "Session '%s' killed", session->name);
    send_response(client_fd, &resp);
    
    session_free(session);
}

static void handle_rename(daemon_t *daemon, const message_t *msg, int client_fd) {
    response_t resp = {0};
    
    if (!msg->new_name[0]) {
        resp.status = STATUS_ERROR;
        snprintf(resp.message, sizeof(resp.message), "New name is required");
        send_response(client_fd, &resp);
        return;
    }
    
    /* Check if new name already exists */
    if (find_session_by_name(daemon, msg->new_name)) {
        resp.status = STATUS_ALREADY_EXISTS;
        snprintf(resp.message, sizeof(resp.message), 
                "Session '%s' already exists", msg->new_name);
        send_response(client_fd, &resp);
        return;
    }
    
    session_t *session = NULL;
    if (msg->session_id[0]) {
        session = find_session_by_id(daemon, msg->session_id);
    } else if (msg->session_name[0]) {
        session = find_session_by_name(daemon, msg->session_name);
    }
    
    if (!session) {
        resp.status = STATUS_NOT_FOUND;
        snprintf(resp.message, sizeof(resp.message), "Session not found");
        send_response(client_fd, &resp);
        return;
    }
    
    char old_name[256];
    strncpy(old_name, session->name, sizeof(old_name) - 1);
    strncpy(session->name, msg->new_name, sizeof(session->name) - 1);
    
    session_save(session, g_config.session_dir);
    
    log_info("Renamed session from '%s' to '%s'", old_name, session->name);
    
    resp.status = STATUS_OK;
    snprintf(resp.message, sizeof(resp.message), 
            "Session renamed from '%s' to '%s'", old_name, session->name);
    send_response(client_fd, &resp);
}

static void handle_status(daemon_t *daemon, const message_t *msg, int client_fd) {
    response_t resp = {0};
    
    session_t *session = NULL;
    if (msg->session_id[0]) {
        session = find_session_by_id(daemon, msg->session_id);
    } else if (msg->session_name[0]) {
        session = find_session_by_name(daemon, msg->session_name);
    }
    
    if (!session) {
        resp.status = STATUS_NOT_FOUND;
        snprintf(resp.message, sizeof(resp.message), "Session not found");
        send_response(client_fd, &resp);
        return;
    }
    
    /* Update status */
    if (!session_is_alive(session)) {
        session->status = SESSION_STATUS_DEAD;
    }
    
    resp.status = STATUS_OK;
    snprintf(resp.message, sizeof(resp.message), "Session info");
    send_response(client_fd, &resp);
    
    /* Send session JSON */
    char *json = session_to_json(session);
    if (json) {
        uint32_t len = strlen(json) + 1;
        write(client_fd, &len, sizeof(len));
        write(client_fd, json, len);
        free(json);
    }
}

static void handle_resize(daemon_t *daemon, const message_t *msg, int client_fd) {
    response_t resp = {0};
    
    session_t *session = NULL;
    if (msg->session_id[0]) {
        session = find_session_by_id(daemon, msg->session_id);
    }
    
    if (!session) {
        resp.status = STATUS_NOT_FOUND;
        snprintf(resp.message, sizeof(resp.message), "Session not found");
        send_response(client_fd, &resp);
        return;
    }
    
    if (session->master_fd >= 0) {
        pty_set_window_size(session->master_fd, msg->rows, msg->cols);
        log_debug("Resized session %s to %dx%d", session->name, msg->rows, msg->cols);
        
        resp.status = STATUS_OK;
        snprintf(resp.message, sizeof(resp.message), 
                "Session resized to %dx%d", msg->rows, msg->cols);
    } else {
        resp.status = STATUS_ERROR;
        snprintf(resp.message, sizeof(resp.message), "Session has no active PTY");
    }
    
    send_response(client_fd, &resp);
}

static void handle_client(daemon_t *daemon, int client_fd) {
    message_t msg;
    
    if (recv_message(client_fd, &msg) < 0) {
        log_warn("Failed to receive message from client");
        close(client_fd);
        return;
    }
    
    log_debug("Received command: %d", msg.command);
    
    switch (msg.command) {
        case CMD_CREATE:
            handle_create(daemon, &msg, client_fd);
            close(client_fd);
            break;
        case CMD_ATTACH:
            handle_attach(daemon, &msg, client_fd);
            close(client_fd);
            break;
        case CMD_LIST:
            handle_list(daemon, client_fd);
            close(client_fd);
            break;
        case CMD_KILL:
            handle_kill(daemon, &msg, client_fd);
            close(client_fd);
            break;
        case CMD_RENAME:
            handle_rename(daemon, &msg, client_fd);
            close(client_fd);
            break;
        case CMD_STATUS:
            handle_status(daemon, &msg, client_fd);
            close(client_fd);
            break;
        case CMD_RESIZE:
            handle_resize(daemon, &msg, client_fd);
            close(client_fd);
            break;
        case CMD_PING:
            {
                response_t resp = {0};
                resp.status = STATUS_OK;
                snprintf(resp.message, sizeof(resp.message), "pong");
                send_response(client_fd, &resp);
                close(client_fd);
            }
            break;
        case CMD_SHUTDOWN:
            {
                response_t resp = {0};
                resp.status = STATUS_OK;
                snprintf(resp.message, sizeof(resp.message), "Daemon shutting down");
                send_response(client_fd, &resp);
                close(client_fd);
                daemon->running = false;
            }
            break;
        default:
            {
                response_t resp = {0};
                resp.status = STATUS_ERROR;
                snprintf(resp.message, sizeof(resp.message), "Unknown command");
                send_response(client_fd, &resp);
                close(client_fd);
            }
            break;
    }
}

int daemon_start(daemon_t *daemon) {
    g_daemon = daemon;
    
    /* Set up signal handlers */
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, sigchld_handler);
    
    /* Load existing sessions */
    load_existing_sessions(daemon);
    
    /* Create socket */
    if (create_socket(daemon) < 0) {
        return -1;
    }
    
    log_info("SShell daemon started");
    printf("SShell daemon started, listening on %s\n", g_config.socket_path);
    
    daemon->running = true;
    while (daemon->running) {
        int client_fd = accept(daemon->server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            log_error("Accept failed: %s", strerror(errno));
            break;
        }
        
        handle_client(daemon, client_fd);
    }
    
    log_info("SShell daemon shutting down");
    return 0;
}

void daemon_cleanup(daemon_t *daemon) {
    if (daemon->server_fd >= 0) {
        close(daemon->server_fd);
        unlink(g_config.socket_path);
    }
    
    /* Save all sessions */
    for (int i = 0; i < daemon->session_count; i++) {
        session_save(daemon->sessions[i], g_config.session_dir);
        session_free(daemon->sessions[i]);
    }
    
    log_info("Daemon cleanup complete");
}

int main(int argc, char **argv) {
    bool foreground = false;
    
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-fork") == 0 || strcmp(argv[i], "-f") == 0) {
            foreground = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("Options:\n");
            printf("  -f, --no-fork    Run in foreground\n");
            printf("  -h, --help       Show this help\n");
            printf("  -v, --version    Show version\n");
            return 0;
        } else if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0) {
            printf("SShell daemon (C) version 1.0 - Enhanced\n");
            return 0;
        }
    }
    
    /* Initialize configuration */
    config_init();
    config_ensure_directories();
    
    /* Initialize logger */
    logger_init(g_config.log_file, LOG_LEVEL_INFO, foreground);
    
    /* Initialize daemon */
    daemon_t daemon;
    daemon_init(&daemon);
    
    /* Start daemon */
    int ret = daemon_start(&daemon);
    
    /* Cleanup */
    daemon_cleanup(&daemon);
    logger_close();
    
    return ret;
}
