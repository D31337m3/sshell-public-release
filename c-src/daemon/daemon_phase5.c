/*
 * daemon_phase5.c - SShell daemon with Phase 5 features
 * 
 * Features:
 * - Network roaming (UDP heartbeat)
 * - Session recording/playback
 * - Multi-user sessions
 * - Web viewer (WebSocket + MetaMask auth)
 */

#include "../common/session.h"
#include "../common/protocol.h"
#include "../common/config.h"
#include "../common/logger.h"
#include "../common/terminal.h"
#include "../common/network_roaming.h"
#include "../common/recording.h"
#include "../common/multiuser.h"
#include "../common/webserver.h"
#include "pty_manager.h"
#include "daemon.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>

#define MAX_SESSIONS 100
#define SELECT_TIMEOUT 1

/* Global state */
typedef struct {
    session_t sessions[MAX_SESSIONS];
    int session_count;
    pty_info_t pty_sessions[MAX_SESSIONS];
    recording_t recordings[MAX_SESSIONS];
    multiuser_session_t multiuser_sessions[MAX_SESSIONS];
    int server_fd;
    roaming_server_t roaming_server;
    webserver_t web_server;
    bool running;
} daemon_state_t;

static daemon_state_t g_state = {0};

/* Signal handlers */
static void signal_handler(int sig) {
    if (sig == SIGTERM || sig == SIGINT) {
        log_info("Received signal %d, shutting down", sig);
        g_state.running = false;
    }
}

static void sigchld_handler(int sig) {
    (void)sig;
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        log_debug("Child process %d exited with status %d", pid, status);
        /* Mark session for cleanup */
        for (int i = 0; i < g_state.session_count; i++) {
            if (g_state.sessions[i].pid == pid) {
                g_state.sessions[i].active = false;
            }
        }
    }
}

/* Session management */
static session_t* find_session(const char *id) {
    for (int i = 0; i < g_state.session_count; i++) {
        if (strcmp(g_state.sessions[i].id, id) == 0) {
            return &g_state.sessions[i];
        }
    }
    return NULL;
}

static int get_session_index(const char *id) {
    for (int i = 0; i < g_state.session_count; i++) {
        if (strcmp(g_state.sessions[i].id, id) == 0) {
            return i;
        }
    }
    return -1;
}

/* Handle CREATE command */
static int handle_create(int client_fd, const char *session_id, const char *shell_cmd) {
    if (g_state.session_count >= MAX_SESSIONS) {
        protocol_send_response(client_fd, RESP_ERROR, "Too many sessions");
        return -1;
    }
    
    if (find_session(session_id)) {
        protocol_send_response(client_fd, RESP_ERROR, "Session already exists");
        return -1;
    }
    
    /* Create PTY */
    pty_info_t *pty = &g_state.pty_sessions[g_state.session_count];
    const char *shell = shell_cmd[0] ? shell_cmd : getenv("SHELL");
    if (!shell) shell = "/bin/bash";
    
    if (pty_create(pty, shell) < 0) {
        protocol_send_response(client_fd, RESP_ERROR, "Failed to create PTY");
        return -1;
    }
    
    /* Create session */
    session_t *session = &g_state.sessions[g_state.session_count];
    session_init(session, session_id, shell);
    session->pid = pty->pid;
    session->active = true;
    
    /* Initialize multi-user support */
    multiuser_init(&g_state.multiuser_sessions[g_state.session_count]);
    
    /* Initialize recording (but don't start yet) */
    int cols, rows;
    terminal_get_size(&cols, &rows);
    recording_init(&g_state.recordings[g_state.session_count], session_id, cols, rows);
    
    g_state.session_count++;
    
    session_save(session);
    log_info("Created session: %s (PID %d)", session_id, session->pid);
    
    protocol_send_response(client_fd, RESP_OK, "Session created");
    return 0;
}

/* Handle ATTACH command with multi-user support */
static int handle_attach(int client_fd, const char *session_id) {
    session_t *session = find_session(session_id);
    if (!session) {
        protocol_send_response(client_fd, RESP_ERROR, "Session not found");
        return -1;
    }
    
    if (!session->active) {
        protocol_send_response(client_fd, RESP_ERROR, "Session not active");
        return -1;
    }
    
    int idx = get_session_index(session_id);
    pty_info_t *pty = &g_state.pty_sessions[idx];
    
    protocol_send_response(client_fd, RESP_OK, "Attached");
    
    /* Add user to multi-user session */
    char username[64];
    snprintf(username, sizeof(username), "user_%d", client_fd);
    multiuser_add_user(&g_state.multiuser_sessions[idx], client_fd, username, ACCESS_READ_WRITE);
    
    /* Main attach loop */
    char buffer[4096];
    fd_set readfds;
    struct timeval tv;
    
    while (session->active) {
        FD_ZERO(&readfds);
        FD_SET(client_fd, &readfds);
        FD_SET(pty->master_fd, &readfds);
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int max_fd = (client_fd > pty->master_fd ? client_fd : pty->master_fd) + 1;
        int ret = select(max_fd, &readfds, NULL, NULL, &tv);
        
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        
        /* PTY -> Client(s) */
        if (FD_ISSET(pty->master_fd, &readfds)) {
            ssize_t n = read(pty->master_fd, buffer, sizeof(buffer));
            if (n <= 0) break;
            
            /* Broadcast to all attached users */
            multiuser_broadcast(&g_state.multiuser_sessions[idx], buffer, n);
            
            /* Record if active */
            if (recording_is_active(&g_state.recordings[idx])) {
                recording_write(&g_state.recordings[idx], buffer, n);
            }
        }
        
        /* Client -> PTY */
        if (FD_ISSET(client_fd, &readfds)) {
            ssize_t n = read(client_fd, buffer, sizeof(buffer));
            if (n <= 0) break;
            
            /* Check write access */
            if (multiuser_has_write_access(&g_state.multiuser_sessions[idx], client_fd)) {
                write(pty->master_fd, buffer, n);
            }
        }
    }
    
    /* Remove user from session */
    multiuser_remove_user(&g_state.multiuser_sessions[idx], client_fd);
    
    log_info("Client detached from session: %s", session_id);
    return 0;
}

/* Handle LIST command */
static int handle_list(int client_fd) {
    char response[8192] = "[";
    bool first = true;
    
    for (int i = 0; i < g_state.session_count; i++) {
        if (g_state.sessions[i].active) {
            if (!first) strcat(response, ",");
            char *json = session_to_json(&g_state.sessions[i]);
            strcat(response, json);
            free(json);
            first = false;
        }
    }
    
    strcat(response, "]");
    protocol_send_response(client_fd, RESP_OK, response);
    return 0;
}

/* Handle REC_START command */
static int handle_rec_start(int client_fd, const char *session_id) {
    session_t *session = find_session(session_id);
    if (!session) {
        protocol_send_response(client_fd, RESP_ERROR, "Session not found");
        return -1;
    }
    
    int idx = get_session_index(session_id);
    
    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "%s/recordings/%s.cast",
             g_config.config_dir, session_id);
    
    int cols, rows;
    terminal_get_size(&cols, &rows);
    
    if (recording_start(&g_state.recordings[idx], filepath, cols, rows) < 0) {
        protocol_send_response(client_fd, RESP_ERROR, "Failed to start recording");
        return -1;
    }
    
    log_info("Started recording session: %s", session_id);
    protocol_send_response(client_fd, RESP_OK, "Recording started");
    return 0;
}

/* Handle REC_STOP command */
static int handle_rec_stop(int client_fd, const char *session_id) {
    int idx = get_session_index(session_id);
    if (idx < 0) {
        protocol_send_response(client_fd, RESP_ERROR, "Session not found");
        return -1;
    }
    
    recording_stop(&g_state.recordings[idx]);
    log_info("Stopped recording session: %s", session_id);
    protocol_send_response(client_fd, RESP_OK, "Recording stopped");
    return 0;
}

/* Handle SHARE command */
static int handle_share(int client_fd, const char *session_id) {
    int idx = get_session_index(session_id);
    if (idx < 0) {
        protocol_send_response(client_fd, RESP_ERROR, "Session not found");
        return -1;
    }
    
    char token[64];
    multiuser_enable_sharing(&g_state.multiuser_sessions[idx], token);
    
    char response[128];
    snprintf(response, sizeof(response), "Share token: %s", token);
    protocol_send_response(client_fd, RESP_OK, response);
    return 0;
}

/* WebServer thread */
static void* webserver_thread(void *arg) {
    (void)arg;
    log_info("Starting web server thread");
    webserver_run(&g_state.web_server);
    return NULL;
}

/* Main daemon initialization */
static int daemon_init() {
    /* Create socket directory */
    char socket_dir[1024];
    snprintf(socket_dir, sizeof(socket_dir), "%s", g_config.socket_dir);
    mkdir(socket_dir, 0700);
    
    /* Create Unix socket */
    g_state.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_state.server_fd < 0) {
        log_error("Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_config.socket_path, sizeof(addr.sun_path) - 1);
    
    unlink(g_config.socket_path);
    
    if (bind(g_state.server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_error("Failed to bind socket: %s", strerror(errno));
        return -1;
    }
    
    chmod(g_config.socket_path, 0600);
    
    if (listen(g_state.server_fd, 10) < 0) {
        log_error("Failed to listen: %s", strerror(errno));
        return -1;
    }
    
    /* Initialize network roaming */
    if (roaming_server_init(&g_state.roaming_server, ROAMING_PORT) < 0) {
        log_warn("Failed to initialize network roaming (non-fatal)");
    }
    
    /* Initialize web server */
    if (webserver_init(&g_state.web_server, WEB_PORT, &g_state) < 0) {
        log_warn("Failed to initialize web server (non-fatal)");
    } else {
        /* Start web server in separate thread */
        pthread_t web_thread;
        pthread_create(&web_thread, NULL, webserver_thread, NULL);
        pthread_detach(web_thread);
    }
    
    log_info("Daemon initialized on socket: %s", g_config.socket_path);
    log_info("Network roaming enabled on UDP port %d", ROAMING_PORT);
    log_info("Web viewer available at http://localhost:%d", WEB_PORT);
    
    return 0;
}

/* Main daemon loop */
static int daemon_run() {
    g_state.running = true;
    
    while (g_state.running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(g_state.server_fd, &readfds);
        
        if (g_state.roaming_server.running) {
            FD_SET(g_state.roaming_server.udp_fd, &readfds);
        }
        
        struct timeval tv = {SELECT_TIMEOUT, 0};
        int max_fd = g_state.server_fd;
        if (g_state.roaming_server.udp_fd > max_fd) {
            max_fd = g_state.roaming_server.udp_fd;
        }
        
        int ret = select(max_fd + 1, &readfds, NULL, NULL, &tv);
        
        if (ret < 0) {
            if (errno == EINTR) continue;
            log_error("select() failed: %s", strerror(errno));
            break;
        }
        
        /* Handle new client connections */
        if (FD_ISSET(g_state.server_fd, &readfds)) {
            int client_fd = accept(g_state.server_fd, NULL, NULL);
            if (client_fd < 0) {
                log_warn("accept() failed: %s", strerror(errno));
                continue;
            }
            
            /* Handle client request */
            message_t msg;
            if (protocol_receive_message(client_fd, &msg) < 0) {
                close(client_fd);
                continue;
            }
            
            switch (msg.type) {
                case MSG_CREATE:
                    handle_create(client_fd, msg.session_id, msg.data);
                    close(client_fd);
                    break;
                case MSG_ATTACH:
                    handle_attach(client_fd, msg.session_id);
                    close(client_fd);
                    break;
                case MSG_LIST:
                    handle_list(client_fd);
                    close(client_fd);
                    break;
                case MSG_REC_START:
                    handle_rec_start(client_fd, msg.session_id);
                    close(client_fd);
                    break;
                case MSG_REC_STOP:
                    handle_rec_stop(client_fd, msg.session_id);
                    close(client_fd);
                    break;
                case MSG_SHARE:
                    handle_share(client_fd, msg.session_id);
                    close(client_fd);
                    break;
                default:
                    log_warn("Unknown message type: %d", msg.type);
                    close(client_fd);
                    break;
            }
        }
        
        /* Handle network roaming heartbeats */
        if (g_state.roaming_server.running && 
            FD_ISSET(g_state.roaming_server.udp_fd, &readfds)) {
            roaming_server_process(&g_state.roaming_server);
        }
        
        /* Periodic cleanup */
        roaming_cleanup_expired(&g_state.roaming_server);
    }
    
    return 0;
}

/* Cleanup */
static void daemon_cleanup() {
    /* Stop web server */
    webserver_stop(&g_state.web_server);
    
    /* Stop roaming server */
    roaming_server_shutdown(&g_state.roaming_server);
    
    /* Close server socket */
    if (g_state.server_fd >= 0) {
        close(g_state.server_fd);
    }
    
    /* Close all PTYs */
    for (int i = 0; i < g_state.session_count; i++) {
        if (g_state.sessions[i].active) {
            pty_close(&g_state.pty_sessions[i]);
        }
        if (recording_is_active(&g_state.recordings[i])) {
            recording_stop(&g_state.recordings[i]);
        }
    }
    
    unlink(g_config.socket_path);
    log_info("Daemon shut down");
}

/* Main entry point */
int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("sshell-daemon (Phase 5) version 1.0.0\n");
        return 0;
    }
    
    /* Initialize config */
    if (config_init() < 0) {
        fprintf(stderr, "Failed to initialize config\n");
        return 1;
    }
    
    /* Initialize logger */
    logger_init(g_config.log_file, LOG_INFO);
    log_info("=== SShell Daemon (Phase 5) Starting ===");
    log_info("Features: Network Roaming, Recording, Multi-User, Web Viewer");
    
    /* Set up signal handlers */
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGCHLD, sigchld_handler);
    signal(SIGPIPE, SIG_IGN);
    
    /* Load existing sessions */
    session_load_all(g_state.sessions, &g_state.session_count, MAX_SESSIONS);
    log_info("Loaded %d existing sessions", g_state.session_count);
    
    /* Initialize daemon */
    if (daemon_init() < 0) {
        log_error("Failed to initialize daemon");
        return 1;
    }
    
    /* Run main loop */
    daemon_run();
    
    /* Cleanup */
    daemon_cleanup();
    logger_close();
    
    return 0;
}
