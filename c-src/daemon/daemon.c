/*
 * daemon.c - Main daemon implementation (simplified for compilation)
 */

#include "daemon.h"
#include "pty_manager.h"
#include "../common/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <errno.h>

static daemon_t *g_daemon = NULL;

static void signal_handler(int sig) {
    if (g_daemon) {
        g_daemon->running = false;
    }
}

int daemon_init(daemon_t *daemon) {
    memset(daemon, 0, sizeof(daemon_t));
    daemon->server_fd = -1;
    daemon->running = false;
    return 0;
}

static int create_socket(daemon_t *daemon) {
    struct sockaddr_un addr;
    
    daemon->server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (daemon->server_fd < 0) {
        perror("socket");
        return -1;
    }
    
    unlink(g_config.socket_path);  /* Remove old socket */
    
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_config.socket_path, sizeof(addr.sun_path) - 1);
    
    if (bind(daemon->server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(daemon->server_fd);
        return -1;
    }
    
    if (listen(daemon->server_fd, 5) < 0) {
        perror("listen");
        close(daemon->server_fd);
        return -1;
    }
    
    chmod(g_config.socket_path, 0600);
    
    return 0;
}

static void handle_create(daemon_t *daemon, const message_t *msg, int client_fd) {
    response_t resp = {0};
    
    if (daemon->session_count >= MAX_SESSIONS) {
        resp.status = STATUS_ERROR;
        snprintf(resp.message, sizeof(resp.message), "Maximum session limit reached");
        send_response(client_fd, &resp);
        return;
    }
    
    const char *name = msg->session_name[0] ? msg->session_name : NULL;
    const char *shell = msg->shell[0] ? msg->shell : g_config.default_shell;
    
    session_t *session = session_create(name, shell);
    if (!session) {
        resp.status = STATUS_ERROR;
        snprintf(resp.message, sizeof(resp.message), "Failed to create session");
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
    
    resp.status = STATUS_OK;
    snprintf(resp.message, sizeof(resp.message), "Session '%s' created (id: %s)", 
             session->name, session->id);
    send_response(client_fd, &resp);
}

static void handle_list(daemon_t *daemon, int client_fd) {
    response_t resp = {0};
    resp.status = STATUS_OK;
    snprintf(resp.message, sizeof(resp.message), "Found %d sessions", daemon->session_count);
    
    /* Send count first */
    send_response(client_fd, &resp);
    
    /* Then send each session as JSON */
    for (int i = 0; i < daemon->session_count; i++) {
        char *json = session_to_json(daemon->sessions[i]);
        if (json) {
            uint32_t len = strlen(json) + 1;
            write(client_fd, &len, sizeof(len));
            write(client_fd, json, len);
            free(json);
        }
    }
}

static void handle_client(daemon_t *daemon, int client_fd) {
    message_t msg;
    
    if (recv_message(client_fd, &msg) < 0) {
        close(client_fd);
        return;
    }
    
    switch (msg.command) {
        case CMD_CREATE:
            handle_create(daemon, &msg, client_fd);
            break;
        case CMD_LIST:
            handle_list(daemon, client_fd);
            break;
        case CMD_PING:
            {
                response_t resp = {0};
                resp.status = STATUS_OK;
                snprintf(resp.message, sizeof(resp.message), "pong");
                send_response(client_fd, &resp);
            }
            break;
        default:
            {
                response_t resp = {0};
                resp.status = STATUS_ERROR;
                snprintf(resp.message, sizeof(resp.message), "Command not implemented");
                send_response(client_fd, &resp);
            }
            break;
    }
    
    close(client_fd);
}

int daemon_start(daemon_t *daemon) {
    g_daemon = daemon;
    
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    if (create_socket(daemon) < 0) {
        return -1;
    }
    
    printf("SShell daemon started, listening on %s\n", g_config.socket_path);
    
    daemon->running = true;
    while (daemon->running) {
        int client_fd = accept(daemon->server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }
        
        handle_client(daemon, client_fd);
    }
    
    return 0;
}

void daemon_cleanup(daemon_t *daemon) {
    if (daemon->server_fd >= 0) {
        close(daemon->server_fd);
        unlink(g_config.socket_path);
    }
    
    for (int i = 0; i < daemon->session_count; i++) {
        session_free(daemon->sessions[i]);
    }
}

int main(int argc, char **argv) {
    config_init();
    config_ensure_directories();
    
    daemon_t daemon;
    daemon_init(&daemon);
    
    int ret = daemon_start(&daemon);
    
    daemon_cleanup(&daemon);
    
    return ret;
}
