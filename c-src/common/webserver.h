/*
 * webserver.h - HTTP/WebSocket server for web-based terminal access
 */

#ifndef SSHELL_WEBSERVER_H
#define SSHELL_WEBSERVER_H

#include <libwebsockets.h>
#include <stdbool.h>

#define WEB_PORT 8080
#define MAX_WS_CLIENTS 50

typedef struct {
    struct lws_context *context;
    struct lws_vhost *vhost;
    bool running;
    void *daemon_ctx;  // Pointer to daemon context
} webserver_t;

typedef struct {
    struct lws *wsi;
    char session_id[64];
    char eth_address[43];  // 0x + 40 hex chars
    bool authenticated;
    bool active;
} ws_client_t;

/* Initialize web server */
int webserver_init(webserver_t *server, int port, void *daemon_ctx);

/* Start web server (blocking) */
int webserver_run(webserver_t *server);

/* Stop web server */
void webserver_stop(webserver_t *server);

/* Send data to WebSocket client */
int webserver_send_to_client(webserver_t *server, const char *session_id,
                              const char *data, size_t len);

/* Broadcast to all clients on a session */
int webserver_broadcast_to_session(webserver_t *server, const char *session_id,
                                   const char *data, size_t len);

#endif /* SSHELL_WEBSERVER_H */
