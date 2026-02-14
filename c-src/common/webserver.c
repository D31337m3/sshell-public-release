/*
 * webserver.c - Web server implementation
 */

#include "webserver.h"
#include "logger.h"
#include "metamask_auth.h"
#include <stdlib.h>
#include <string.h>

static ws_client_t ws_clients[MAX_WS_CLIENTS];
static int ws_client_count = 0;

/* HTML template for terminal viewer */
static const char *html_template = 
"<!DOCTYPE html>\n"
"<html>\n"
"<head>\n"
"  <title>SShell Web Terminal</title>\n"
"  <link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/xterm@5.1.0/css/xterm.min.css\" />\n"
"  <script src=\"https://cdn.jsdelivr.net/npm/xterm@5.1.0/lib/xterm.min.js\"></script>\n"
"  <script src=\"https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.7.0/lib/xterm-addon-fit.min.js\"></script>\n"
"  <script src=\"https://cdn.ethers.io/lib/ethers-5.2.umd.min.js\"></script>\n"
"  <style>\n"
"    body { margin: 0; padding: 20px; background: #1e1e1e; font-family: monospace; }\n"
"    #terminal { width: 100%%; height: 80vh; }\n"
"    #auth { color: #fff; margin-bottom: 20px; }\n"
"    button { padding: 10px 20px; font-size: 16px; cursor: pointer; }\n"
"  </style>\n"
"</head>\n"
"<body>\n"
"  <div id=\"auth\">\n"
"    <button id=\"connectBtn\" onclick=\"connectMetaMask()\">Connect MetaMask</button>\n"
"    <span id=\"status\">Not connected</span>\n"
"  </div>\n"
"  <div id=\"terminal\"></div>\n"
"  <script>\n"
"    let ws = null;\n"
"    let term = null;\n"
"    let address = null;\n"
"    let sessionId = new URLSearchParams(window.location.search).get('session') || 'default';\n"
"\n"
"    async function connectMetaMask() {\n"
"      if (typeof window.ethereum === 'undefined') {\n"
"        alert('MetaMask not installed!');\n"
"        return;\n"
"      }\n"
"      try {\n"
"        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });\n"
"        address = accounts[0];\n"
"        const message = 'Sign this message to access SShell: ' + Date.now();\n"
"        const signature = await window.ethereum.request({\n"
"          method: 'personal_sign',\n"
"          params: [message, address]\n"
"        });\n"
"        document.getElementById('status').textContent = 'Connected: ' + address.substring(0, 10) + '...';\n"
"        connectWebSocket(address, message, signature);\n"
"      } catch (err) {\n"
"        console.error(err);\n"
"        alert('Failed to connect: ' + err.message);\n"
"      }\n"
"    }\n"
"\n"
"    function connectWebSocket(addr, msg, sig) {\n"
"      ws = new WebSocket('ws://' + location.host + '/ws');\n"
"      ws.onopen = () => {\n"
"        ws.send(JSON.stringify({ type: 'auth', address: addr, message: msg, signature: sig, session: sessionId }));\n"
"      };\n"
"      ws.onmessage = (evt) => {\n"
"        const data = JSON.parse(evt.data);\n"
"        if (data.type === 'auth_ok') {\n"
"          initTerminal();\n"
"        } else if (data.type === 'output') {\n"
"          term.write(atob(data.data));\n"
"        }\n"
"      };\n"
"      ws.onerror = (err) => console.error('WebSocket error:', err);\n"
"      ws.onclose = () => document.getElementById('status').textContent = 'Disconnected';\n"
"    }\n"
"\n"
"    function initTerminal() {\n"
"      term = new Terminal({ cursorBlink: true, fontSize: 14 });\n"
"      const fitAddon = new FitAddon.FitAddon();\n"
"      term.loadAddon(fitAddon);\n"
"      term.open(document.getElementById('terminal'));\n"
"      fitAddon.fit();\n"
"      term.onData(data => {\n"
"        ws.send(JSON.stringify({ type: 'input', data: btoa(data) }));\n"
"      });\n"
"      window.addEventListener('resize', () => fitAddon.fit());\n"
"    }\n"
"  </script>\n"
"</body>\n"
"</html>\n";

static int callback_http(struct lws *wsi, enum lws_callback_reasons reason,
                        void *user, void *in, size_t len) {
    (void)user;
    (void)in;
    (void)len;
    
    switch (reason) {
        case LWS_CALLBACK_HTTP:
            /* Serve HTML page */
            lws_serve_http_file(wsi, "text/html", html_template, strlen(html_template), 0);
            return 0;
            
        default:
            break;
    }
    return 0;
}

static int callback_websocket(struct lws *wsi, enum lws_callback_reasons reason,
                              void *user, void *in, size_t len) {
    ws_client_t *client = (ws_client_t*)user;
    
    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED:
            log_info("WebSocket client connected");
            client->wsi = wsi;
            client->active = true;
            break;
            
        case LWS_CALLBACK_RECEIVE:
            /* Parse JSON message */
            {
                char *msg = malloc(len + 1);
                memcpy(msg, in, len);
                msg[len] = '\0';
                
                /* TODO: Parse JSON and handle auth/input */
                log_debug("WebSocket received: %s", msg);
                
                /* Example auth response */
                const char *response = "{\"type\":\"auth_ok\"}";
                unsigned char buf[LWS_PRE + 256];
                memcpy(&buf[LWS_PRE], response, strlen(response));
                lws_write(wsi, &buf[LWS_PRE], strlen(response), LWS_WRITE_TEXT);
                
                free(msg);
            }
            break;
            
        case LWS_CALLBACK_CLOSED:
            log_info("WebSocket client disconnected");
            client->active = false;
            break;
            
        default:
            break;
    }
    
    return 0;
}

static struct lws_protocols protocols[] = {
    { "http", callback_http, 0, 0, 0, NULL, 0 },
    { "ws", callback_websocket, sizeof(ws_client_t), 1024, 0, NULL, 0 },
    { NULL, NULL, 0, 0, 0, NULL, 0 }
};

int webserver_init(webserver_t *server, int port, void *daemon_ctx) {
    memset(server, 0, sizeof(webserver_t));
    server->daemon_ctx = daemon_ctx;
    
    struct lws_context_creation_info info = {0};
    info.port = port;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    
    server->context = lws_create_context(&info);
    if (!server->context) {
        log_error("Failed to create WebSocket context");
        return -1;
    }
    
    server->running = true;
    log_info("Web server started on port %d", port);
    
    return 0;
}

int webserver_run(webserver_t *server) {
    while (server->running) {
        lws_service(server->context, 50);
    }
    return 0;
}

void webserver_stop(webserver_t *server) {
    server->running = false;
    if (server->context) {
        lws_context_destroy(server->context);
        server->context = NULL;
    }
    log_info("Web server stopped");
}

int webserver_send_to_client(webserver_t *server, const char *session_id,
                              const char *data, size_t len) {
    (void)server;
    (void)session_id;
    (void)data;
    (void)len;
    /* TODO: Implement */
    return 0;
}

int webserver_broadcast_to_session(webserver_t *server, const char *session_id,
                                   const char *data, size_t len) {
    (void)server;
    (void)session_id;
    (void)data;
    (void)len;
    /* TODO: Implement */
    return 0;
}
