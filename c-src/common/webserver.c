/*
 * webserver.c - Web server implementation
 */

#include "webserver.h"
#include "logger.h"
#include "../daemon/daemon.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <json-c/json.h>

static ws_client_t *g_ws_clients[MAX_WS_CLIENTS];
static int g_ws_client_count = 0;
static pthread_mutex_t g_ws_lock = PTHREAD_MUTEX_INITIALIZER;

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
"        const ts = Math.floor(Date.now() / 1000);\n"
"        const message = 'SSHell v1.6.3 auth ' + ts + ' ' + location.host + ' web';\n"
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
"          term.write('\\r\\n[web] authenticated\\r\\n');\n"
"        } else if (data.type === 'error') {\n"
"          alert(data.message || 'Error');\n"
"          return;\n"
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

static bool client_out_append(ws_client_t *c, const unsigned char *data, size_t len) {
    if (!c || !data || len == 0) {
        return true;
    }

    if (c->out_len + len > c->out_cap) {
        size_t new_cap = c->out_cap ? c->out_cap : 16384;
        while (new_cap < c->out_len + len) {
            new_cap *= 2;
            if (new_cap > (1u << 20)) {
                break;
            }
        }
        if (new_cap < c->out_len + len) {
            return false;
        }

        unsigned char *p = (unsigned char *)realloc(c->out_buf, new_cap);
        if (!p) {
            return false;
        }
        c->out_buf = p;
        c->out_cap = new_cap;
    }

    memcpy(c->out_buf + c->out_len, data, len);
    c->out_len += len;
    return true;
}

static void client_out_consume(ws_client_t *c, size_t len) {
    if (!c || len == 0) {
        return;
    }
    if (len >= c->out_len) {
        c->out_len = 0;
        return;
    }
    memmove(c->out_buf, c->out_buf + len, c->out_len - len);
    c->out_len -= len;
}

static bool b64_encode(const unsigned char *in, size_t in_len, char *out, size_t out_cap, size_t *out_len) {
    if (!in || !out || out_cap == 0) {
        return false;
    }
    int need = 4 * (int)((in_len + 2) / 3);
    if (need < 0 || (size_t)need + 1 > out_cap) {
        return false;
    }
    int wrote = EVP_EncodeBlock((unsigned char *)out, in, (int)in_len);
    if (wrote < 0) {
        return false;
    }
    out[wrote] = '\0';
    if (out_len) {
        *out_len = (size_t)wrote;
    }
    return true;
}

static bool b64_decode(const char *in, unsigned char *out, size_t out_cap, size_t *out_len) {
    if (!in || !out) {
        return false;
    }
    size_t in_len = strlen(in);
    if (in_len == 0 || (in_len % 4) != 0) {
        return false;
    }
    int wrote = EVP_DecodeBlock(out, (const unsigned char *)in, (int)in_len);
    if (wrote < 0) {
        return false;
    }

    /* Adjust for padding */
    size_t actual = (size_t)wrote;
    if (in_len >= 1 && in[in_len - 1] == '=') actual--;
    if (in_len >= 2 && in[in_len - 2] == '=') actual--;

    if (actual > out_cap) {
        return false;
    }
    if (out_len) {
        *out_len = actual;
    }
    return true;
}

static int ws_send_json(struct lws *wsi, const char *json, size_t json_len) {
    unsigned char *buf = (unsigned char *)malloc(LWS_PRE + json_len);
    if (!buf) {
        return -1;
    }
    memcpy(buf + LWS_PRE, json, json_len);
    int n = lws_write(wsi, buf + LWS_PRE, json_len, LWS_WRITE_TEXT);
    free(buf);
    return n;
}

static void register_client(ws_client_t *client) {
    if (!client || !client->wsi) {
        return;
    }

    pthread_mutex_lock(&g_ws_lock);
    for (int i = 0; i < g_ws_client_count; i++) {
        if (g_ws_clients[i] == client) {
            pthread_mutex_unlock(&g_ws_lock);
            return;
        }
    }
    if (g_ws_client_count < MAX_WS_CLIENTS) {
        g_ws_clients[g_ws_client_count++] = client;
    }
    pthread_mutex_unlock(&g_ws_lock);
}

static void unregister_client(ws_client_t *client) {
    pthread_mutex_lock(&g_ws_lock);
    for (int i = 0; i < g_ws_client_count; i++) {
        if (g_ws_clients[i] == client) {
            g_ws_clients[i] = g_ws_clients[g_ws_client_count - 1];
            g_ws_clients[g_ws_client_count - 1] = NULL;
            g_ws_client_count--;
            break;
        }
    }
    pthread_mutex_unlock(&g_ws_lock);
}

static int callback_http(struct lws *wsi, enum lws_callback_reasons reason,
                        void *user, void *in, size_t len) {
    (void)user;
    (void)len;
    
    switch (reason) {
        case LWS_CALLBACK_HTTP: {
            const char *uri = (const char *)in;
            if (!uri || (strcmp(uri, "/") != 0 && strcmp(uri, "/index.html") != 0)) {
                lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
                return -1;
            }

            const size_t body_len = strlen(html_template);
            unsigned char headers[LWS_PRE + 256];
            unsigned char *p = headers + LWS_PRE;
            unsigned char *end = headers + sizeof(headers);
            const unsigned char *ct = (const unsigned char *)"text/html";

            if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end) != 0 ||
                lws_add_http_header_by_token(wsi,
                                             WSI_TOKEN_HTTP_CONTENT_TYPE,
                                             ct,
                                             (int)strlen((const char *)ct),
                                             &p,
                                             end) != 0 ||
                lws_add_http_header_content_length(wsi, body_len, &p, end) != 0 ||
                lws_finalize_http_header(wsi, &p, end) != 0) {
                return -1;
            }

            if (lws_write(wsi,
                          headers + LWS_PRE,
                          (size_t)(p - (headers + LWS_PRE)),
                          LWS_WRITE_HTTP_HEADERS) < 0) {
                return -1;
            }
            if (lws_write(wsi, (unsigned char *)html_template, body_len, LWS_WRITE_HTTP_FINAL) < 0) {
                return -1;
            }
            return -1;
        }
            
        default:
            break;
    }
    return 0;
}

static int callback_websocket(struct lws *wsi, enum lws_callback_reasons reason,
                              void *user, void *in, size_t len) {
    ws_client_t *client = (ws_client_t*)user;
    webserver_t *server = (webserver_t *)lws_context_user(lws_get_context(wsi));
    daemon_t *daemon = server ? (daemon_t *)server->daemon_ctx : NULL;
    
    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED:
            log_info("WebSocket client connected");
            client->wsi = wsi;
            client->authenticated = false;
            client->session_id[0] = '\0';
            client->eth_address[0] = '\0';
            client->active = true;
            client->out_buf = NULL;
            client->out_len = 0;
            client->out_cap = 0;
            register_client(client);
            break;
            
        case LWS_CALLBACK_RECEIVE:
            {
                if (!daemon) {
                    const char *err = "{\"type\":\"error\",\"message\":\"daemon unavailable\"}";
                    (void)ws_send_json(wsi, err, strlen(err));
                    break;
                }

                char *msg = (char *)malloc(len + 1);
                if (!msg) {
                    break;
                }
                memcpy(msg, in, len);
                msg[len] = '\0';

                struct json_object *root = json_tokener_parse(msg);
                free(msg);
                if (!root) {
                    break;
                }

                struct json_object *jt = NULL;
                if (!json_object_object_get_ex(root, "type", &jt) || !json_object_is_type(jt, json_type_string)) {
                    json_object_put(root);
                    break;
                }
                const char *type = json_object_get_string(jt);

                if (strcmp(type, "auth") == 0) {
                    struct json_object *ja = NULL, *jm = NULL, *js = NULL, *jsession = NULL;
                    if (!json_object_object_get_ex(root, "address", &ja) ||
                        !json_object_object_get_ex(root, "message", &jm) ||
                        !json_object_object_get_ex(root, "signature", &js) ||
                        !json_object_object_get_ex(root, "session", &jsession)) {
                        const char *err = "{\"type\":\"error\",\"message\":\"missing auth fields\"}";
                        (void)ws_send_json(wsi, err, strlen(err));
                        json_object_put(root);
                        break;
                    }

                    const char *addr = json_object_get_string(ja);
                    const char *m = json_object_get_string(jm);
                    const char *sig = json_object_get_string(js);
                    const char *target = json_object_get_string(jsession);

                    if (!daemon_web_is_authorized_wallet(addr, m, sig)) {
                        const char *err = "{\"type\":\"error\",\"message\":\"auth failed\"}";
                        (void)ws_send_json(wsi, err, strlen(err));
                        json_object_put(root);
                        break;
                    }

                    session_t *sess = daemon_find_session(daemon, target);
                    if (!sess) {
                        const char *err = "{\"type\":\"error\",\"message\":\"session not found\"}";
                        (void)ws_send_json(wsi, err, strlen(err));
                        json_object_put(root);
                        break;
                    }

                    snprintf(client->eth_address, sizeof(client->eth_address), "%s", addr);
                    snprintf(client->session_id, sizeof(client->session_id), "%s", sess->id);
                    client->authenticated = true;

                    const char *ok = "{\"type\":\"auth_ok\"}";
                    (void)ws_send_json(wsi, ok, strlen(ok));

                    lws_callback_on_writable(wsi);
                } else if (strcmp(type, "input") == 0) {
                    if (!client->authenticated || !client->session_id[0]) {
                        json_object_put(root);
                        break;
                    }

                    struct json_object *jd = NULL;
                    if (json_object_object_get_ex(root, "data", &jd) && json_object_is_type(jd, json_type_string)) {
                        const char *b64 = json_object_get_string(jd);
                        unsigned char decoded[4096];
                        size_t decoded_len = 0;
                        if (b64_decode(b64, decoded, sizeof(decoded), &decoded_len)) {
                            (void)daemon_write_to_session(daemon, client->session_id, (const char *)decoded, decoded_len);
                        }
                    }
                }

                json_object_put(root);
            }
            break;

        case LWS_CALLBACK_SERVER_WRITEABLE:
            if (!client->active || !client->authenticated || !client->session_id[0]) {
                break;
            }

            pthread_mutex_lock(&g_ws_lock);
            if (client->out_len > 0) {
                const size_t chunk = (client->out_len > 2048) ? 2048 : client->out_len;
                char b64[4096];
                size_t b64_len = 0;
                if (b64_encode(client->out_buf, chunk, b64, sizeof(b64), &b64_len)) {
                    char json[4600];
                    int wrote = snprintf(json,
                                         sizeof(json),
                                         "{\"type\":\"output\",\"data\":\"%s\"}",
                                         b64);
                    if (wrote > 0 && (size_t)wrote < sizeof(json)) {
                        (void)ws_send_json(wsi, json, (size_t)wrote);
                        client_out_consume(client, chunk);
                    }
                }

                if (client->out_len > 0) {
                    lws_callback_on_writable(wsi);
                }
            }
            pthread_mutex_unlock(&g_ws_lock);
            break;
            
        case LWS_CALLBACK_CLOSED:
            log_info("WebSocket client disconnected");
            client->active = false;
            unregister_client(client);
            pthread_mutex_lock(&g_ws_lock);
            free(client->out_buf);
            client->out_buf = NULL;
            client->out_len = 0;
            client->out_cap = 0;
            pthread_mutex_unlock(&g_ws_lock);
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
    info.user = server;
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
    if (!server || !server->context || !session_id || !session_id[0] || !data || len == 0) {
        return -1;
    }

    /* For now, treat as broadcast to that session. */
    return webserver_broadcast_to_session(server, session_id, data, len);
}

int webserver_broadcast_to_session(webserver_t *server, const char *session_id,
                                   const char *data, size_t len) {
    if (!server || !server->context || !session_id || !session_id[0] || !data || len == 0) {
        return -1;
    }

    /* NOTE: libwebsockets isn't thread-safe for direct writes from other threads.
       We buffer output here and ask the lws service thread to flush. */
    pthread_mutex_lock(&g_ws_lock);
    for (int i = 0; i < g_ws_client_count; i++) {
        ws_client_t *c = g_ws_clients[i];
        if (!c || !c->active || !c->authenticated) {
            continue;
        }
        if (strcmp(c->session_id, session_id) != 0) {
            continue;
        }

        /* Append output and schedule a flush */
        if (client_out_append(c, (const unsigned char *)data, len)) {
            lws_callback_on_writable(c->wsi);
        }
    }
    pthread_mutex_unlock(&g_ws_lock);

    lws_cancel_service(server->context);
    return 0;
}

int webserver_get_session_client_count(webserver_t *server, const char *session_id) {
    if (!server || !server->context || !session_id || !session_id[0]) {
        return 0;
    }

    int count = 0;
    pthread_mutex_lock(&g_ws_lock);
    for (int i = 0; i < g_ws_client_count; i++) {
        ws_client_t *c = g_ws_clients[i];
        if (!c || !c->active || !c->authenticated) {
            continue;
        }
        if (strcmp(c->session_id, session_id) == 0) {
            count++;
        }
    }
    pthread_mutex_unlock(&g_ws_lock);
    return count;
}
