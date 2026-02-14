/*
 * network_roaming.h - Network roaming support (mosh-like)
 */

#ifndef SSHELL_NETWORK_ROAMING_H
#define SSHELL_NETWORK_ROAMING_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <time.h>

#define ROAMING_PORT 60001
#define HEARTBEAT_INTERVAL 1  // seconds
#define ROAMING_TIMEOUT 60    // seconds

typedef struct {
    char session_id[64];
    struct sockaddr_in client_addr;
    time_t last_heartbeat;
    uint32_t sequence_num;
    bool active;
} roaming_client_t;

typedef struct {
    int udp_fd;
    roaming_client_t clients[100];
    int client_count;
    bool running;
} roaming_server_t;

/* Initialize roaming server */
int roaming_server_init(roaming_server_t *server, int port);

/* Start roaming server (non-blocking) */
int roaming_server_start(roaming_server_t *server);

/* Process heartbeat packets */
int roaming_server_process(roaming_server_t *server);

/* Update client info */
int roaming_update_client(roaming_server_t *server, const char *session_id,
                         struct sockaddr_in *addr, uint32_t seq);

/* Get client address for session */
bool roaming_get_client_addr(roaming_server_t *server, const char *session_id,
                             struct sockaddr_in *addr);

/* Check if client is active */
bool roaming_is_active(roaming_server_t *server, const char *session_id);

/* Cleanup expired clients */
void roaming_cleanup_expired(roaming_server_t *server);

/* Shutdown roaming server */
void roaming_server_shutdown(roaming_server_t *server);

#endif /* SSHELL_NETWORK_ROAMING_H */
