/*
 * network_roaming.c - Network roaming implementation
 */

#include "network_roaming.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

int roaming_server_init(roaming_server_t *server, int port) {
    memset(server, 0, sizeof(roaming_server_t));
    
    server->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server->udp_fd < 0) {
        log_error("Failed to create UDP socket: %s", strerror(errno));
        return -1;
    }
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(server->udp_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_error("Failed to bind UDP socket: %s", strerror(errno));
        close(server->udp_fd);
        return -1;
    }
    
    server->running = true;
    log_info("Network roaming server started on UDP port %d", port);
    
    return 0;
}

int roaming_server_process(roaming_server_t *server) {
    char buffer[1024];
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    ssize_t n = recvfrom(server->udp_fd, buffer, sizeof(buffer) - 1,
                        MSG_DONTWAIT, (struct sockaddr*)&client_addr, &addr_len);
    
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;  // No data
        }
        log_warn("UDP recvfrom error: %s", strerror(errno));
        return -1;
    }
    
    buffer[n] = '\0';
    
    /* Parse heartbeat: session_id:sequence_num */
    char session_id[64];
    uint32_t seq_num;
    if (sscanf(buffer, "%63[^:]:%u", session_id, &seq_num) != 2) {
        log_warn("Invalid heartbeat packet");
        return -1;
    }
    
    /* Update or add client */
    roaming_update_client(server, session_id, &client_addr, seq_num);
    
    /* Send ACK */
    char response[64];
    snprintf(response, sizeof(response), "ACK:%u", seq_num);
    sendto(server->udp_fd, response, strlen(response), 0,
           (struct sockaddr*)&client_addr, addr_len);
    
    return 0;
}

int roaming_update_client(roaming_server_t *server, const char *session_id,
                         struct sockaddr_in *addr, uint32_t seq) {
    /* Find existing client */
    for (int i = 0; i < server->client_count; i++) {
        if (strcmp(server->clients[i].session_id, session_id) == 0) {
            /* Check if IP changed */
            if (server->clients[i].client_addr.sin_addr.s_addr != addr->sin_addr.s_addr ||
                server->clients[i].client_addr.sin_port != addr->sin_port) {
                char old_ip[INET_ADDRSTRLEN], new_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &server->clients[i].client_addr.sin_addr, old_ip, sizeof(old_ip));
                inet_ntop(AF_INET, &addr->sin_addr, new_ip, sizeof(new_ip));
                log_info("Session %s roamed: %s:%d -> %s:%d",
                        session_id, old_ip, ntohs(server->clients[i].client_addr.sin_port),
                        new_ip, ntohs(addr->sin_port));
            }
            
            /* Update info */
            server->clients[i].client_addr = *addr;
            server->clients[i].last_heartbeat = time(NULL);
            server->clients[i].sequence_num = seq;
            server->clients[i].active = true;
            return 0;
        }
    }
    
    /* New client */
    if (server->client_count >= 100) {
        log_warn("Too many roaming clients");
        return -1;
    }
    
    roaming_client_t *client = &server->clients[server->client_count++];
    strncpy(client->session_id, session_id, sizeof(client->session_id) - 1);
    client->client_addr = *addr;
    client->last_heartbeat = time(NULL);
    client->sequence_num = seq;
    client->active = true;
    
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
    log_info("New roaming client: session=%s, addr=%s:%d",
            session_id, ip, ntohs(addr->sin_port));
    
    return 0;
}

bool roaming_get_client_addr(roaming_server_t *server, const char *session_id,
                             struct sockaddr_in *addr) {
    for (int i = 0; i < server->client_count; i++) {
        if (strcmp(server->clients[i].session_id, session_id) == 0 &&
            server->clients[i].active) {
            *addr = server->clients[i].client_addr;
            return true;
        }
    }
    return false;
}

bool roaming_is_active(roaming_server_t *server, const char *session_id) {
    time_t now = time(NULL);
    for (int i = 0; i < server->client_count; i++) {
        if (strcmp(server->clients[i].session_id, session_id) == 0) {
            return server->clients[i].active &&
                   (now - server->clients[i].last_heartbeat) < ROAMING_TIMEOUT;
        }
    }
    return false;
}

void roaming_cleanup_expired(roaming_server_t *server) {
    time_t now = time(NULL);
    
    for (int i = 0; i < server->client_count; i++) {
        if (server->clients[i].active &&
            (now - server->clients[i].last_heartbeat) > ROAMING_TIMEOUT) {
            log_info("Roaming client expired: %s", server->clients[i].session_id);
            server->clients[i].active = false;
        }
    }
}

void roaming_server_shutdown(roaming_server_t *server) {
    if (server->udp_fd >= 0) {
        close(server->udp_fd);
        server->udp_fd = -1;
    }
    server->running = false;
    log_info("Network roaming server shutdown");
}
