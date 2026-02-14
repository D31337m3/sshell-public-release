/*
 * protocol.c - Protocol implementation
 */

#include "protocol.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int send_message(int sockfd, const message_t *msg) {
    uint32_t len = sizeof(message_t);
    if (write(sockfd, &len, sizeof(len)) != sizeof(len)) return -1;
    if (write(sockfd, msg, len) != (ssize_t)len) return -1;
    return 0;
}

int recv_message(int sockfd, message_t *msg) {
    uint32_t len;
    if (read(sockfd, &len, sizeof(len)) != sizeof(len)) return -1;
    if (len != sizeof(message_t)) return -1;
    if (read(sockfd, msg, len) != (ssize_t)len) return -1;
    return 0;
}

int send_response(int sockfd, const response_t *resp) {
    /* Send status and message */
    uint32_t status = resp->status;
    if (write(sockfd, &status, sizeof(status)) != sizeof(status)) return -1;
    
    uint32_t msg_len = strlen(resp->message) + 1;
    if (write(sockfd, &msg_len, sizeof(msg_len)) != sizeof(msg_len)) return -1;
    if (write(sockfd, resp->message, msg_len) != (ssize_t)msg_len) return -1;
    
    /* For simplicity, session data sent separately in real implementation */
    return 0;
}

int recv_response(int sockfd, response_t *resp) {
    uint32_t status;
    if (read(sockfd, &status, sizeof(status)) != sizeof(status)) return -1;
    resp->status = status;
    
    uint32_t msg_len;
    if (read(sockfd, &msg_len, sizeof(msg_len)) != sizeof(msg_len)) return -1;
    if (msg_len > sizeof(resp->message)) return -1;
    if (read(sockfd, resp->message, msg_len) != (ssize_t)msg_len) return -1;
    
    resp->session_count = 0;
    resp->sessions = NULL;
    return 0;
}

void response_free(response_t *resp) {
    if (resp->sessions) {
        for (int i = 0; i < resp->session_count; i++) {
            session_free(resp->sessions[i]);
        }
        free(resp->sessions);
    }
}

/* Binary protocol implementation */
int protocol_receive_message(int fd, binary_message_t *msg) {
    /* Read type */
    if (read(fd, &msg->type, sizeof(msg->type)) != sizeof(msg->type)) {
        return -1;
    }
    
    /* Read session ID */
    if (read(fd, msg->session_id, sizeof(msg->session_id)) != sizeof(msg->session_id)) {
        return -1;
    }
    
    /* Read data */
    if (read(fd, msg->data, sizeof(msg->data)) != sizeof(msg->data)) {
        return -1;
    }
    
    return 0;
}

int protocol_send_response(int fd, resp_status_t status, const char *message) {
    /* Send status */
    uint32_t status_code = status;
    if (write(fd, &status_code, sizeof(status_code)) != sizeof(status_code)) {
        return -1;
    }
    
    /* Send message length */
    uint32_t msg_len = strlen(message) + 1;
    if (write(fd, &msg_len, sizeof(msg_len)) != sizeof(msg_len)) {
        return -1;
    }
    
    /* Send message */
    if (write(fd, message, msg_len) != (ssize_t)msg_len) {
        return -1;
    }
    
    return 0;
}

