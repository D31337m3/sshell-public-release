/*
 * protocol.h - Client-daemon protocol (simplified)
 */

#ifndef SSHELL_PROTOCOL_H
#define SSHELL_PROTOCOL_H

#include <stdint.h>
#include "session.h"

typedef enum {
    CMD_CREATE,
    CMD_ATTACH,
    CMD_LIST,
    CMD_KILL,
    CMD_RENAME,
    CMD_RESIZE,
    CMD_STATUS,
    CMD_PING,
    CMD_SHUTDOWN,
    CMD_REC_START,    // Start recording
    CMD_REC_STOP,     // Stop recording
    CMD_REC_PLAY,     // Playback recording
    CMD_SHARE,        // Enable session sharing
    CMD_JOIN,         // Join shared session
    CMD_STOPSHARE     // Disable session sharing
} command_t;

typedef enum {
    STATUS_OK,
    STATUS_ERROR,
    STATUS_NOT_FOUND,
    STATUS_ALREADY_EXISTS
} status_t;

/* Simple message structure (can be enhanced with JSON) */
typedef struct {
    command_t command;
    char session_id[64];
    char session_name[256];
    char new_name[256];
    char shell[256];
    char share_token[128];
    char auth_wallet_address[128];
    char auth_wallet_message[256];
    char auth_wallet_signature[256];
    char auth_ssh_key_id[128];
    int rows;
    int cols;
    bool no_attach;
} message_t;

typedef struct {
    status_t status;
    char message[512];
    int session_count;
    session_t **sessions;  /* Array of session pointers for LIST */
} response_t;

/* Send/receive message over socket */
int send_message(int sockfd, const message_t *msg);
int recv_message(int sockfd, message_t *msg);

/* Send/receive response */
int send_response(int sockfd, const response_t *resp);
int recv_response(int sockfd, response_t *resp);

/* Free response resources */
void response_free(response_t *resp);

/* Binary protocol for Phase 5 daemon */
typedef enum {
    MSG_CREATE = CMD_CREATE,
    MSG_ATTACH = CMD_ATTACH,
    MSG_LIST = CMD_LIST,
    MSG_KILL = CMD_KILL,
    MSG_RENAME = CMD_RENAME,
    MSG_RESIZE = CMD_RESIZE,
    MSG_STATUS = CMD_STATUS,
    MSG_REC_START = CMD_REC_START,
    MSG_REC_STOP = CMD_REC_STOP,
    MSG_REC_PLAY = CMD_REC_PLAY,
    MSG_SHARE = CMD_SHARE,
    MSG_JOIN = CMD_JOIN,
    MSG_STOPSHARE = CMD_STOPSHARE
} msg_type_t;

typedef enum {
    RESP_OK = STATUS_OK,
    RESP_ERROR = STATUS_ERROR,
    RESP_NOT_FOUND = STATUS_NOT_FOUND
} resp_status_t;

/* Binary message structure */
typedef struct {
    msg_type_t type;
    char session_id[64];
    char data[256];
} binary_message_t;

/* Binary protocol functions */
int protocol_receive_message(int fd, binary_message_t *msg);
int protocol_send_response(int fd, resp_status_t status, const char *message);

#endif /* SSHELL_PROTOCOL_H */
