/*
 * daemon.h - Session daemon header
 */

#ifndef SSHELL_DAEMON_H
#define SSHELL_DAEMON_H

#include "../common/session.h"
#include "../common/protocol.h"
#include "../common/multiuser.h"

#define MAX_SESSIONS 100

typedef struct {
    session_t *sessions[MAX_SESSIONS];
    multiuser_session_t multiuser[MAX_SESSIONS];
    int session_count;
    int server_fd;
    bool running;
} daemon_t;

/* Initialize daemon */
int daemon_init(daemon_t *daemon);

/* Start daemon */
int daemon_start(daemon_t *daemon);

/* Cleanup daemon */
void daemon_cleanup(daemon_t *daemon);

#endif /* SSHELL_DAEMON_H */
