/*
 * daemon.h - Session daemon header
 */

#ifndef SSHELL_DAEMON_H
#define SSHELL_DAEMON_H

#include "../common/session.h"
#include "../common/protocol.h"
#include "../common/multiuser.h"
#include "../common/recording.h"

#define MAX_SESSIONS 100

typedef struct {
    session_t *sessions[MAX_SESSIONS];
    multiuser_session_t multiuser[MAX_SESSIONS];
    recording_t recordings[MAX_SESSIONS];
    char recording_paths[MAX_SESSIONS][512];
    int session_count;
    int server_fd;
    bool running;
} daemon_t;

/* Web terminal helpers (used by common/webserver.c) */
bool daemon_web_is_authorized_wallet(const char *address,
                                     const char *message,
                                     const char *signature);

/* Find a session by name or id; returns NULL if not found */
session_t *daemon_find_session(daemon_t *daemon, const char *target);

/* Write input bytes to a session PTY by session id; returns bytes written or -1 */
ssize_t daemon_write_to_session(daemon_t *daemon,
                               const char *session_id,
                               const char *data,
                               size_t len);

/* Initialize daemon */
int daemon_init(daemon_t *daemon);

/* Start daemon */
int daemon_start(daemon_t *daemon);

/* Cleanup daemon */
void daemon_cleanup(daemon_t *daemon);

#endif /* SSHELL_DAEMON_H */
