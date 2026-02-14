/*
 * session.h - Session data structures for SShell
 */

#ifndef SSHELL_SESSION_H
#define SSHELL_SESSION_H

#include <time.h>
#include <stdbool.h>
#include <sys/types.h>

#define SESSION_ID_LEN 9
#define SESSION_NAME_LEN 256
#define SHELL_PATH_LEN 256

typedef enum {
    SESSION_STATUS_CREATED,
    SESSION_STATUS_RUNNING,
    SESSION_STATUS_ATTACHED,
    SESSION_STATUS_DEAD
} session_status_t;

typedef struct {
    char id[SESSION_ID_LEN];
    char name[SESSION_NAME_LEN];
    pid_t pid;
    int master_fd;
    time_t created;
    time_t last_attached;
    time_t last_activity;
    char shell[SHELL_PATH_LEN];
    session_status_t status;
} session_t;

/* Create a new session with generated ID */
session_t* session_create(const char *name, const char *shell);

/* Free session memory */
void session_free(session_t *session);

/* Check if session process is alive */
bool session_is_alive(const session_t *session);

/* Check if session is idle */
bool session_is_idle(const session_t *session, int timeout_seconds);

/* Update last attached timestamp */
void session_update_attached(session_t *session);

/* Update last activity timestamp */
void session_update_activity(session_t *session);

/* Serialize session to JSON string (caller must free) */
char* session_to_json(const session_t *session);

/* Deserialize session from JSON string */
session_t* session_from_json(const char *json_str);

/* Save session to file */
int session_save(const session_t *session, const char *session_dir);

/* Load session from file */
session_t* session_load(const char *session_file);

#endif /* SSHELL_SESSION_H */
