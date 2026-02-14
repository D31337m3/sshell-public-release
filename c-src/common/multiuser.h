/*
 * multiuser.h - Multi-user session sharing
 */

#ifndef SSHELL_MULTIUSER_H
#define SSHELL_MULTIUSER_H

#include <stdbool.h>
#include <time.h>

#define MAX_ATTACHED_USERS 10
#define TOKEN_LENGTH 64

typedef enum {
    ACCESS_READ_ONLY,
    ACCESS_READ_WRITE
} access_mode_t;

typedef struct {
    int fd;
    char username[64];
    access_mode_t access;
    time_t connected_at;
    bool is_guest;
    bool active;
} attached_user_t;

typedef struct {
    attached_user_t users[MAX_ATTACHED_USERS];
    int user_count;
    char share_token[TOKEN_LENGTH + 1];
    char share_owner_id[128];
    bool sharing_enabled;
} multiuser_session_t;

/* Initialize multi-user session */
int multiuser_init(multiuser_session_t *mu);

/* Enable sharing and generate token */
int multiuser_enable_sharing(multiuser_session_t *mu, char *token_out);

/* Disable sharing */
void multiuser_disable_sharing(multiuser_session_t *mu);

/* Add user to session */
int multiuser_add_user(multiuser_session_t *mu, int fd, const char *username,
                      access_mode_t access, bool is_guest);

/* Remove user from session */
void multiuser_remove_user(multiuser_session_t *mu, int fd);

/* Broadcast data to all users */
int multiuser_broadcast(multiuser_session_t *mu, const char *data, size_t len);

/* Send data to specific user */
int multiuser_send_to_user(multiuser_session_t *mu, int fd, const char *data, size_t len);

/* Check if user has write access */
bool multiuser_has_write_access(multiuser_session_t *mu, int fd);

/* Get user count */
int multiuser_get_user_count(multiuser_session_t *mu);

/* Validate share token */
bool multiuser_validate_token(multiuser_session_t *mu, const char *token);

#endif /* SSHELL_MULTIUSER_H */
