/*
 * multiuser.c - Multi-user session implementation
 */

#include "multiuser.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static void generate_token(char *token, size_t len) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    srand(time(NULL));
    
    for (size_t i = 0; i < len; i++) {
        token[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    token[len] = '\0';
}

int multiuser_init(multiuser_session_t *mu) {
    memset(mu, 0, sizeof(multiuser_session_t));
    return 0;
}

int multiuser_enable_sharing(multiuser_session_t *mu, char *token_out) {
    generate_token(mu->share_token, TOKEN_LENGTH);
    mu->sharing_enabled = true;
    
    if (token_out) {
        strcpy(token_out, mu->share_token);
    }
    
    log_info("Sharing enabled with token: %s", mu->share_token);
    return 0;
}

void multiuser_disable_sharing(multiuser_session_t *mu) {
    mu->sharing_enabled = false;
    memset(mu->share_token, 0, sizeof(mu->share_token));
    log_info("Sharing disabled");
}

int multiuser_add_user(multiuser_session_t *mu, int fd, const char *username,
                      access_mode_t access) {
    if (mu->user_count >= MAX_ATTACHED_USERS) {
        log_warn("Maximum attached users reached");
        return -1;
    }
    
    attached_user_t *user = &mu->users[mu->user_count++];
    user->fd = fd;
    strncpy(user->username, username, sizeof(user->username) - 1);
    user->access = access;
    user->connected_at = time(NULL);
    user->active = true;
    
    log_info("User '%s' joined session (access: %s)",
            username, access == ACCESS_READ_WRITE ? "read-write" : "read-only");
    
    return 0;
}

void multiuser_remove_user(multiuser_session_t *mu, int fd) {
    for (int i = 0; i < mu->user_count; i++) {
        if (mu->users[i].fd == fd && mu->users[i].active) {
            log_info("User '%s' left session", mu->users[i].username);
            mu->users[i].active = false;
            
            /* Compact array */
            for (int j = i; j < mu->user_count - 1; j++) {
                mu->users[j] = mu->users[j + 1];
            }
            mu->user_count--;
            return;
        }
    }
}

int multiuser_broadcast(multiuser_session_t *mu, const char *data, size_t len) {
    int sent = 0;
    
    for (int i = 0; i < mu->user_count; i++) {
        if (mu->users[i].active) {
            ssize_t n = write(mu->users[i].fd, data, len);
            if (n > 0) {
                sent++;
            } else if (n < 0) {
                log_warn("Failed to send to user '%s'", mu->users[i].username);
            }
        }
    }
    
    return sent;
}

int multiuser_send_to_user(multiuser_session_t *mu, int fd, const char *data, size_t len) {
    for (int i = 0; i < mu->user_count; i++) {
        if (mu->users[i].fd == fd && mu->users[i].active) {
            ssize_t n = write(fd, data, len);
            return n > 0 ? 0 : -1;
        }
    }
    return -1;
}

bool multiuser_has_write_access(multiuser_session_t *mu, int fd) {
    for (int i = 0; i < mu->user_count; i++) {
        if (mu->users[i].fd == fd && mu->users[i].active) {
            return mu->users[i].access == ACCESS_READ_WRITE;
        }
    }
    return false;
}

int multiuser_get_user_count(multiuser_session_t *mu) {
    return mu->user_count;
}

bool multiuser_validate_token(multiuser_session_t *mu, const char *token) {
    if (!mu->sharing_enabled) {
        return false;
    }
    return strcmp(mu->share_token, token) == 0;
}
