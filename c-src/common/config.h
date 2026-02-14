/*
 * config.h - Configuration management
 */

#ifndef SSHELL_CONFIG_H
#define SSHELL_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    char home_dir[256];
    char config_dir[512];
    char session_dir[512];
    char socket_path[512];
    char pid_file[512];
    char log_file[512];
    char default_shell[256];
    int max_sessions;
    int session_timeout;
    bool auto_cleanup_dead;
    int cleanup_interval;
} config_t;

/* Global configuration */
extern config_t g_config;

/* Initialize configuration */
void config_init(void);

/* Ensure directories exist */
int config_ensure_directories(void);

/* Get session file path */
void config_get_session_file(const char *session_id, char *path, size_t path_len);

#endif /* SSHELL_CONFIG_H */
