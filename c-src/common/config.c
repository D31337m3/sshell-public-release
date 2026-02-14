/*
 * config.c - Configuration implementation
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

config_t g_config;

void config_init(void) {
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : "/tmp";
    }
    
    strncpy(g_config.home_dir, home, sizeof(g_config.home_dir) - 1);
    
    snprintf(g_config.config_dir, sizeof(g_config.config_dir), "%s/.sshell", home);
    snprintf(g_config.session_dir, sizeof(g_config.session_dir), "%s/sessions", g_config.config_dir);
    snprintf(g_config.socket_path, sizeof(g_config.socket_path), "%s/daemon.sock", g_config.config_dir);
    snprintf(g_config.pid_file, sizeof(g_config.pid_file), "%s/daemon.pid", g_config.config_dir);
    snprintf(g_config.log_file, sizeof(g_config.log_file), "%s/daemon.log", g_config.config_dir);
    
    const char *shell = getenv("SHELL");
    strncpy(g_config.default_shell, shell ? shell : "/bin/bash", sizeof(g_config.default_shell) - 1);
    
    g_config.max_sessions = 10;
    g_config.session_timeout = 0;
    g_config.auto_cleanup_dead = true;
    g_config.cleanup_interval = 60;
}

int config_ensure_directories(void) {
    if (mkdir(g_config.config_dir, 0700) != 0 && errno != EEXIST) {
        return -1;
    }
    if (mkdir(g_config.session_dir, 0700) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

void config_get_session_file(const char *session_id, char *path, size_t path_len) {
    snprintf(path, path_len, "%s/%s.json", g_config.session_dir, session_id);
}
