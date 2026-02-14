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

static void compose_path(char *out, size_t out_size, const char *base, const char *leaf) {
    if (out_size == 0) {
        return;
    }

    out[0] = '\0';
    if (!base || !leaf) {
        return;
    }

    strncpy(out, base, out_size - 1);
    out[out_size - 1] = '\0';

    size_t len = strlen(out);
    if (len > 0 && out[len - 1] != '/' && len + 1 < out_size) {
        out[len++] = '/';
        out[len] = '\0';
    }

    strncat(out, leaf, out_size - strlen(out) - 1);
}

void config_init(void) {
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : "/tmp";
    }
    
    strncpy(g_config.home_dir, home, sizeof(g_config.home_dir) - 1);
    
    compose_path(g_config.config_dir, sizeof(g_config.config_dir), home, ".sshell");
    compose_path(g_config.session_dir, sizeof(g_config.session_dir), g_config.config_dir, "sessions");
    compose_path(g_config.socket_path, sizeof(g_config.socket_path), g_config.config_dir, "daemon.sock");
    compose_path(g_config.pid_file, sizeof(g_config.pid_file), g_config.config_dir, "daemon.pid");
    compose_path(g_config.log_file, sizeof(g_config.log_file), g_config.config_dir, "daemon.log");
    
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
