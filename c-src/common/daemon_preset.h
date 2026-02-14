/*
 * daemon_preset.h - Optional daemon preset configuration loader
 *
 * Loaded only if the preset file exists (typically: ~/.sshell/daemon.json).
 * CLI args still take precedence over presets.
 */

#ifndef SSHELL_DAEMON_PRESET_H
#define SSHELL_DAEMON_PRESET_H

#include <stdbool.h>
#include <stddef.h>

#include "logger.h"

typedef struct {
    bool has_tcp_mode;
    bool tcp_mode;

    bool has_host;
    char host[256];

    bool has_port;
    int port;

    bool has_ufw_auto;
    bool ufw_auto;

    bool has_auth_required;
    bool auth_required;

    bool has_wallet;
    char wallet[128];

    bool has_wallet_allowlist;
    char wallet_allowlist_path[512];

    bool has_ssh_allowlist;
    char ssh_allowlist_path[512];

    bool has_log_level;
    log_level_t log_level;
} daemon_preset_t;

/* Load presets from JSON file. Returns true if loaded successfully. */
bool daemon_preset_load(const char *path, daemon_preset_t *out);

#endif /* SSHELL_DAEMON_PRESET_H */
