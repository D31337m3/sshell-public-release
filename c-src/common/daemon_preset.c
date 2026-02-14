/*
 * daemon_preset.c - Optional daemon preset configuration loader
 */

#include "daemon_preset.h"

#include <json-c/json.h>
#include <string.h>

static bool json_get_bool(struct json_object *root, const char *key, bool *out) {
    struct json_object *tmp = NULL;
    if (!json_object_object_get_ex(root, key, &tmp)) {
        return false;
    }

    if (json_object_is_type(tmp, json_type_boolean)) {
        *out = json_object_get_boolean(tmp);
        return true;
    }

    return false;
}

static bool json_get_int(struct json_object *root, const char *key, int *out) {
    struct json_object *tmp = NULL;
    if (!json_object_object_get_ex(root, key, &tmp)) {
        return false;
    }

    if (json_object_is_type(tmp, json_type_int)) {
        *out = json_object_get_int(tmp);
        return true;
    }

    return false;
}

static bool json_get_string(struct json_object *root, const char *key, char *out, size_t out_size) {
    struct json_object *tmp = NULL;
    if (!json_object_object_get_ex(root, key, &tmp)) {
        return false;
    }

    if (!json_object_is_type(tmp, json_type_string)) {
        return false;
    }

    const char *value = json_object_get_string(tmp);
    if (!value) {
        return false;
    }

    snprintf(out, out_size, "%s", value);
    return true;
}

static bool parse_log_level(const char *value, log_level_t *out) {
    if (!value || !out) {
        return false;
    }

    if (strcasecmp(value, "debug") == 0) {
        *out = LOG_LEVEL_DEBUG;
        return true;
    }
    if (strcasecmp(value, "info") == 0) {
        *out = LOG_LEVEL_INFO;
        return true;
    }
    if (strcasecmp(value, "warn") == 0 || strcasecmp(value, "warning") == 0) {
        *out = LOG_LEVEL_WARN;
        return true;
    }
    if (strcasecmp(value, "error") == 0) {
        *out = LOG_LEVEL_ERROR;
        return true;
    }

    return false;
}

bool daemon_preset_load(const char *path, daemon_preset_t *out) {
    if (!path || !out) {
        return false;
    }

    memset(out, 0, sizeof(*out));

    struct json_object *root = json_object_from_file(path);
    if (!root) {
        return false;
    }

    bool tmp_bool = false;
    int tmp_int = 0;

    char mode[32] = {0};
    if (json_get_string(root, "mode", mode, sizeof(mode))) {
        if (strcasecmp(mode, "tcp") == 0) {
            out->has_tcp_mode = true;
            out->tcp_mode = true;
        } else if (strcasecmp(mode, "unix") == 0) {
            out->has_tcp_mode = true;
            out->tcp_mode = false;
        }
    }

    if (json_get_string(root, "host", out->host, sizeof(out->host))) {
        out->has_host = true;
    }

    if (json_get_int(root, "port", &tmp_int)) {
        if (tmp_int > 0 && tmp_int <= 65535) {
            out->has_port = true;
            out->port = tmp_int;
        }
    }

    if (json_get_bool(root, "ufw_auto", &tmp_bool)) {
        out->has_ufw_auto = true;
        out->ufw_auto = tmp_bool;
    }

    if (json_get_bool(root, "auth_required", &tmp_bool)) {
        out->has_auth_required = true;
        out->auth_required = tmp_bool;
    }

    if (json_get_string(root, "wallet", out->wallet, sizeof(out->wallet))) {
        out->has_wallet = true;
    }

    if (json_get_string(root, "wallet_allowlist", out->wallet_allowlist_path, sizeof(out->wallet_allowlist_path))) {
        out->has_wallet_allowlist = true;
    }

    if (json_get_string(root, "ssh_allowlist", out->ssh_allowlist_path, sizeof(out->ssh_allowlist_path))) {
        out->has_ssh_allowlist = true;
    }

    char log_level[32] = {0};
    if (json_get_string(root, "log_level", log_level, sizeof(log_level))) {
        log_level_t lvl;
        if (parse_log_level(log_level, &lvl)) {
            out->has_log_level = true;
            out->log_level = lvl;
        }
    }

    json_object_put(root);
    return true;
}
