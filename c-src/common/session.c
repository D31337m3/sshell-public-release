/*
 * session.c - Session management implementation
 */

#include "session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <json-c/json.h>

/* Generate random session ID */
static void generate_session_id(char *id) {
    const char charset[] = "0123456789abcdef";
    for (int i = 0; i < SESSION_ID_LEN - 1; i++) {
        id[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    id[SESSION_ID_LEN - 1] = '\0';
}

session_t* session_create(const char *name, const char *shell) {
    session_t *session = calloc(1, sizeof(session_t));
    if (!session) return NULL;
    
    generate_session_id(session->id);
    
    if (name) {
        strncpy(session->name, name, SESSION_NAME_LEN - 1);
    } else {
        snprintf(session->name, SESSION_NAME_LEN, "session-%s", session->id);
    }
    
    strncpy(session->shell, shell ? shell : "/bin/bash", SHELL_PATH_LEN - 1);
    
    time_t now = time(NULL);
    session->created = now;
    session->last_attached = now;
    session->last_activity = now;
    session->status = SESSION_STATUS_CREATED;
    session->pid = 0;
    session->master_fd = -1;
    
    return session;
}

void session_free(session_t *session) {
    if (session) {
        free(session);
    }
}

bool session_is_alive(const session_t *session) {
    if (session->pid <= 0) return false;
    
    /* Send signal 0 to check if process exists */
    if (kill(session->pid, 0) == 0) {
        return true;
    }
    return false;
}

bool session_is_idle(const session_t *session, int timeout_seconds) {
    if (timeout_seconds <= 0) return false;
    time_t now = time(NULL);
    return (now - session->last_activity) > timeout_seconds;
}

void session_update_attached(session_t *session) {
    time_t now = time(NULL);
    session->last_attached = now;
    session->last_activity = now;
}

void session_update_activity(session_t *session) {
    session->last_activity = time(NULL);
}

char* session_to_json(const session_t *session) {
    struct json_object *root = json_object_new_object();
    
    json_object_object_add(root, "id", json_object_new_string(session->id));
    json_object_object_add(root, "name", json_object_new_string(session->name));
    json_object_object_add(root, "pid", json_object_new_int(session->pid));
    json_object_object_add(root, "master_fd", json_object_new_int(session->master_fd));
    json_object_object_add(root, "created", json_object_new_int64(session->created));
    json_object_object_add(root, "last_attached", json_object_new_int64(session->last_attached));
    json_object_object_add(root, "last_activity", json_object_new_int64(session->last_activity));
    json_object_object_add(root, "shell", json_object_new_string(session->shell));
    
    const char *status_str;
    switch (session->status) {
        case SESSION_STATUS_CREATED: status_str = "created"; break;
        case SESSION_STATUS_RUNNING: status_str = "running"; break;
        case SESSION_STATUS_ATTACHED: status_str = "attached"; break;
        case SESSION_STATUS_DEAD: status_str = "dead"; break;
        default: status_str = "unknown"; break;
    }
    json_object_object_add(root, "status", json_object_new_string(status_str));
    
    const char *json_str = json_object_to_json_string(root);
    char *result = strdup(json_str);
    
    json_object_put(root);
    return result;
}

session_t* session_from_json(const char *json_str) {
    struct json_object *root = json_tokener_parse(json_str);
    if (!root) return NULL;
    
    session_t *session = calloc(1, sizeof(session_t));
    if (!session) {
        json_object_put(root);
        return NULL;
    }
    
    struct json_object *tmp;
    
    if (json_object_object_get_ex(root, "id", &tmp))
        strncpy(session->id, json_object_get_string(tmp), SESSION_ID_LEN - 1);
    
    if (json_object_object_get_ex(root, "name", &tmp))
        strncpy(session->name, json_object_get_string(tmp), SESSION_NAME_LEN - 1);
    
    if (json_object_object_get_ex(root, "pid", &tmp))
        session->pid = json_object_get_int(tmp);
    
    if (json_object_object_get_ex(root, "master_fd", &tmp))
        session->master_fd = json_object_get_int(tmp);
    
    if (json_object_object_get_ex(root, "created", &tmp))
        session->created = json_object_get_int64(tmp);
    
    if (json_object_object_get_ex(root, "last_attached", &tmp))
        session->last_attached = json_object_get_int64(tmp);
    
    if (json_object_object_get_ex(root, "last_activity", &tmp))
        session->last_activity = json_object_get_int64(tmp);
    else
        session->last_activity = session->last_attached; /* Migration */
    
    if (json_object_object_get_ex(root, "shell", &tmp))
        strncpy(session->shell, json_object_get_string(tmp), SHELL_PATH_LEN - 1);
    
    if (json_object_object_get_ex(root, "status", &tmp)) {
        const char *status_str = json_object_get_string(tmp);
        if (strcmp(status_str, "created") == 0)
            session->status = SESSION_STATUS_CREATED;
        else if (strcmp(status_str, "running") == 0)
            session->status = SESSION_STATUS_RUNNING;
        else if (strcmp(status_str, "attached") == 0)
            session->status = SESSION_STATUS_ATTACHED;
        else if (strcmp(status_str, "dead") == 0)
            session->status = SESSION_STATUS_DEAD;
    }
    
    json_object_put(root);
    return session;
}

int session_save(const session_t *session, const char *session_dir) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.json", session_dir, session->id);
    
    char *json = session_to_json(session);
    if (!json) return -1;
    
    FILE *f = fopen(path, "w");
    if (!f) {
        free(json);
        return -1;
    }
    
    fprintf(f, "%s\n", json);
    fclose(f);
    free(json);
    
    return 0;
}

session_t* session_load(const char *session_file) {
    FILE *f = fopen(session_file, "r");
    if (!f) return NULL;
    
    char buffer[4096];
    size_t len = fread(buffer, 1, sizeof(buffer) - 1, f);
    fclose(f);
    
    if (len == 0) return NULL;
    buffer[len] = '\0';
    
    return session_from_json(buffer);
}
