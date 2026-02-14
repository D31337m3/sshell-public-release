/*
 * logger.h - Logging utility
 */

#ifndef SSHELL_LOGGER_H
#define SSHELL_LOGGER_H

#include <stdio.h>
#include <stdbool.h>

typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR
} log_level_t;

typedef struct {
    FILE *file;
    log_level_t level;
    bool to_stderr;
} logger_t;

/* Global logger */
extern logger_t g_logger;

/* Initialize logger */
int logger_init(const char *log_file, log_level_t level, bool to_stderr);

/* Close logger */
void logger_close(void);

/* Log functions */
void log_debug(const char *fmt, ...);
void log_info(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_error(const char *fmt, ...);

#endif /* SSHELL_LOGGER_H */
