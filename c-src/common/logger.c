/*
 * logger.c - Logging implementation
 */

#include "logger.h"
#include <stdarg.h>
#include <time.h>
#include <string.h>

logger_t g_logger = {0};

int logger_init(const char *log_file, log_level_t level, bool to_stderr) {
    if (log_file) {
        g_logger.file = fopen(log_file, "a");
        if (!g_logger.file && !to_stderr) {
            return -1;
        }
    }
    
    g_logger.level = level;
    g_logger.to_stderr = to_stderr;
    return 0;
}

void logger_close(void) {
    if (g_logger.file) {
        fclose(g_logger.file);
        g_logger.file = NULL;
    }
}

static const char* level_to_string(log_level_t level) {
    switch (level) {
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_INFO:  return "INFO";
        case LOG_LEVEL_WARN:  return "WARN";
        case LOG_LEVEL_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

static void log_message(log_level_t level, const char *fmt, va_list args) {
    if (level < g_logger.level) return;
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    char message[1024];
    vsnprintf(message, sizeof(message), fmt, args);
    
    char formatted[1200];
    snprintf(formatted, sizeof(formatted), "[%s] %s: %s\n",
             timestamp, level_to_string(level), message);
    
    if (g_logger.file) {
        fputs(formatted, g_logger.file);
        fflush(g_logger.file);
    }
    
    if (g_logger.to_stderr) {
        fputs(formatted, stderr);
    }
}

void log_debug(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_message(LOG_LEVEL_DEBUG, fmt, args);
    va_end(args);
}

void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_message(LOG_LEVEL_INFO, fmt, args);
    va_end(args);
}

void log_warn(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_message(LOG_LEVEL_WARN, fmt, args);
    va_end(args);
}

void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_message(LOG_LEVEL_ERROR, fmt, args);
    va_end(args);
}
