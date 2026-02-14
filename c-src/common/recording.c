/*
 * recording.c - Session recording implementation
 */

#include "recording.h"
#include "logger.h"
#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>

static double get_timestamp() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

static void json_escape(const char *input, char *output, size_t output_size) {
    size_t j = 0;
    for (size_t i = 0; input[i] && j < output_size - 2; i++) {
        switch (input[i]) {
            case '"':  output[j++] = '\\'; output[j++] = '"'; break;
            case '\\': output[j++] = '\\'; output[j++] = '\\'; break;
            case '\n': output[j++] = '\\'; output[j++] = 'n'; break;
            case '\r': output[j++] = '\\'; output[j++] = 'r'; break;
            case '\t': output[j++] = '\\'; output[j++] = 't'; break;
            default:
                if (input[i] >= 32 && input[i] < 127) {
                    output[j++] = input[i];
                } else {
                    j += snprintf(output + j, output_size - j, "\\u%04x", (unsigned char)input[i]);
                }
                break;
        }
    }
    output[j] = '\0';
}

int recording_init(recording_t *rec, const char *session_id, int width, int height) {
    (void)session_id;  // Will be used for filename
    memset(rec, 0, sizeof(recording_t));
    rec->width = width;
    rec->height = height;
    return 0;
}

int recording_start(recording_t *rec, const char *filepath, int width, int height) {
    /* Create recordings directory */
    char rec_dir[1024];
    snprintf(rec_dir, sizeof(rec_dir), "%s/recordings", g_config.config_dir);
    mkdir(rec_dir, 0700);
    
    rec->file = fopen(filepath, "w");
    if (!rec->file) {
        log_error("Failed to open recording file: %s", filepath);
        return -1;
    }
    
    /* Write asciicast v2 header */
    rec->start_time = time(NULL);
    rec->width = width;
    rec->height = height;
    rec->last_event_time = 0;
    
    fprintf(rec->file, "{\"version\": 2, \"width\": %d, \"height\": %d, \"timestamp\": %ld}\n",
            width, height, rec->start_time);
    fflush(rec->file);
    
    rec->active = true;
    log_info("Started recording to %s", filepath);
    
    return 0;
}

int recording_write(recording_t *rec, const char *data, size_t len) {
    if (!rec->active || !rec->file) {
        return -1;
    }
    
    double now = get_timestamp();
    double elapsed = now - (rec->start_time + rec->last_event_time);
    rec->last_event_time += elapsed;
    
    /* Escape JSON */
    char *escaped = malloc(len * 6 + 1);  // Worst case: all chars need escaping
    if (!escaped) return -1;
    
    json_escape(data, escaped, len * 6 + 1);
    
    /* Write event: [time, "o", "data"] */
    fprintf(rec->file, "[%.3f, \"o\", \"%s\"]\n", rec->last_event_time, escaped);
    fflush(rec->file);
    
    free(escaped);
    return 0;
}

int recording_stop(recording_t *rec) {
    if (!rec->active) {
        return -1;
    }
    
    if (rec->file) {
        fclose(rec->file);
        rec->file = NULL;
    }
    
    rec->active = false;
    log_info("Recording stopped");
    
    return 0;
}

int recording_playback(const char *filepath, double speed) {
    FILE *f = fopen(filepath, "r");
    if (!f) {
        log_error("Failed to open recording: %s", filepath);
        return -1;
    }
    
    char line[65536];
    bool first_line = true;
    
    while (fgets(line, sizeof(line), f)) {
        if (first_line) {
            /* Skip header */
            first_line = false;
            continue;
        }
        
        double timestamp;
        char type;
        char data[65536];
        
        /* Parse: [1.234, "o", "data"] */
        if (sscanf(line, "[%lf, \"%c\", \"%[^\"]\"", &timestamp, &type, data) == 3) {
            if (type == 'o') {
                /* Unescape and print */
                size_t j = 0;
                for (size_t i = 0; data[i]; i++) {
                    if (data[i] == '\\' && data[i+1]) {
                        i++;
                        switch (data[i]) {
                            case 'n': putchar('\n'); break;
                            case 'r': putchar('\r'); break;
                            case 't': putchar('\t'); break;
                            case '\\': putchar('\\'); break;
                            case '"': putchar('"'); break;
                            default: putchar(data[i]); break;
                        }
                    } else {
                        putchar(data[i]);
                    }
                    j++;
                }
                fflush(stdout);
                
                /* Sleep for next event (adjusted by speed) */
                if (timestamp > 0) {
                    usleep((useconds_t)(timestamp * 1000000 / speed));
                }
            }
        }
    }
    
    fclose(f);
    return 0;
}

bool recording_is_active(const recording_t *rec) {
    return rec->active;
}
