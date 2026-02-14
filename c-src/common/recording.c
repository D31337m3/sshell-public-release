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

static void json_escape_len(const char *input, size_t input_len, char *output, size_t output_size) {
    size_t j = 0;
    if (!input || !output || output_size == 0) {
        return;
    }

    for (size_t i = 0; i < input_len && j < output_size - 2; i++) {
        unsigned char c = (unsigned char)input[i];
        switch (c) {
            case '"':  output[j++] = '\\'; output[j++] = '"'; break;
            case '\\': output[j++] = '\\'; output[j++] = '\\'; break;
            case '\n': output[j++] = '\\'; output[j++] = 'n'; break;
            case '\r': output[j++] = '\\'; output[j++] = 'r'; break;
            case '\t': output[j++] = '\\'; output[j++] = 't'; break;
            default:
                if (c >= 32 && c < 127) {
                    output[j++] = (char)c;
                } else {
                    int wrote = snprintf(output + j, output_size - j, "\\u%04x", c);
                    if (wrote < 0) {
                        output[j] = '\0';
                        return;
                    }
                    j += (size_t)wrote;
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
    rec->start_ts = get_timestamp();
    rec->width = width;
    rec->height = height;
    rec->last_event_ts = 0;
    
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

    if (!data || len == 0) {
        return 0;
    }

    /* Avoid unbounded allocations on pathological output */
    if (len > 256 * 1024) {
        len = 256 * 1024;
    }
    
    double now = get_timestamp();
    double elapsed = now - rec->start_ts;
    if (elapsed < rec->last_event_ts) {
        elapsed = rec->last_event_ts;
    }
    rec->last_event_ts = elapsed;
    
    /* Escape JSON */
    char *escaped = malloc(len * 6 + 1);  // Worst case: all chars need escaping
    if (!escaped) return -1;
    
    json_escape_len(data, len, escaped, len * 6 + 1);
    
    /* Write event: [time, "o", "data"] */
    fprintf(rec->file, "[%.3f, \"o\", \"%s\"]\n", elapsed, escaped);
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
    double prev_ts = 0.0;

    if (speed <= 0.0) {
        speed = 1.0;
    }

    if (speed > 50.0) {
        speed = 50.0;
    }
    
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
                for (size_t i = 0; data[i]; i++) {
                    if (data[i] == '\\' && data[i+1]) {
                        i++;
                        switch (data[i]) {
                            case 'n': putchar('\n'); break;
                            case 'r': putchar('\r'); break;
                            case 't': putchar('\t'); break;
                            case '\\': putchar('\\'); break;
                            case '"': putchar('"'); break;
                            case 'u': {
                                /* Basic \uXXXX (ASCII only) */
                                if (data[i+1] && data[i+2] && data[i+3] && data[i+4]) {
                                    unsigned int code = 0;
                                    if (sscanf(&data[i+1], "%4x", &code) == 1) {
                                        if (code <= 0x7f) {
                                            putchar((int)code);
                                        } else {
                                            putchar('?');
                                        }
                                    }
                                    i += 4;
                                }
                                break;
                            }
                            default: putchar(data[i]); break;
                        }
                    } else {
                        putchar(data[i]);
                    }
                }
                fflush(stdout);
                
                /* Sleep based on delta between events */
                if (timestamp >= prev_ts) {
                    double delta = timestamp - prev_ts;
                    if (delta > 0) {
                        usleep((useconds_t)((delta * 1000000.0) / speed));
                    }
                }
                prev_ts = timestamp;
            }
        }
    }
    
    fclose(f);
    return 0;
}

bool recording_is_active(const recording_t *rec) {
    return rec->active;
}
