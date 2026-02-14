/*
 * recording.h - Session recording and playback (asciicast format)
 */

#ifndef SSHELL_RECORDING_H
#define SSHELL_RECORDING_H

#include <stdio.h>
#include <stdbool.h>
#include <time.h>

typedef struct {
    FILE *file;
    bool active;
    time_t start_time;
    double start_ts;
    double last_event_ts;
    int width;
    int height;
} recording_t;

/* Initialize recording */
int recording_init(recording_t *rec, const char *session_id, int width, int height);

/* Start recording */
int recording_start(recording_t *rec, const char *filepath, int width, int height);

/* Record output data */
int recording_write(recording_t *rec, const char *data, size_t len);

/* Stop recording */
int recording_stop(recording_t *rec);

/* Playback recording */
int recording_playback(const char *filepath, double speed);

/* Check if recording active */
bool recording_is_active(const recording_t *rec);

#endif /* SSHELL_RECORDING_H */
