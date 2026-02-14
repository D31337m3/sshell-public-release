/*
 * sshell-player - tiny asciicast v2 playback tool
 */

#include "../common/recording.h"

#include <stdio.h>
#include <stdlib.h>

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s RECORDING.cast [SPEED]\n", prog);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *path = argv[1];
    double speed = 1.0;
    if (argc >= 3) {
        speed = atof(argv[2]);
        if (speed <= 0.0) {
            speed = 1.0;
        }
    }

    if (recording_playback(path, speed) < 0) {
        return 1;
    }

    return 0;
}
