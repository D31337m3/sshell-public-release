/*
 * client.c - SShell client implementation (simplified)
 */

#include "../common/config.h"
#include "../common/protocol.h"
#include "../common/session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

static int connect_daemon(void) {
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_config.socket_path, sizeof(addr.sun_path) - 1);
    
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

static void cmd_new(const char *name) {
    int sockfd = connect_daemon();
    if (sockfd < 0) {
        fprintf(stderr, "Error: Cannot connect to daemon. Start it with 'sshell-daemon-c'\n");
        exit(1);
    }
    
    message_t msg = {0};
    msg.command = CMD_CREATE;
    if (name) {
        strncpy(msg.session_name, name, sizeof(msg.session_name) - 1);
    }
    msg.no_attach = true;
    
    if (send_message(sockfd, &msg) < 0) {
        perror("send_message");
        close(sockfd);
        exit(1);
    }
    
    response_t resp;
    if (recv_response(sockfd, &resp) < 0) {
        perror("recv_response");
        close(sockfd);
        exit(1);
    }
    
    if (resp.status == STATUS_OK) {
        printf("%s\n", resp.message);
    } else {
        fprintf(stderr, "Error: %s\n", resp.message);
        exit(1);
    }
    
    close(sockfd);
}

static void cmd_list(void) {
    int sockfd = connect_daemon();
    if (sockfd < 0) {
        fprintf(stderr, "Error: Cannot connect to daemon\n");
        exit(1);
    }
    
    message_t msg = {0};
    msg.command = CMD_LIST;
    
    if (send_message(sockfd, &msg) < 0) {
        perror("send_message");
        close(sockfd);
        exit(1);
    }
    
    response_t resp;
    if (recv_response(sockfd, &resp) < 0) {
        perror("recv_response");
        close(sockfd);
        exit(1);
    }
    
    printf("%-10s %-20s %-10s %-8s %s\n", "ID", "Name", "Status", "PID", "Created");
    printf("----------------------------------------------------------------------\n");
    
    /* Read session JSON strings */
    for (int i = 0; i < 100; i++) {  /* Max sessions */
        uint32_t len;
        if (read(sockfd, &len, sizeof(len)) != sizeof(len)) break;
        
        char *json = malloc(len);
        if (!json) break;
        
        if (read(sockfd, json, len) != (ssize_t)len) {
            free(json);
            break;
        }
        
        session_t *session = session_from_json(json);
        free(json);
        
        if (session) {
            const char *status_str = "unknown";
            switch (session->status) {
                case SESSION_STATUS_CREATED: status_str = "created"; break;
                case SESSION_STATUS_RUNNING: status_str = "running"; break;
                case SESSION_STATUS_ATTACHED: status_str = "attached"; break;
                case SESSION_STATUS_DEAD: status_str = "dead"; break;
            }
            
            char created[32];
            strftime(created, sizeof(created), "%Y-%m-%d %H:%M:%S", localtime(&session->created));
            
            printf("%-10s %-20s %-10s %-8d %s\n",
                   session->id, session->name, status_str, session->pid, created);
            
            session_free(session);
        }
    }
    
    close(sockfd);
}

static void print_usage(void) {
    printf("Usage: sshell-c [COMMAND] [OPTIONS]\n\n");
    printf("Commands:\n");
    printf("  new [NAME]       Create a new session\n");
    printf("  list             List all sessions\n");
    printf("  --version        Show version\n");
    printf("  --help           Show this help\n");
}

int main(int argc, char **argv) {
    srand(time(NULL));
    config_init();
    
    if (argc < 2) {
        print_usage();
        return 1;
    }
    
    const char *command = argv[1];
    
    if (strcmp(command, "new") == 0) {
        const char *name = (argc > 2) ? argv[2] : NULL;
        cmd_new(name);
    } else if (strcmp(command, "list") == 0 || strcmp(command, "ls") == 0) {
        cmd_list();
    } else if (strcmp(command, "--version") == 0) {
        printf("SShell C version 1.0\n");
        return 0;
    } else if (strcmp(command, "--help") == 0) {
        print_usage();
        return 0;
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage();
        return 1;
    }
    
    return 0;
}
