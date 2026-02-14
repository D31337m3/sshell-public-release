# SShell C Implementation Makefile - Enhanced Version

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11 -D_GNU_SOURCE
LDFLAGS = -lutil -ljson-c -lpthread -lwebsockets -lmicrohttpd -lssl -lcrypto
PREFIX = /usr/local

# Source directories
SRC_DIR = c-src
COMMON_SRC = $(SRC_DIR)/common
DAEMON_SRC = $(SRC_DIR)/daemon
CLIENT_SRC = $(SRC_DIR)/client

# Build directory
BUILD_DIR = build

# Common objects
COMMON_OBJS = $(BUILD_DIR)/session.o $(BUILD_DIR)/protocol.o \
              $(BUILD_DIR)/config.o $(BUILD_DIR)/terminal.o \
              $(BUILD_DIR)/logger.o $(BUILD_DIR)/network_roaming.o \
              $(BUILD_DIR)/recording.o $(BUILD_DIR)/multiuser.o \
              $(BUILD_DIR)/webserver.o $(BUILD_DIR)/metamask_auth.o

# Daemon objects
DAEMON_OBJS = $(BUILD_DIR)/daemon_enhanced.o $(BUILD_DIR)/pty_manager.o $(COMMON_OBJS)
DAEMON_PHASE5_OBJS = $(BUILD_DIR)/daemon_phase5.o $(BUILD_DIR)/pty_manager.o $(COMMON_OBJS)

# Client objects
CLIENT_OBJS = $(BUILD_DIR)/client_enhanced.o $(COMMON_OBJS)

# Targets
DAEMON_BIN = $(BUILD_DIR)/sshell-daemon
DAEMON_PHASE5_BIN = $(BUILD_DIR)/sshell-daemon-phase5
CLIENT_BIN = $(BUILD_DIR)/sshell

.PHONY: all clean install test strip phase5

all: $(BUILD_DIR) $(DAEMON_BIN) $(CLIENT_BIN)

phase5: $(BUILD_DIR) $(DAEMON_PHASE5_BIN) $(CLIENT_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Common objects
$(BUILD_DIR)/session.o: $(COMMON_SRC)/session.c $(COMMON_SRC)/session.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/protocol.o: $(COMMON_SRC)/protocol.c $(COMMON_SRC)/protocol.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/config.o: $(COMMON_SRC)/config.c $(COMMON_SRC)/config.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/terminal.o: $(COMMON_SRC)/terminal.c $(COMMON_SRC)/terminal.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/logger.o: $(COMMON_SRC)/logger.c $(COMMON_SRC)/logger.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/network_roaming.o: $(COMMON_SRC)/network_roaming.c $(COMMON_SRC)/network_roaming.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/recording.o: $(COMMON_SRC)/recording.c $(COMMON_SRC)/recording.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/multiuser.o: $(COMMON_SRC)/multiuser.c $(COMMON_SRC)/multiuser.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/webserver.o: $(COMMON_SRC)/webserver.c $(COMMON_SRC)/webserver.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/metamask_auth.o: $(COMMON_SRC)/metamask_auth.c $(COMMON_SRC)/metamask_auth.h
	$(CC) $(CFLAGS) -c $< -o $@

# Daemon objects
$(BUILD_DIR)/daemon_enhanced.o: $(DAEMON_SRC)/daemon_enhanced.c $(DAEMON_SRC)/daemon.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/daemon_phase5.o: $(DAEMON_SRC)/daemon_phase5.c $(DAEMON_SRC)/daemon.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/pty_manager.o: $(DAEMON_SRC)/pty_manager.c $(DAEMON_SRC)/pty_manager.h
	$(CC) $(CFLAGS) -c $< -o $@

# Client objects
$(BUILD_DIR)/client_enhanced.o: $(CLIENT_SRC)/client_enhanced.c
	$(CC) $(CFLAGS) -c $< -o $@

# Binaries
$(DAEMON_BIN): $(DAEMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(DAEMON_PHASE5_BIN): $(DAEMON_PHASE5_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(CLIENT_BIN): $(CLIENT_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

strip: all
	strip $(DAEMON_BIN) $(CLIENT_BIN)

clean:
	rm -rf $(BUILD_DIR)

install: all strip
	install -D -m 755 $(DAEMON_BIN) $(PREFIX)/bin/sshell-daemon-c
	install -D -m 755 $(CLIENT_BIN) $(PREFIX)/bin/sshell-c
	install -D -m 644 man/sshell.1 $(PREFIX)/share/man/man1/sshell.1
	install -D -m 644 man/sshell-daemon.8 $(PREFIX)/share/man/man8/sshell-daemon.8
	@echo ""
	@echo "==================================================================="
	@echo "SShell (Enhanced C Version) installed successfully!"
	@echo "==================================================================="
	@echo "Binaries:"
	@echo "  $(PREFIX)/bin/sshell-c          (client)"
	@echo "  $(PREFIX)/bin/sshell-daemon-c   (daemon)"
	@echo ""
	@echo "Usage:"
	@echo "  sshell-c                # Create and attach to new session"
	@echo "  sshell-c new my-task    # Create named session"
	@echo "  sshell-c list           # List sessions"
	@echo "  sshell-c attach my-task # Attach to session"
	@echo ""
	@echo "Detach: Press Ctrl+B then 'd'"
	@echo "==================================================================="

test: all
	@echo "Running basic tests..."
	@./$(DAEMON_BIN) --version
	@./$(CLIENT_BIN) --version

.DEFAULT_GOAL := all
