#!/bin/bash
# SShell Interactive Installer

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
if [ -t 1 ] || [ -e /dev/tty ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'
    NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi

# ── Banner ────────────────────────────────────────────────────────────────────
print_banner() {
    echo
    echo -e "${CYAN}${BOLD}"
    cat << 'BANNER'
  ██████  ██████  ██   ██ ███████ ██      ██
 ██      ██      ██   ██ ██      ██      ██
  █████   █████  ███████ █████   ██      ██
      ██ ██      ██   ██ ██      ██      ██
 ██████   ██████ ██   ██ ███████ ███████ ███████
BANNER
    echo -e "${NC}"
    echo -e " ${BOLD}SShell v${CLIENT_VERSION}${NC}  —  Next-Generation Terminal Multiplexer"
    echo -e " ${DIM}https://github.com/d31337m3/sshell${NC}"
    echo
    echo -e " ${CYAN}●${NC} Persistent sessions that survive disconnects"
    echo -e " ${CYAN}●${NC} Network roaming — reconnect from any machine"
    echo -e " ${CYAN}●${NC} Session recording & playback (asciicast v2)"
    echo -e " ${CYAN}●${NC} Multi-user sharing with access tokens"
    echo -e " ${CYAN}●${NC} Web terminal with MetaMask / wallet auth"
    echo
}

# ── Prompt helpers ────────────────────────────────────────────────────────────
# Always read from /dev/tty so curl | bash works correctly
_tty() {
    if [ -e /dev/tty ]; then cat /dev/tty; else cat; fi
}
ask() {
    # ask "Question" [default]
    local prompt="$1" default="${2:-}"
    local hint=""
    [ -n "$default" ] && hint=" ${DIM}[$default]${NC}"
    printf "${BOLD}%s${NC}%b " "$prompt" "$hint" >/dev/tty
    local answer
    answer=$(head -n1 </dev/tty 2>/dev/null || echo "$default")
    answer="${answer:-$default}"
    printf '%s' "$answer"
}
ask_yn() {
    # ask_yn "Question" [Y|N]  →  returns 0=yes 1=no
    local prompt="$1" default="${2:-Y}"
    local hint
    if [ "$default" = "Y" ]; then hint="${BOLD}Y${NC}/n"; else hint="y/${BOLD}N${NC}"; fi
    printf "${BOLD}%s${NC} ${DIM}[${NC}%b${DIM}]${NC} " "$prompt" "$hint" >/dev/tty
    local answer
    answer=$(head -n1 </dev/tty 2>/dev/null || echo "$default")
    answer="${answer:-$default}"
    case "${answer,,}" in y|yes) return 0;; *) return 1;; esac
}
section() {
    echo
    echo -e "${BLUE}${BOLD}── $1 ${NC}${DIM}$(printf '─%.0s' {1..50})${NC}"
    echo
}
ok()   { echo -e " ${GREEN}✔${NC}  $*"; }
warn() { echo -e " ${YELLOW}⚠${NC}  $*"; }
err()  { echo -e " ${RED}✖${NC}  $*" >&2; }

# This installer installs Linux binaries. If invoked from Windows Git-Bash/MSYS/Cygwin,
# automatically re-run it inside WSL2 so the install actually works.
is_windows_posix_shell() {
    case "$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]')" in
        mingw*|msys*|cygwin*) return 0 ;;
        *) return 1 ;;
    esac
}

to_wsl_path() {
    # Best-effort conversion for paths coming from Git-Bash/MSYS/Cygwin.
    # Examples:
    #   /f/sshell -> /mnt/f/sshell
    #   F:\sshell -> /mnt/f/sshell
    local p="$1"
    if command -v cygpath >/dev/null 2>&1; then
        # cygpath -u turns C:\x into /c/x and keeps /c/x as /c/x
        p="$(cygpath -u "$p" 2>/dev/null || echo "$p")"
    fi
    # Convert /c/... -> /mnt/c/...
    if [[ "$p" =~ ^/([a-zA-Z])/(.*)$ ]]; then
        local drive="${BASH_REMATCH[1],,}"
        local rest="${BASH_REMATCH[2]}"
        printf '/mnt/%s/%s' "$drive" "$rest"
        return 0
    fi
    # Convert C:\... -> /mnt/c/...
    if [[ "$p" =~ ^([a-zA-Z]):\\(.*)$ ]]; then
        local drive="${BASH_REMATCH[1],,}"
        local rest="${BASH_REMATCH[2]}"
        rest="${rest//\\//}"
        printf '/mnt/%s/%s' "$drive" "$rest"
        return 0
    fi
    printf '%s' "$p"
}

forward_to_wsl_if_needed() {
    if ! is_windows_posix_shell; then
        return 0
    fi

    if ! command -v wsl.exe >/dev/null 2>&1 && ! command -v wsl >/dev/null 2>&1; then
        echo "Error: detected Windows shell (MSYS/MINGW/Cygwin) but WSL is not available." >&2
        echo "Install WSL2 then re-run (PowerShell): wsl --install" >&2
        exit 1
    fi

    local wsl_bin
    wsl_bin="$(command -v wsl.exe 2>/dev/null || command -v wsl)"

    # Re-run this same script inside WSL, translating any -e/--from-dir path argument.
    local script_abs
    script_abs="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")"
    local wsl_script
    wsl_script="$(to_wsl_path "$script_abs")"

    local -a args
    args=("$wsl_script")
    while [ "$#" -gt 0 ]; do
        local a="$1"
        shift || true
        case "$a" in
            -e|--from-dir|--extract-dir)
                if [ "$#" -gt 0 ]; then
                    local p="$1"
                    shift || true
                    args+=("$a" "$(to_wsl_path "$p")")
                else
                    args+=("$a")
                fi
                ;;
            *)
                args+=("$a")
                ;;
        esac
    done

    local cmd_q=""
    local part
    for part in "${args[@]}"; do
        cmd_q+=" $(printf '%q' "$part")"
    done
    cmd_q="${cmd_q# }"

    echo "Detected Windows shell; re-running installer inside WSL2..." >&2
    exec "$wsl_bin" -e bash -lc "set -euo pipefail; $cmd_q"
}

forward_to_wsl_if_needed "$@"

CLIENT_VERSION="1.6.3"
DAEMON_VERSION="1.6.2"

# ── Release URL overrides ─────────────────────────────────────────────────────
SSHELL_REPO_DEFAULT="d31337m3/sshell-public-release"
SSHELL_TAG_DEFAULT="v${CLIENT_VERSION}"
SSHELL_ASSET_DEFAULT="sshell_release_x64_client-${CLIENT_VERSION}_daemon-${DAEMON_VERSION}.zip"
REPO="${SSHELL_REPO:-$SSHELL_REPO_DEFAULT}"
TAG="${SSHELL_TAG:-$SSHELL_TAG_DEFAULT}"
ASSET="${SSHELL_ASSET:-$SSHELL_ASSET_DEFAULT}"
RELEASE_URL="${SSHELL_RELEASE_URL:-https://github.com/${REPO}/releases/download/${TAG}/${ASSET}}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# ── CLI flags (non-interactive overrides) ─────────────────────────────────────
WITH_DAEMON=0
ENABLE_DAEMON=0
WRITE_DAEMON_CONFIG=1
LOCAL_SRC_DIR=""
YES_MODE=0       # -y / --yes: skip all prompts, accept defaults

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -y, --yes          Non-interactive: accept all defaults"
    echo "  --daemon           Install sshell-daemon (skips prompt)"
    echo "  --enable-daemon    Install daemon + enable systemd autostart"
    echo "  --no-config        Do not write ~/.sshell/daemon.json"
    echo "  -e, --from-dir DIR Install from an already-extracted release directory"
    echo "  -h, --help         Show this help"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -y|--yes)        YES_MODE=1;       shift ;;
        --daemon)        WITH_DAEMON=1;    shift ;;
        --enable-daemon) WITH_DAEMON=1; ENABLE_DAEMON=1; shift ;;
        --no-config)     WRITE_DAEMON_CONFIG=0; shift ;;
        -e|--from-dir|--extract-dir)
            [ "$#" -lt 2 ] && { err "$1 requires a path"; usage >&2; exit 1; }
            LOCAL_SRC_DIR="$2"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) err "Unknown argument: $1"; usage >&2; exit 1 ;;
    esac
done

# ── Utility ───────────────────────────────────────────────────────────────────
need_cmd() { command -v "$1" >/dev/null 2>&1; }

target_home() {
    if [ "$EUID" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        getent passwd "$SUDO_USER" | cut -d: -f6; return
    fi
    echo "$HOME"
}

# ── Show banner & intro ───────────────────────────────────────────────────────
print_banner

echo -e " ${DIM}Client v${CLIENT_VERSION}  ·  Daemon v${DAEMON_VERSION}${NC}"
echo
echo -e " SShell lets you create persistent terminal sessions that survive"
echo -e " network drops and can be re-attached from any machine or network."
echo -e " The ${BOLD}daemon${NC} runs on a server; the ${BOLD}client${NC} connects from anywhere."
echo

if [ "$YES_MODE" -eq 0 ]; then
    printf "${DIM}Press Enter to begin setup, or Ctrl-C to cancel...${NC} " >/dev/tty
    head -n1 </dev/tty >/dev/null 2>&1 || true
    echo
fi

# ── Check prerequisites ───────────────────────────────────────────────────────
section "Checking prerequisites"

install_deps_apt() {
    echo "  Installing dependencies via apt..."
    apt-get update -y -qq
    apt-get install -y -qq curl unzip ca-certificates \
        libjson-c-dev libwebsockets-dev libmicrohttpd-dev libssl-dev libsecp256k1-dev
}

if ! need_cmd unzip || ! (need_cmd curl || need_cmd wget); then
    if [ "$EUID" -ne 0 ]; then
        err "Missing prerequisites (need unzip + curl/wget). Re-run with sudo to auto-install."
        exit 1
    fi
    need_cmd apt-get && { install_deps_apt; } || \
        { err "Unsupported package manager. Please install: unzip, curl, wget."; exit 1; }
fi
ok "Prerequisites satisfied"

# ── Determine install destination ─────────────────────────────────────────────
if [ "$EUID" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

# ── Interactive configuration wizard ─────────────────────────────────────────
# Collected config values (defaults shown):
CFG_MODE="tcp"
CFG_HOST="0.0.0.0"
CFG_PORT="7444"
CFG_AUTH_REQUIRED="true"
CFG_AUTH_TYPE="none"    # none | wallet | allowlist
CFG_WALLET=""
CFG_ALLOWLIST_PATH=""
CFG_WEB_ENABLED="false"
CFG_WEB_PORT="8080"
CFG_ROAMING="true"
CFG_LOG_LEVEL="info"

if [ "$YES_MODE" -eq 0 ]; then

    # ── Step 1: Install type ──────────────────────────────────────────────────
    section "Step 1 of 5  ·  Install type"
    echo -e " ${BOLD}1)${NC} Client only  ${DIM}— connect to sessions on a remote server${NC}"
    echo -e " ${BOLD}2)${NC} Client + Daemon  ${DIM}— run sessions on this machine${NC}"
    echo
    _install_type=$(ask "Your choice" "1")
    if [ "$_install_type" = "2" ]; then
        WITH_DAEMON=1
    fi

    # ── Step 2: Network (daemon only) ────────────────────────────────────────
    if [ "$WITH_DAEMON" -eq 1 ]; then
        section "Step 2 of 5  ·  Network"
        echo -e " ${BOLD}1)${NC} Local only  ${DIM}(127.0.0.1) — only connections from this machine${NC}"
        echo -e " ${BOLD}2)${NC} Remote access  ${DIM}(0.0.0.0) — accept connections from the internet${NC}"
        echo
        _net=$(ask "Your choice" "2")
        if [ "$_net" = "1" ]; then
            CFG_HOST="127.0.0.1"
        else
            CFG_HOST="0.0.0.0"
        fi

        CFG_PORT=$(ask "TCP port for daemon" "7444")
        if ! [[ "$CFG_PORT" =~ ^[0-9]+$ ]] || [ "$CFG_PORT" -lt 1 ] || [ "$CFG_PORT" -gt 65535 ]; then
            warn "Invalid port — using 7444"
            CFG_PORT="7444"
        fi
    else
        section "Step 2 of 5  ·  Network"
        echo -e " ${DIM}(Skipped — client only install, no daemon to configure)${NC}"
        echo
    fi

    # ── Step 3: Authentication ────────────────────────────────────────────────
    if [ "$WITH_DAEMON" -eq 1 ]; then
        section "Step 3 of 5  ·  Authentication"
        echo -e " Choose how clients prove their identity when connecting:"
        echo
        echo -e " ${BOLD}1)${NC} Wallet address  ${DIM}— MetaMask / Ethereum wallet signature${NC}"
        echo -e " ${BOLD}2)${NC} Allowlist file  ${DIM}— plain text file of wallet addresses, one per line${NC}"
        echo -e " ${BOLD}3)${NC} No auth  ${DIM}— ${RED}insecure${NC}${DIM}, suitable for localhost-only or trusted LANs${NC}"
        echo
        _auth=$(ask "Your choice" "1")

        case "$_auth" in
            1)
                CFG_AUTH_TYPE="wallet"
                CFG_AUTH_REQUIRED="true"
                echo
                echo -e " ${DIM}Your Ethereum wallet address (0x…) will be the only address allowed to connect.${NC}"
                echo -e " ${DIM}The client signs a challenge message with MetaMask or a local key.${NC}"
                echo
                CFG_WALLET=$(ask "Wallet address (0x…)" "")
                if [ -z "$CFG_WALLET" ]; then
                    warn "No wallet entered — auth_required left true but no wallet filter set."
                    warn "Edit ~/.sshell/daemon.json before starting the daemon."
                    CFG_AUTH_TYPE="none_configured"
                fi
                ;;
            2)
                CFG_AUTH_TYPE="allowlist"
                CFG_AUTH_REQUIRED="true"
                echo
                CFG_ALLOWLIST_PATH=$(ask "Path to wallet allowlist file" "$HOME/.sshell/allowed_wallets.txt")
                if [ ! -f "$CFG_ALLOWLIST_PATH" ]; then
                    warn "File does not exist yet — it will be created empty at: $CFG_ALLOWLIST_PATH"
                    mkdir -p "$(dirname "$CFG_ALLOWLIST_PATH")"
                    touch "$CFG_ALLOWLIST_PATH"
                    chmod 600 "$CFG_ALLOWLIST_PATH"
                    echo "  Add one wallet address per line, e.g.:"
                    echo "    0xYourAddress"
                fi
                ;;
            3)
                CFG_AUTH_TYPE="none"
                CFG_AUTH_REQUIRED="false"
                warn "No authentication — only use this on localhost or a fully trusted network."
                ;;
        esac
    else
        section "Step 3 of 5  ·  Authentication"
        echo -e " ${DIM}(Skipped — configure auth when you set up a remote daemon)${NC}"
        echo
    fi

    # ── Step 4: Optional features ─────────────────────────────────────────────
    if [ "$WITH_DAEMON" -eq 1 ]; then
        section "Step 4 of 5  ·  Optional features"

        echo -e " ${BOLD}Web terminal${NC}  ${DIM}— access sessions from a browser over WebSocket${NC}"
        if ask_yn "Enable web terminal?" "N"; then
            CFG_WEB_ENABLED="true"
            CFG_WEB_PORT=$(ask "  Web terminal port" "8080")
        fi
        echo

        echo -e " ${BOLD}Network roaming${NC}  ${DIM}— UDP heartbeat lets clients reconnect after network changes${NC}"
        if ask_yn "Enable network roaming (recommended)?" "Y"; then
            CFG_ROAMING="true"
        else
            CFG_ROAMING="false"
        fi
        echo

        echo -e " ${BOLD}Autostart${NC}  ${DIM}— start daemon automatically on login via systemd user service${NC}"
        if need_cmd systemctl; then
            if ask_yn "Enable autostart (systemd)?" "Y"; then
                ENABLE_DAEMON=1
            fi
        else
            echo -e " ${DIM}  systemctl not found — skipping autostart option${NC}"
        fi
    else
        section "Step 4 of 5  ·  Optional features"
        echo -e " ${DIM}(Skipped — no daemon)${NC}"
        echo
    fi

    # ── Step 5: Summary & confirm ─────────────────────────────────────────────
    section "Step 5 of 5  ·  Summary"

    echo -e " ${BOLD}Install directory:${NC}  $INSTALL_DIR"
    echo -e " ${BOLD}Binaries:${NC}"
    echo -e "   sshell, sshell-player"
    if [ "$WITH_DAEMON" -eq 1 ]; then
        echo -e "   sshell-daemon"
    fi

    if [ "$WITH_DAEMON" -eq 1 ]; then
        echo
        echo -e " ${BOLD}Daemon config:${NC}  ~/.sshell/daemon.json"
        echo -e "   mode       = tcp"
        echo -e "   host       = $CFG_HOST"
        echo -e "   port       = $CFG_PORT"
        echo -e "   auth       = $CFG_AUTH_REQUIRED"
        case "$CFG_AUTH_TYPE" in
            wallet)       echo -e "   wallet     = $CFG_WALLET" ;;
            allowlist)    echo -e "   allowlist  = $CFG_ALLOWLIST_PATH" ;;
            none)         echo -e "   ${RED}auth disabled${NC}" ;;
        esac
        echo -e "   web        = $CFG_WEB_ENABLED$([ "$CFG_WEB_ENABLED" = "true" ] && echo " (port $CFG_WEB_PORT)" || true)"
        echo -e "   roaming    = $CFG_ROAMING"
        echo -e "   autostart  = $([ "$ENABLE_DAEMON" -eq 1 ] && echo "yes (systemd)" || echo "no")"
    fi

    echo
    if ! ask_yn "Proceed with installation?" "Y"; then
        echo
        echo -e " ${YELLOW}Installation cancelled.${NC}"
        exit 0
    fi

else
    # Non-interactive: apply CLI flag defaults
    section "Non-interactive install"
    echo -e " Using defaults (pass flags to override — see --help)"
    echo -e " Install dir: ${BOLD}$INSTALL_DIR${NC}"
    [ "$WITH_DAEMON" -eq 1 ] && echo -e " Including: ${BOLD}sshell-daemon${NC}"
    echo
fi

# ── Write daemon.json ─────────────────────────────────────────────────────────
write_daemon_json() {
    [ "$WRITE_DAEMON_CONFIG" -ne 1 ] && return 0
    [ "$WITH_DAEMON" -ne 1 ] && return 0

    local home; home="$(target_home)"
    [ -z "$home" ] && return 0

    local cfg_dir="$home/.sshell"
    local cfg_file="$cfg_dir/daemon.json"
    mkdir -p "$cfg_dir"

    if [ -f "$cfg_file" ]; then
        warn "Existing config found — leaving unchanged: $cfg_file"
        return 0
    fi

    # Build JSON
    local wallet_line="" allowlist_line=""
    [ "$CFG_AUTH_TYPE" = "wallet" ] && [ -n "$CFG_WALLET" ] && \
        wallet_line="    \"wallet\": \"${CFG_WALLET}\","
    [ "$CFG_AUTH_TYPE" = "allowlist" ] && [ -n "$CFG_ALLOWLIST_PATH" ] && \
        allowlist_line="    \"wallet_allowlist\": \"${CFG_ALLOWLIST_PATH}\","

    cat > "$cfg_file" << JSON
{
    "mode": "tcp",
    "host": "${CFG_HOST}",
    "port": ${CFG_PORT},
    "auth_required": ${CFG_AUTH_REQUIRED},
${wallet_line:+$wallet_line$'\n'}${allowlist_line:+$allowlist_line$'\n'}    "web_enabled": ${CFG_WEB_ENABLED},
    "web_port": ${CFG_WEB_PORT},
    "roaming": ${CFG_ROAMING},
    "ufw_auto": true,
    "log_level": "${CFG_LOG_LEVEL}"
}
JSON

    chmod 600 "$cfg_file"
    ok "Wrote daemon config: $cfg_file"
}

# ── Install binaries ──────────────────────────────────────────────────────────
install_from_dir() {
    local src_dir="$1"
    [ -z "$src_dir" ] || [ ! -d "$src_dir" ] && { err "Source directory not found: $src_dir"; exit 1; }
    [ ! -f "$src_dir/sshell" ] && { err "$src_dir does not contain sshell"; exit 1; }

    chmod +x "$src_dir/sshell" || true
    cp -f "$src_dir/sshell" "$INSTALL_DIR/"
    ok "Installed: sshell"

    if [ -f "$src_dir/sshell-player" ]; then
        chmod +x "$src_dir/sshell-player" || true
        cp -f "$src_dir/sshell-player" "$INSTALL_DIR/"
        ok "Installed: sshell-player"
    fi

    if [ "$WITH_DAEMON" -eq 1 ]; then
        [ ! -f "$src_dir/sshell-daemon" ] && { err "$src_dir does not contain sshell-daemon"; exit 1; }
        chmod +x "$src_dir/sshell-daemon" || true
        cp -f "$src_dir/sshell-daemon" "$INSTALL_DIR/"
        ok "Installed: sshell-daemon"
    fi
}

section "Installing"

# Auto-detect local bundle (install.sh alongside binaries)
[ -z "$LOCAL_SRC_DIR" ] && [ -f "$SCRIPT_DIR/sshell" ] && LOCAL_SRC_DIR="$SCRIPT_DIR"

TMP_DIR=""
if [ -n "$LOCAL_SRC_DIR" ]; then
    echo " Installing from local directory: $LOCAL_SRC_DIR"
    install_from_dir "$LOCAL_SRC_DIR"
else
    echo " Downloading release asset..."
    TMP_DIR=$(mktemp -d)
    cd "$TMP_DIR"

    if need_cmd curl; then
        curl -fL --progress-bar -o sshell.zip "$RELEASE_URL"
    elif need_cmd wget; then
        wget -q --show-progress -O sshell.zip "$RELEASE_URL"
    else
        err "Neither curl nor wget found."
        exit 1
    fi

    echo " Extracting..."
    if ! unzip -q sshell.zip; then
        err "Failed to unzip. Check URL: $RELEASE_URL"
        exit 1
    fi

    chmod +x sshell
    mv sshell "$INSTALL_DIR/"
    ok "Installed: sshell"

    if [ -f sshell-player ]; then
        chmod +x sshell-player
        mv sshell-player "$INSTALL_DIR/"
        ok "Installed: sshell-player"
    fi

    if [ "$WITH_DAEMON" -eq 1 ]; then
        [ ! -f sshell-daemon ] && { err "Release archive did not contain sshell-daemon"; exit 1; }
        chmod +x sshell-daemon
        mv sshell-daemon "$INSTALL_DIR/"
        ok "Installed: sshell-daemon"
    fi
fi

write_daemon_json

# ── Systemd autostart ─────────────────────────────────────────────────────────
if [ "$WITH_DAEMON" -eq 1 ] && [ "$ENABLE_DAEMON" -eq 1 ]; then
    echo
    if ! need_cmd systemctl; then
        warn "systemctl not found — skipping autostart"
    else
        user_home="$(target_home)"
        if [ -n "$user_home" ]; then
            service_dir="$user_home/.config/systemd/user"
            mkdir -p "$service_dir"
            cat > "$service_dir/sshell.service" << EOF
[Unit]
Description=SShell Persistent Session Daemon
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/sshell-daemon --no-fork
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=default.target
EOF
            if [ "$EUID" -eq 0 ]; then
                ok "Systemd service written: $service_dir/sshell.service"
                echo "   Run as your normal user to activate:"
                echo "   ${BOLD}systemctl --user daemon-reload && systemctl --user enable --now sshell${NC}"
            else
                systemctl --user daemon-reload 2>/dev/null || true
                systemctl --user enable --now sshell 2>/dev/null || \
                    warn "Could not enable service — run: systemctl --user enable --now sshell"
                ok "Autostart enabled (systemd user service)"
            fi
        fi
    fi
fi

# ── Cleanup ───────────────────────────────────────────────────────────────────
if [ -n "$TMP_DIR" ]; then
    cd /
    rm -rf "$TMP_DIR"
fi

# ── PATH reminder ─────────────────────────────────────────────────────────────
path_reminder() {
    case ":${PATH}:" in
        *":${INSTALL_DIR}:"*) return 0 ;;
    esac
    echo
    warn "$INSTALL_DIR is not in your PATH."
    echo "   Add this to ~/.bashrc or ~/.zshrc:"
    echo -e "   ${BOLD}export PATH=\"\$PATH:${INSTALL_DIR}\"${NC}"
}

# ── Done ──────────────────────────────────────────────────────────────────────
echo
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ✔  Installation complete!${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════${NC}"
echo
echo -e " Installed to: ${BOLD}$INSTALL_DIR${NC}"
echo
echo -e " ${BOLD}Quick start:${NC}"
if [ "$WITH_DAEMON" -eq 1 ]; then
    echo -e "   ${CYAN}sshell-daemon --no-fork${NC}   # start the daemon"
    echo -e "   ${CYAN}sshell new mysession${NC}      # create a new session"
    echo -e "   ${CYAN}sshell list${NC}               # list all sessions"
    echo -e "   ${CYAN}sshell attach mysession${NC}   # re-attach to a session"
    echo -e "   ${CYAN}sshell kill mysession${NC}     # kill a session"
else
    echo -e "   ${CYAN}sshell SESSION@HOST[:PORT]${NC}  # connect to a remote session"
    echo -e "   ${CYAN}sshell list --host HOST${NC}     # list remote sessions"
fi
echo -e "   ${CYAN}sshell rec-start NAME${NC}     # start recording"
echo -e "   ${CYAN}sshell-player FILE.cast${NC}   # replay a recording"
echo
echo -e " ${DIM}Docs: https://github.com/d31337m3/sshell${NC}"
echo

path_reminder
