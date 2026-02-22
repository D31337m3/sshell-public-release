# Security Notes (SShell)

## Recommended defaults (TCP mode)

If you expose the daemon over TCP, treat it like a remote-admin interface.

- Prefer **authentication enabled** (`auth_required: true`).
- Prefer **explicit allowlists** (wallet allowlist or single wallet) before binding to non-local addresses.
- Prefer binding to **localhost** unless you specifically need remote access.
- Use your firewall to restrict access to trusted source IP ranges.

## Daemon preset config

The daemon loads `~/.sshell/daemon.json` **only if it exists**. CLI flags override presets.

Example secure starter config (safe-by-default):
```json
{
  "mode": "tcp",
  "host": "0.0.0.0",
  "port": 7444,
  "auth_required": true,
  "wallet": "0x...",
  "wallet_allowlist": "~/.sshell/allowed_wallets.txt",
  "web_enabled": false,
  "web_port": 8080,
  "roaming": true,
  "ufw_auto": true,
  "log_level": "info"
}
```

Notes:
- `wallet` and `wallet_allowlist` are mutually exclusive — configure one or the other, not both.
- With `auth_required: true` and **no allowlists configured**, the daemon will reject remote requests. Localhost may still be allowed.
- To actually allow remote access, configure either:
  - `wallet` (single wallet gate), or
  - `wallet_allowlist` path (one wallet address per line), or
  - `ssh_allowlist` path (one identity string per line).
- The interactive installer (`install.sh`) guides you through auth configuration in its wizard (Step 3). Use `-y` / `--yes` to skip the wizard and accept safe defaults.

## Wallet authentication

- Wallet auth is designed to gate access in TCP mode.
- Keep signed messages short-lived (include time/host/operation) and do not reuse signatures.

## Multi-user sharing tokens

- Share tokens grant guest access to an active session on the daemon.
- Send tokens over a secure channel (encrypted messaging). Consider tokens as secrets.
- The inviter can revoke access with `sshell --stopshare`.

## Logs and recordings

- Logs: `~/.sshell/daemon.log` (by default).
- Recordings: `~/.sshell/recordings/*.cast`.
- Both should be treated as sensitive; they may contain commands, output, and secrets.
