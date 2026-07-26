# Relay

A small self-hosted gateway that lets trusted users post to Discord channels through webhooks — without revealing who pressed send. Messages arrive under the webhook's own name and avatar; the webhook URLs themselves are only ever visible to admins.

## Features

- **Authenticated logon** — session-based login, hashed passwords, per-user accounts.
- **Admin-managed webhooks** — register any number of Discord webhooks by name; users only ever see the friendly name, never the URL.
- **Per-user access control** — a checkbox matrix on the Access page controls which accounts can post to which webhooks. Admins can post to all of them.
- **Live Discord-style preview** — the compose page renders your message (bold, italic, code blocks, quotes, headings, spoilers, lists) exactly as it will appear in Discord before you send it.
- **Send log** — admin-only audit trail of who sent what, where, and whether Discord accepted it. Discord itself never learns the poster's identity.
- **Safety rails** — CSRF protection on every form, webhook URL format validation, `@everyone`/role mentions stripped from outgoing messages, 2000-character limit enforced.

## Quick start

```bash
# 1. Set the initial admin password (otherwise one is generated
#    and printed once in the container logs)
export ADMIN_PASSWORD='choose-something-strong'

# 2. Build and run
docker compose up -d --build

# 3. Open http://localhost:8080 and sign in as 'admin'
```

Then, as admin:

1. **Webhooks** → add a webhook. In Discord: *channel settings → Integrations → Webhooks → Copy URL*. Give it a friendly name like `#announcements` — that's all users will see. Use **Test** to confirm it's live.
2. **Accounts** → create an account for each person who should be able to post.
3. **Access** → tick which webhooks each account may use, and save.

Users sign in, pick a destination, write their message with a live preview, and send.

## Configuration

| Environment variable | Default | Purpose |
|---|---|---|
| `ADMIN_PASSWORD` | random (printed once in logs) | Password for the bootstrap admin account, first run only |
| `ADMIN_USERNAME` | `admin` | Username for the bootstrap admin account, first run only |
| `SECRET_KEY` | auto-generated, persisted in `/data` | Flask session signing key |
| `RELAY_PROXY_HOPS` | `0` | Reverse proxies to trust for real client IPs (`1` behind NPM/Caddy) |
| `RELAY_HTTPS` | `0` | Set `1` when served over TLS: Secure cookies + HSTS |
| `RELAY_SESSION_HOURS` | `12` | Login session lifetime |
| `RELAY_MAX_FILE_MB` | `10` | Per-file attachment limit (raise for boosted servers) |
| `DATA_DIR` | `/data` | Where the SQLite database and secret key live |

All state lives in the `/data` volume (`relay-data` in docker-compose), so the container itself is disposable.

## Security & deployment

Hardening that's built in:

- **Login rate limiting** — 5 failed attempts locks a username, 10 locks a client IP, for 15 minutes. Failures and throttles are logged to the container output. Limits are tracked in SQLite, so they hold across workers and restarts.
- **Timing-safe login** — unknown usernames take as long to reject as wrong passwords.
- **Sessions expire** after `RELAY_SESSION_HOURS` (default 12).
- **Security headers** on every response: a strict Content-Security-Policy (no inline scripts), `X-Frame-Options: DENY`, `nosniff`, referrer policy, and HSTS when `RELAY_HTTPS=1`.
- **Non-root container** — the app runs as an unprivileged user.
- CSRF protection on all forms, `@everyone`/user pings always stripped, role pings only for admin-registered roles, webhook URLs never exposed to non-admins, admin-only audit log with client IPs.

Running behind a reverse proxy (nginx proxy manager, Caddy, Traefik):

1. Set `RELAY_PROXY_HOPS=1` and `RELAY_HTTPS=1` (already set in `docker-compose.yml`). Without `RELAY_PROXY_HOPS`, rate limiting and the audit log would see the proxy's IP for everyone; leave it at `0` only if the app is exposed directly, since trusting forwarded headers from arbitrary clients would let them spoof their IP.
2. In nginx proxy manager, enable **Force SSL** and add to the proxy host's Advanced config so large attachments survive the proxy:

   ```nginx
   client_max_body_size 102m;
   ```

3. Strongly consider an **Access List** (IP allowlist or basic auth) in front. This is a tool for a handful of trusted people — reducing who can even reach the login page removes most of the risk of public exposure.

Back up the `relay-data` volume; it contains the accounts, webhook URLs, and audit log.

## Project layout

```
app.py               Flask app: auth, admin, sending, audit
templates/           Jinja2 pages (compose, login, admin screens)
static/style.css     UI styling
static/preview.js    Client-side Discord markdown preview
Dockerfile           Python 3.12 slim + gunicorn
docker-compose.yml   One-service stack with a data volume
```
