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
| `DATA_DIR` | `/data` | Where the SQLite database and secret key live |

All state lives in the `/data` volume (`relay-data` in docker-compose), so the container itself is disposable.

## Deployment notes

- Run it **behind a reverse proxy with TLS** (Caddy, nginx, Traefik). The app speaks plain HTTP on port 8080; login credentials should never travel unencrypted.
- If you serve it over HTTPS, consider adding `SESSION_COOKIE_SECURE=True` to `app.config` in `app.py`.
- Don't expose it directly to the internet unless you have to — a VPN or IP allowlist is a good fit for an internal admin tool.
- Back up the `relay-data` volume; it contains the accounts, webhook URLs, and audit log.

## Project layout

```
app.py               Flask app: auth, admin, sending, audit
templates/           Jinja2 pages (compose, login, admin screens)
static/style.css     UI styling
static/preview.js    Client-side Discord markdown preview
Dockerfile           Python 3.12 slim + gunicorn
docker-compose.yml   One-service stack with a data volume
```
