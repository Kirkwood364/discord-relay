"""
Relay — an anonymising Discord webhook gateway.

Admins register Discord webhooks and grant users access to them.
Users compose a message, see a Discord-style preview, and send it.
The message arrives in Discord under the webhook's identity, so the
poster's own account is never exposed. Webhook URLs are never shown
to non-admin users.
"""

import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps

import requests
from flask import (
    Flask, abort, flash, g, redirect, render_template, request,
    session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "relay.db")
os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__)

# Persist the secret key so sessions survive container restarts.
_key_file = os.path.join(DATA_DIR, "secret_key")
if os.environ.get("SECRET_KEY"):
    app.secret_key = os.environ["SECRET_KEY"]
elif os.path.exists(_key_file):
    with open(_key_file) as f:
        app.secret_key = f.read().strip()
else:
    key = secrets.token_hex(32)
    with open(_key_file, "w") as f:
        f.write(key)
    os.chmod(_key_file, 0o600)
    app.secret_key = key

# Discord's default cap is 10 MB per file for non-boosted servers; raise
# RELAY_MAX_FILE_MB if your servers have boost-level upload limits.
MAX_FILE_MB = int(os.environ.get("RELAY_MAX_FILE_MB", "10"))
MAX_FILES = 10

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=(MAX_FILE_MB * MAX_FILES + 2) * 1024 * 1024,
)

DISCORD_WEBHOOK_RE = re.compile(
    r"^https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+$"
)
ROLE_MENTION_RE = re.compile(r"<@&(\d+)>")
MAX_MESSAGE_LEN = 2000


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY,
            username      TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            is_admin      INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS webhooks (
            id         INTEGER PRIMARY KEY,
            name       TEXT UNIQUE NOT NULL,
            url        TEXT NOT NULL,
            note       TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS roles (
            id         INTEGER PRIMARY KEY,
            webhook_id INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
            name       TEXT NOT NULL,
            role_id    TEXT NOT NULL,
            UNIQUE (webhook_id, role_id)
        );
        CREATE TABLE IF NOT EXISTS access (
            user_id    INTEGER NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
            webhook_id INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
            PRIMARY KEY (user_id, webhook_id)
        );
        CREATE TABLE IF NOT EXISTS audit (
            id         INTEGER PRIMARY KEY,
            user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
            username   TEXT NOT NULL,
            webhook    TEXT NOT NULL,
            excerpt    TEXT NOT NULL,
            status     TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """)
    # Bootstrap the first admin account if the user table is empty.
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        username = os.environ.get("ADMIN_USERNAME", "admin")
        password = os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(12)
        db.execute(
            "INSERT INTO users (username, password_hash, is_admin, created_at)"
            " VALUES (?, ?, 1, ?)",
            (username, generate_password_hash(password), now()),
        )
        db.commit()
        if os.environ.get("ADMIN_PASSWORD"):
            print(f"[relay] Created admin account '{username}' with password from ADMIN_PASSWORD.")
        else:
            print(f"[relay] Created admin account '{username}' with generated password: {password}")
            print("[relay] Log in and change it, or set ADMIN_PASSWORD before first run.")
    db.close()


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------------

@app.before_request
def load_user():
    g.user = None
    uid = session.get("uid")
    if uid is not None:
        g.user = get_db().execute(
            "SELECT * FROM users WHERE id = ?", (uid,)
        ).fetchone()
        if g.user is None:
            session.clear()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        if not g.user["is_admin"]:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        token = request.form.get("csrf") or request.headers.get("X-CSRF")
        if not token or token != session.get("csrf"):
            abort(400, "Invalid or missing CSRF token.")


def user_webhooks(user):
    db = get_db()
    if user["is_admin"]:
        return db.execute("SELECT * FROM webhooks ORDER BY name").fetchall()
    return db.execute(
        "SELECT w.* FROM webhooks w JOIN access a ON a.webhook_id = w.id"
        " WHERE a.user_id = ? ORDER BY w.name", (user["id"],)
    ).fetchall()


# --------------------------------------------------------------------------
# Auth routes
# --------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["uid"] = user["id"]
            session.permanent = True
            dest = request.args.get("next") or url_for("compose")
            if not dest.startswith("/"):
                dest = url_for("compose")
            return redirect(dest)
        flash("That username and password combination wasn't recognised.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        current = request.form.get("current", "")
        new = request.form.get("new", "")
        if not check_password_hash(g.user["password_hash"], current):
            flash("Current password is incorrect.", "error")
        elif len(new) < 8:
            flash("New password needs at least 8 characters.", "error")
        else:
            get_db().execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(new), g.user["id"]),
            )
            get_db().commit()
            flash("Password changed.", "ok")
            return redirect(url_for("compose"))
    return render_template("account.html")


# --------------------------------------------------------------------------
# Compose & send
# --------------------------------------------------------------------------

@app.route("/")
@login_required
def compose():
    hooks = user_webhooks(g.user)
    roles = {}
    if hooks:
        ids = tuple(w["id"] for w in hooks)
        rows = get_db().execute(
            f"SELECT * FROM roles WHERE webhook_id IN ({','.join('?' * len(ids))})"
            " ORDER BY name", ids
        ).fetchall()
        for r in rows:
            roles.setdefault(r["webhook_id"], []).append(
                {"name": r["name"], "role_id": r["role_id"]}
            )
    return render_template(
        "compose.html", webhooks=hooks, roles_json=json.dumps(roles),
        max_files=MAX_FILES, max_file_mb=MAX_FILE_MB,
    )


@app.route("/send", methods=["POST"])
@login_required
def send():
    webhook_id = request.form.get("webhook_id", "")
    content = request.form.get("content", "").strip()
    uploads = [f for f in request.files.getlist("files") if f and f.filename]

    if not content and not uploads:
        flash("The message is empty — nothing was sent.", "error")
        return redirect(url_for("compose"))
    if len(content) > MAX_MESSAGE_LEN:
        flash(f"Discord messages are limited to {MAX_MESSAGE_LEN} characters.", "error")
        return redirect(url_for("compose"))
    if len(uploads) > MAX_FILES:
        flash(f"Discord allows at most {MAX_FILES} attachments per message.", "error")
        return redirect(url_for("compose"))

    allowed = {str(w["id"]): w for w in user_webhooks(g.user)}
    hook = allowed.get(webhook_id)
    if hook is None:
        abort(403)

    # Read and size-check the attachments.
    files = []
    for i, f in enumerate(uploads):
        data = f.read()
        if len(data) > MAX_FILE_MB * 1024 * 1024:
            flash(f"{f.filename} is over the {MAX_FILE_MB} MB attachment limit.", "error")
            return redirect(url_for("compose"))
        files.append((f"files[{i}]", (f.filename, data, f.mimetype or "application/octet-stream")))

    # Only role pings the admin has registered for this webhook go through;
    # @everyone, @here, and user pings are always suppressed.
    registered = {
        r["role_id"] for r in get_db().execute(
            "SELECT role_id FROM roles WHERE webhook_id = ?", (hook["id"],)
        ).fetchall()
    }
    mentioned = [rid for rid in set(ROLE_MENTION_RE.findall(content)) if rid in registered]
    payload = {
        "content": content,
        "allowed_mentions": {"parse": [], "roles": mentioned[:100]},
    }

    try:
        if files:
            resp = requests.post(
                hook["url"],
                data={"payload_json": json.dumps(payload)},
                files=files,
                timeout=60,
            )
        else:
            resp = requests.post(hook["url"], json=payload, timeout=10)
        ok = resp.status_code in (200, 204)
        status = "sent" if ok else f"failed ({resp.status_code})"
    except requests.RequestException:
        ok, status = False, "failed (network error)"

    excerpt = content[:120]
    if files:
        excerpt = (excerpt + f" [+{len(files)} file{'s' if len(files) != 1 else ''}]").strip()
    get_db().execute(
        "INSERT INTO audit (user_id, username, webhook, excerpt, status, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (g.user["id"], g.user["username"], hook["name"], excerpt, status, now()),
    )
    get_db().commit()

    if ok:
        flash(f"Message sent to {hook['name']}.", "ok")
    else:
        flash(f"Discord rejected the message — {status}. Check the webhook still exists.", "error")
    return redirect(url_for("compose"))


# --------------------------------------------------------------------------
# Admin — webhooks
# --------------------------------------------------------------------------

@app.route("/admin/webhooks", methods=["GET", "POST"])
@admin_required
def admin_webhooks():
    db = get_db()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        url = request.form.get("url", "").strip()
        note = request.form.get("note", "").strip()
        if not name or not url:
            flash("A webhook needs both a name and a URL.", "error")
        elif not DISCORD_WEBHOOK_RE.match(url):
            flash("That doesn't look like a Discord webhook URL.", "error")
        else:
            try:
                db.execute(
                    "INSERT INTO webhooks (name, url, note, created_at) VALUES (?, ?, ?, ?)",
                    (name, url, note, now()),
                )
                db.commit()
                flash(f"Added webhook {name}.", "ok")
            except sqlite3.IntegrityError:
                flash("A webhook with that name already exists.", "error")
        return redirect(url_for("admin_webhooks"))
    hooks = db.execute("SELECT * FROM webhooks ORDER BY name").fetchall()
    roles = {}
    for r in db.execute("SELECT * FROM roles ORDER BY name").fetchall():
        roles.setdefault(r["webhook_id"], []).append(r)
    return render_template("admin_webhooks.html", hooks=hooks, roles=roles)


@app.route("/admin/webhooks/<int:hook_id>/delete", methods=["POST"])
@admin_required
def delete_webhook(hook_id):
    get_db().execute("DELETE FROM webhooks WHERE id = ?", (hook_id,))
    get_db().commit()
    flash("Webhook removed.", "ok")
    return redirect(url_for("admin_webhooks"))


@app.route("/admin/webhooks/<int:hook_id>/test", methods=["POST"])
@admin_required
def test_webhook(hook_id):
    hook = get_db().execute("SELECT * FROM webhooks WHERE id = ?", (hook_id,)).fetchone()
    if hook is None:
        abort(404)
    try:
        resp = requests.get(hook["url"], timeout=10)
        if resp.status_code == 200:
            info = resp.json()
            flash(
                f"Webhook is live — posts as “{info.get('name', 'unknown')}”.", "ok"
            )
        else:
            flash(f"Discord returned {resp.status_code} — the webhook may have been deleted.", "error")
    except requests.RequestException:
        flash("Couldn't reach Discord to test the webhook.", "error")
    return redirect(url_for("admin_webhooks"))


@app.route("/admin/webhooks/<int:hook_id>/roles", methods=["POST"])
@admin_required
def add_role(hook_id):
    db = get_db()
    hook = db.execute("SELECT * FROM webhooks WHERE id = ?", (hook_id,)).fetchone()
    if hook is None:
        abort(404)
    name = request.form.get("name", "").strip().lstrip("@")
    role_id = request.form.get("role_id", "").strip()
    if not name or not role_id.isdigit():
        flash("A role needs a name and a numeric role ID.", "error")
    else:
        try:
            db.execute(
                "INSERT INTO roles (webhook_id, name, role_id) VALUES (?, ?, ?)",
                (hook_id, name, role_id),
            )
            db.commit()
            flash(f"@{name} can now be tagged via {hook['name']}.", "ok")
        except sqlite3.IntegrityError:
            flash("That role ID is already registered for this webhook.", "error")
    return redirect(url_for("admin_webhooks"))


@app.route("/admin/roles/<int:role_id>/delete", methods=["POST"])
@admin_required
def delete_role(role_id):
    get_db().execute("DELETE FROM roles WHERE id = ?", (role_id,))
    get_db().commit()
    flash("Role removed — it can no longer be tagged.", "ok")
    return redirect(url_for("admin_webhooks"))


# --------------------------------------------------------------------------
# Admin — users & access
# --------------------------------------------------------------------------

@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    db = get_db()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        is_admin = 1 if request.form.get("is_admin") else 0
        if not username or len(password) < 8:
            flash("Give the account a username and a password of at least 8 characters.", "error")
        else:
            try:
                db.execute(
                    "INSERT INTO users (username, password_hash, is_admin, created_at)"
                    " VALUES (?, ?, ?, ?)",
                    (username, generate_password_hash(password), is_admin, now()),
                )
                db.commit()
                flash(f"Created account {username}.", "ok")
            except sqlite3.IntegrityError:
                flash("That username is already taken.", "error")
        return redirect(url_for("admin_users"))
    users = db.execute("SELECT * FROM users ORDER BY username").fetchall()
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    if user_id == g.user["id"]:
        flash("You can't delete the account you're signed in with.", "error")
        return redirect(url_for("admin_users"))
    get_db().execute("DELETE FROM users WHERE id = ?", (user_id,))
    get_db().commit()
    flash("Account deleted.", "ok")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/reset", methods=["POST"])
@admin_required
def reset_password(user_id):
    password = request.form.get("password", "")
    if len(password) < 8:
        flash("The new password needs at least 8 characters.", "error")
    else:
        get_db().execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(password), user_id),
        )
        get_db().commit()
        flash("Password reset.", "ok")
    return redirect(url_for("admin_users"))


@app.route("/admin/access", methods=["GET", "POST"])
@admin_required
def admin_access():
    db = get_db()
    users = db.execute("SELECT * FROM users WHERE is_admin = 0 ORDER BY username").fetchall()
    hooks = db.execute("SELECT * FROM webhooks ORDER BY name").fetchall()
    if request.method == "POST":
        db.execute("DELETE FROM access")
        for u in users:
            for h in hooks:
                if request.form.get(f"grant_{u['id']}_{h['id']}"):
                    db.execute(
                        "INSERT INTO access (user_id, webhook_id) VALUES (?, ?)",
                        (u["id"], h["id"]),
                    )
        db.commit()
        flash("Access saved.", "ok")
        return redirect(url_for("admin_access"))
    grants = {
        (row["user_id"], row["webhook_id"])
        for row in db.execute("SELECT * FROM access").fetchall()
    }
    return render_template("admin_access.html", users=users, hooks=hooks, grants=grants)


@app.route("/admin/audit")
@admin_required
def admin_audit():
    rows = get_db().execute(
        "SELECT * FROM audit ORDER BY id DESC LIMIT 200"
    ).fetchall()
    return render_template("admin_audit.html", rows=rows)


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
