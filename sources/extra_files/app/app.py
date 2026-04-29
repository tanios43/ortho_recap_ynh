#!/usr/bin/env python3
"""
Ortho Récap — Backend Flask
API REST pour la sauvegarde des honoraires et kilomètres.
Auth : header X-Auth-User injecté par SSOwat (nginx auth_header = true).
Admin : défini à l'installation, seul utilisateur autorisé à modifier.
"""

import os
import json
import sqlite3
import hashlib
import hmac
import time
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, abort

app = Flask(__name__, static_folder="static")

# ── Configuration ────────────────────────────────────────────────────────────
DATA_DIR  = os.environ.get("DATA_DIR", "/home/yunohost.app/ortho_recap")
DB_PATH   = os.path.join(DATA_DIR, "data.db")
ADMIN     = os.environ.get("ADMIN_USER", "")
SECRET    = os.environ.get("APP_SECRET", "changeme")
# ─────────────────────────────────────────────────────────────────────────────


# ── Base de données ───────────────────────────────────────────────────────────
def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            year    INTEGER NOT NULL,
            month   INTEGER NOT NULL,
            day     INTEGER NOT NULL,
            site    TEXT    NOT NULL,
            type    TEXT    NOT NULL,
            value   REAL    NOT NULL DEFAULT 0,
            PRIMARY KEY (year, month, day, site, type)
        )
    """)
    db.commit()
    db.close()
# ─────────────────────────────────────────────────────────────────────────────


# ── Auth helpers ──────────────────────────────────────────────────────────────
def get_current_user():
    """Lit l'utilisateur depuis le header SSOwat injecté par nginx."""
    return request.headers.get("X-Auth-User", "")

def is_admin():
    return get_current_user() == ADMIN

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not get_current_user():
            abort(401)
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_admin():
            abort(403)
        return f(*args, **kwargs)
    return decorated

def make_api_token():
    """Génère un token HMAC signé valable 1h pour les appels /api/ (bypass SSOwat)."""
    ts = str(int(time.time()) // 3600)
    user = get_current_user()
    sig = hmac.new(SECRET.encode(), f"{user}:{ts}".encode(), hashlib.sha256).hexdigest()
    return f"{user}:{ts}:{sig}"

def verify_api_token(token):
    try:
        user, ts, sig = token.split(":")
        ts_now = str(int(time.time()) // 3600)
        expected = hmac.new(SECRET.encode(), f"{user}:{ts}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if abs(int(ts) - int(ts_now)) > 1:  # tolérance ±1h
            return None
        return user
    except Exception:
        return None
# ─────────────────────────────────────────────────────────────────────────────


# ── Routes statiques ──────────────────────────────────────────────────────────
@app.route("/")
@require_auth
def index():
    role = "admin" if is_admin() else "viewer"
    user = get_current_user()
    token = make_api_token()
    # On injecte role, user et token dans le HTML via un script inline
    inject = f"""<script>
window.ORTHO_USER  = {json.dumps(user)};
window.ORTHO_ROLE  = {json.dumps(role)};
window.ORTHO_TOKEN = {json.dumps(token)};
</script>"""
    with open(os.path.join(app.static_folder, "index.html"), "r", encoding="utf-8") as f:
        html = f.read()
    html = html.replace("</head>", inject + "\n</head>", 1)
    from flask import Response
    return Response(html, mimetype="text/html")
# ─────────────────────────────────────────────────────────────────────────────


# ── API : lecture (tous les utilisateurs auth) ────────────────────────────────
@app.route("/api/data/<int:year>/<int:month>")
def api_get_month(year, month):
    token = request.headers.get("X-Api-Token", "")
    user = verify_api_token(token)
    if not user:
        abort(401)

    db = get_db()
    rows = db.execute(
        "SELECT day, site, type, value FROM entries WHERE year=? AND month=?",
        (year, month)
    ).fetchall()
    db.close()

    # Format identique au localStorage original : { "day-site-type": value }
    result = {}
    for r in rows:
        key = f"{r['day']}-{r['site']}-{r['type']}"
        result[key] = r["value"]
    return jsonify(result)


# ── API : écriture (admin uniquement) ─────────────────────────────────────────
@app.route("/api/data/<int:year>/<int:month>", methods=["POST"])
def api_set_month(year, month):
    token = request.headers.get("X-Api-Token", "")
    user = verify_api_token(token)
    if not user:
        abort(401)
    if user != ADMIN:
        abort(403)

    payload = request.get_json(force=True) or {}
    db = get_db()
    for key, value in payload.items():
        try:
            parts = key.split("-")          # "day-site-type"
            day   = int(parts[0])
            site  = parts[1]
            typ   = parts[2]
            value = float(value)
        except (ValueError, IndexError):
            continue
        db.execute("""
            INSERT INTO entries (year, month, day, site, type, value)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(year, month, day, site, type) DO UPDATE SET value=excluded.value
        """, (year, month, day, site, typ, value))
    db.commit()
    db.close()
    return jsonify({"ok": True})


# ── API : infos utilisateur courant ──────────────────────────────────────────
@app.route("/api/me")
def api_me():
    token = request.headers.get("X-Api-Token", "")
    user = verify_api_token(token)
    if not user:
        abort(401)
    return jsonify({"user": user, "role": "admin" if user == ADMIN else "viewer"})


# ── Lancement ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port)
