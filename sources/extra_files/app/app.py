#!/usr/bin/env python3
"""
Ortho Récap — Backend Flask
API REST pour la sauvegarde des honoraires et kilomètres.
Copie exacte du modèle d'auth de scm_vidi_ynh.
"""

import os
import json
import base64
import hmac
import hashlib
import sqlite3
import time
from functools import wraps
from flask import Flask, request, jsonify, g, Response

app = Flask(__name__, static_folder="static")

# ── Configuration ─────────────────────────────────────────────────────────────
DB_PATH    = os.environ.get("DATA_DIR", "/home/yunohost.app/ortho_recap") + "/data.db"
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
SECRET_KEY = os.environ.get("APP_SECRET", os.urandom(32).hex())
# ─────────────────────────────────────────────────────────────────────────────


# ── Base de données ───────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = sqlite3.connect(DB_PATH)
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


# ── Auth — copie exacte de scm_vidi_ynh ──────────────────────────────────────
def make_token(username):
    expires = int(time.time()) + 86400
    payload = f"{username}:{expires}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.b64encode(f"{payload}:{sig}".encode()).decode()

def verify_token(token):
    try:
        raw = base64.b64decode(token.encode()).decode()
        username, expires_str, sig = raw.rsplit(":", 2)
        if time.time() > int(expires_str):
            return None
        payload = f"{username}:{expires_str}"
        expected = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, expected):
            return username
    except Exception:
        pass
    return None

def get_current_user():
    # Méthode 1 — Token signé (appels API JS)
    token = request.headers.get("X-Ortho-Token", "")
    if token:
        user = verify_token(token)
        if user:
            return user
    # Méthode 2 — Authorization Basic (YunoHost 12)
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth[6:]).decode("utf-8")
            username = decoded.split(":")[0]
            if username:
                return username
        except Exception:
            pass
    # Méthode 3 — X-Remote-User (YunoHost < 12)
    remote_user = request.headers.get("X-Remote-User", "")
    if remote_user:
        return remote_user
    return ""

def is_admin():
    return get_current_user() == ADMIN_USER

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not get_current_user():
            return jsonify({"error": "Non authentifié"}), 401
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_admin():
            return jsonify({"error": "Réservé à l'administrateur"}), 403
        return f(*args, **kwargs)
    return decorated
# ─────────────────────────────────────────────────────────────────────────────


# ── API : lecture ─────────────────────────────────────────────────────────────
@app.route("/api/whoami")
def whoami():
    return jsonify({"user": get_current_user(), "is_admin": is_admin()})

@app.route("/api/data/<int:year>/<int:month>")
@require_auth
def api_get_month(year, month):
    token = request.headers.get("X-Ortho-Token", "")
    if not verify_token(token):
        return jsonify({"error": "Token invalide"}), 401
    db = get_db()
    rows = db.execute(
        "SELECT day, site, type, value FROM entries WHERE year=? AND month=?",
        (year, month)
    ).fetchall()
    result = {}
    for r in rows:
        result[f"{r['day']}-{r['site']}-{r['type']}"] = r["value"]
    return jsonify(result)


# ── API : écriture ────────────────────────────────────────────────────────────
@app.route("/api/data/<int:year>/<int:month>", methods=["POST"])
@require_admin
def api_set_month(year, month):
    token = request.headers.get("X-Ortho-Token", "")
    if not verify_token(token):
        return jsonify({"error": "Token invalide"}), 403
    payload = request.get_json(force=True) or {}
    db = get_db()
    for key, value in payload.items():
        try:
            parts = key.split("-")
            day  = int(parts[0])
            site = parts[1]
            typ  = parts[2]
            value = float(value)
        except (ValueError, IndexError):
            continue
        db.execute("""
            INSERT INTO entries (year, month, day, site, type, value)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(year, month, day, site, type) DO UPDATE SET value=excluded.value
        """, (year, month, day, site, typ, value))
    db.commit()
    return jsonify({"ok": True})


# ── Servir l'app HTML ─────────────────────────────────────────────────────────
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve(path):
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        from flask import send_from_directory
        return send_from_directory(app.static_folder, path)

    user  = get_current_user()
    admin = user == ADMIN_USER
    token = make_token(user) if user else ""
    # Déduire le path prefix depuis la requête (ex: /ortho_recap)
    path_prefix = request.script_root or request.host_url.rstrip("/")
    # Plus simple : utiliser REQUEST_URI pour extraire le prefix
    raw_path = request.environ.get("REQUEST_URI", request.path)
    path_prefix = raw_path.rsplit("/api", 1)[0] if "/api" in raw_path else ""
    path_prefix = path_prefix.rstrip("/")

    with open(os.path.join(app.static_folder, "index.html"), "r", encoding="utf-8") as f:
        html = f.read()

    injection = f"""<script>
window.ORTHO_PATH  = "{path_prefix}";
window.ORTHO_USER  = "{user}";
window.ORTHO_ROLE  = "{"admin" if admin else "viewer"}";
window.ORTHO_TOKEN = "{token}";
</script>"""
    html = html.replace("</head>", injection + "\n</head>", 1)
    return Response(html, mimetype="text/html")


# ── Lancement ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port)
