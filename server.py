#!/usr/bin/env python3
"""Servidor de cuentas QUANTIX. Los usuarios viven aquí y cualquier teléfono puede entrar."""
from __future__ import print_function

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
import uuid
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
DB_PATH = os.path.join(DATA, "users.sqlite")
SECRET_PATH = os.path.join(DATA, "jwt.secret")
SETTINGS_PATH = os.path.join(DATA, "settings.json")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8787"))
ADMIN_USER = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASSWORD", "QuantixAdmin1")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@quantix.app")
TOKEN_HOURS = 12
GIST_ID = os.environ.get("GIST_ID", "4625c96548b90d08e42996979c279efa").strip()
GH_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
GIST_FILE = "quantix-store.json"

_lock = threading.Lock()


def _ensure_files():
    os.makedirs(DATA, exist_ok=True)
    if not os.path.exists(SECRET_PATH):
        with open(SECRET_PATH, "w") as f:
            f.write(uuid.uuid4().hex + uuid.uuid4().hex)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            salt TEXT NOT NULL,
            hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL,
            active INTEGER NOT NULL,
            verified INTEGER NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def _secret():
    with open(SECRET_PATH) as f:
        return f.read().strip().encode("utf-8")


def _hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000).hex()


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text):
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _make_token(username):
    payload = {"sub": username, "exp": int(time.time()) + TOKEN_HOURS * 3600}
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = _b64url(hmac.new(_secret(), body.encode("ascii"), hashlib.sha256).digest())
    return body + "." + sig


def _read_token(token):
    try:
        body, sig = token.split(".", 1)
    except ValueError:
        return None
    expected = _b64url(hmac.new(_secret(), body.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, sig):
        return None
    payload = json.loads(_b64url_decode(body).decode("utf-8"))
    if int(payload.get("exp", 0)) < time.time():
        return None
    return payload.get("sub")


def _validate_password(password):
    if len(password) < 8 or not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        raise ValueError("La contraseña necesita 8 caracteres, una letra y un número.")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def seed_admin():
    with _lock:
        conn = db()
        row = conn.execute("SELECT username FROM users WHERE username = ?", (ADMIN_USER,)).fetchone()
        if row is None:
            salt = uuid.uuid4().hex
            conn.execute(
                "INSERT INTO users VALUES (?, ?, ?, ?, 1, 1, 1)",
                (ADMIN_USER, ADMIN_EMAIL, salt, _hash_password(ADMIN_PASS, salt)),
            )
            conn.commit()
        else:
            conn.execute(
                "UPDATE users SET is_admin = 1, active = 1, verified = 1 WHERE username = ?",
                (ADMIN_USER,),
            )
            conn.commit()
        conn.close()


def _load_settings():
    if not os.path.isfile(SETTINGS_PATH):
        return {"contactUrl": ""}
    try:
        with open(SETTINGS_PATH) as f:
            data = json.load(f)
    except Exception:
        return {"contactUrl": ""}
    if not isinstance(data, dict):
        return {"contactUrl": ""}
    return {"contactUrl": str(data.get("contactUrl") or "").strip()}


def _save_settings(settings):
    with open(SETTINGS_PATH, "w") as f:
        json.dump(settings, f)


def _gh_headers():
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + GH_TOKEN,
        "User-Agent": "quantix-auth",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
    }


def _snapshot():
    conn = db()
    users = [{key: row[key] for key in row.keys()} for row in conn.execute("SELECT * FROM users")]
    conn.close()
    secret = ""
    if os.path.isfile(SECRET_PATH):
        with open(SECRET_PATH) as f:
            secret = f.read().strip()
    return {"users": users, "settings": _load_settings(), "secret": secret}


def _apply_snapshot(data):
    users = data.get("users") or []
    settings = data.get("settings") or {"contactUrl": ""}
    secret = data.get("secret") or ""
    if secret:
        with open(SECRET_PATH, "w") as f:
            f.write(secret)
    _save_settings(settings)
    conn = db()
    conn.execute("DELETE FROM users")
    for user in users:
        conn.execute(
            "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                user["username"],
                user["email"],
                user["salt"],
                user["hash"],
                int(user.get("is_admin") or 0),
                int(user.get("active") if user.get("active") is not None else 1),
                int(user.get("verified") if user.get("verified") is not None else 1),
            ),
        )
    conn.commit()
    conn.close()


def restore_from_cloud():
    if not GIST_ID or not GH_TOKEN:
        return
    try:
        req = urllib.request.Request("https://api.github.com/gists/" + GIST_ID, headers=_gh_headers())
        with urllib.request.urlopen(req, timeout=20) as resp:
            gist = json.loads(resp.read().decode("utf-8"))
        content = gist.get("files", {}).get(GIST_FILE, {}).get("content")
        if not content:
            return
        data = json.loads(content)
        if data.get("users"):
            _apply_snapshot(data)
            print("restored accounts from gist")
    except Exception as exc:
        print("gist restore skipped:", exc)


def persist():
    if not GIST_ID or not GH_TOKEN:
        return
    body = json.dumps({"files": {GIST_FILE: {"content": json.dumps(_snapshot())}}}).encode("utf-8")
    req = urllib.request.Request(
        "https://api.github.com/gists/" + GIST_ID,
        data=body,
        headers=_gh_headers(),
        method="PATCH",
    )
    try:
        urllib.request.urlopen(req, timeout=20).read()
    except Exception as exc:
        print("gist persist failed:", exc)


def _normalize_url(url):
    url = (url or "").strip()
    if not url:
        return ""
    lower = url.lower()
    allowed = ("http://", "https://", "mailto:", "tel:", "sms:")
    if not lower.startswith(allowed):
        url = "https://" + url.lstrip("/")
    return url


def user_public(row):
    return {
        "username": row["username"],
        "email": row["email"],
        "verified": bool(row["verified"]),
        "isAdmin": bool(row["is_admin"]),
        "active": bool(row["active"]),
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")

    def _json(self, code, payload):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def _bearer(self):
        header = self.headers.get("Authorization") or ""
        if header.lower().startswith("bearer "):
            return header.split(" ", 1)[1].strip()
        return None

    def _require_user(self):
        username = _read_token(self._bearer() or "")
        if not username:
            return None
        conn = db()
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        if row is None or not row["active"]:
            return None
        return row

    def _require_admin(self):
        row = self._require_user()
        if row is None or not row["is_admin"]:
            return None
        return row

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self._json(200, {"ok": True, "service": "quantix-auth"})
            return
        if path == "/config":
            self._json(200, _load_settings())
            return
        if path == "/auth/me":
            row = self._require_user()
            if row is None:
                self._json(401, {"error": "Sesión caducada. Vuelve a iniciar sesión."})
                return
            self._json(200, {"user": user_public(row)})
            return
        if path == "/admin/users":
            if self._require_admin() is None:
                self._json(403, {"error": "Solo el administrador puede gestionar cuentas."})
                return
            conn = db()
            rows = conn.execute(
                "SELECT * FROM users ORDER BY is_admin DESC, username COLLATE NOCASE"
            ).fetchall()
            conn.close()
            self._json(200, {"users": [user_public(r) for r in rows]})
            return
        self._json(404, {"error": "No encontrado."})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        try:
            body = self._body()
        except Exception:
            self._json(400, {"error": "JSON inválido."})
            return
        if path == "/auth/login":
            self._login(body)
            return
        if path == "/admin/users":
            self._create(body)
            return
        if path == "/admin/users/password":
            self._reset(body)
            return
        self._json(404, {"error": "No encontrado."})

    def do_PUT(self):
        path = self.path.split("?", 1)[0]
        if path != "/admin/config":
            self._json(404, {"error": "No encontrado."})
            return
        if self._require_admin() is None:
            self._json(403, {"error": "Solo el administrador puede gestionar cuentas."})
            return
        try:
            body = self._body()
        except Exception:
            self._json(400, {"error": "JSON inválido."})
            return
        url = _normalize_url(body.get("contactUrl") or "")
        with _lock:
            settings = _load_settings()
            settings["contactUrl"] = url
            _save_settings(settings)
            persist()
        self._json(200, settings)

    def do_PATCH(self):
        path = self.path.split("?", 1)[0]
        if path != "/admin/users":
            self._json(404, {"error": "No encontrado."})
            return
        if self._require_admin() is None:
            self._json(403, {"error": "Solo el administrador puede gestionar cuentas."})
            return
        try:
            body = self._body()
        except Exception:
            self._json(400, {"error": "JSON inválido."})
            return
        username = (body.get("username") or "").strip()
        active = body.get("active")
        if not username or not isinstance(active, bool):
            self._json(400, {"error": "Usuario o estado no válido."})
            return
        if username.lower() == ADMIN_USER.lower():
            self._json(400, {"error": "No puedes desactivar la cuenta admin."})
            return
        with _lock:
            conn = db()
            cur = conn.execute(
                "UPDATE users SET active = ? WHERE username = ? COLLATE NOCASE",
                (1 if active else 0, username),
            )
            conn.commit()
            changed = cur.rowcount
            conn.close()
            if changed:
                persist()
        if not changed:
            self._json(404, {"error": "Usuario no encontrado."})
            return
        self._json(200, {"ok": True})

    def do_DELETE(self):
        path = self.path.split("?", 1)[0]
        if path != "/admin/users":
            self._json(404, {"error": "No encontrado."})
            return
        if self._require_admin() is None:
            self._json(403, {"error": "Solo el administrador puede gestionar cuentas."})
            return
        try:
            body = self._body()
        except Exception:
            self._json(400, {"error": "JSON inválido."})
            return
        username = (body.get("username") or "").strip()
        if not username:
            self._json(400, {"error": "Usuario no encontrado."})
            return
        if username.lower() == ADMIN_USER.lower():
            self._json(400, {"error": "No puedes eliminar la cuenta admin."})
            return
        with _lock:
            conn = db()
            cur = conn.execute("DELETE FROM users WHERE username = ? COLLATE NOCASE", (username,))
            conn.commit()
            changed = cur.rowcount
            conn.close()
            if changed:
                persist()
        if not changed:
            self._json(404, {"error": "Usuario no encontrado."})
            return
        self._json(200, {"ok": True})

    def _login(self, body):
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        conn = db()
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
        ).fetchone()
        conn.close()
        if row is None or not hmac.compare_digest(row["hash"], _hash_password(password, row["salt"])):
            self._json(401, {"error": "Usuario o contraseña incorrectos."})
            return
        if not row["active"]:
            self._json(403, {"error": "Esta cuenta está desactivada. Contacta al administrador."})
            return
        token = _make_token(row["username"])
        self._json(200, {"token": token, "user": user_public(row)})

    def _create(self, body):
        if self._require_admin() is None:
            self._json(403, {"error": "Solo el administrador puede crear cuentas."})
            return
        username = (body.get("username") or "").strip()
        email = (body.get("email") or "").strip()
        password = body.get("password") or ""
        if len(username) < 3:
            self._json(400, {"error": "El usuario debe tener al menos 3 caracteres."})
            return
        if "@" not in email or len(email) < 6:
            self._json(400, {"error": "El correo no es válido."})
            return
        try:
            _validate_password(password)
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
            return
        if username.lower() == ADMIN_USER.lower():
            self._json(400, {"error": "No puedes crear otro usuario admin."})
            return
        salt = uuid.uuid4().hex
        with _lock:
            conn = db()
            exists = conn.execute(
                "SELECT 1 FROM users WHERE username = ? COLLATE NOCASE", (username,)
            ).fetchone()
            if exists:
                conn.close()
                self._json(409, {"error": "Ese usuario ya existe."})
                return
            conn.execute(
                "INSERT INTO users VALUES (?, ?, ?, ?, 0, 1, 1)",
                (username, email, salt, _hash_password(password, salt)),
            )
            conn.commit()
            conn.close()
            persist()
        self._json(201, {"user": {"username": username, "email": email, "verified": True, "isAdmin": False, "active": True}})

    def _reset(self, body):
        if self._require_admin() is None:
            self._json(403, {"error": "Solo el administrador puede gestionar cuentas."})
            return
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        try:
            _validate_password(password)
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
            return
        if username.lower() == ADMIN_USER.lower():
            self._json(400, {"error": "Cambia la contraseña admin desde otro flujo."})
            return
        salt = uuid.uuid4().hex
        with _lock:
            conn = db()
            cur = conn.execute(
                "UPDATE users SET salt = ?, hash = ? WHERE username = ? COLLATE NOCASE",
                (salt, _hash_password(password, salt), username),
            )
            conn.commit()
            changed = cur.rowcount
            conn.close()
            if changed:
                persist()
        if not changed:
            self._json(404, {"error": "Usuario no encontrado."})
            return
        self._json(200, {"ok": True})


def main():
    _ensure_files()
    restore_from_cloud()
    seed_admin()
    persist()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print("QUANTIX auth listening on http://%s:%s" % (HOST, PORT))
    server.serve_forever()


if __name__ == "__main__":
    main()
