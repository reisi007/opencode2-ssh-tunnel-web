"""code-auth: Single-User Cookie-Gate fuer Caddy forward_auth. Nur Stdlib + optional bcrypt.

Env: AUTH_USER, AUTH_HASH (bcrypt $2a$/$2b$ ODER pbkdf2$iter$salt$hex), AUTH_SECRET, SESSION_TTL.
Routen:
  GET  /check      -> 200/401 (Caddy forward_auth, uri /check)
  GET  /api/me     -> 200 {"user":...} / 401 (Browser: schon eingeloggt?)
  POST /login      -> JSON oder Form, setzt Cookie, 200/401
  POST /api/login  -> dito (Caddy routet /api/login hierher)
  POST /logout, /api/logout -> Cookie loeschen
Cookie: auth=user:exp:sig, sig=HMAC_SHA256(AUTH_SECRET, "user:exp"), HttpOnly, Secure, SameSite=Lax, Path /.
"""

import base64
import hashlib
import hmac
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

AUTH_USER = os.environ.get("AUTH_USER", "admin")
AUTH_HASH = os.environ.get("AUTH_HASH", "")
AUTH_SECRET = os.environ.get("AUTH_SECRET", "")
SESSION_TTL = int(os.environ.get("SESSION_TTL", "43200"))
LISTEN_PORT = int(os.environ.get("AUTH_PORT", "8081"))

_bcrypt = None
if AUTH_HASH.startswith("$2"):
    try:
        import bcrypt  # pip install bcrypt (nur noetig fuer caddy hash-password Format)
        _bcrypt = bcrypt
    except ImportError:
        _bcrypt = None


def verify_password(plain: str) -> bool:
    if not AUTH_HASH or not plain:
        return False
    if AUTH_HASH.startswith("$2"):
        if _bcrypt is None:
            print("FEHLER: bcrypt-Hash konfiguriert aber bcrypt-Modul fehlt. "
                  "Stack-Command installiert es (pip install bcrypt).")
            return False
        try:
            return _bcrypt.checkpw(plain.encode(), AUTH_HASH.encode())
        except Exception:
            return False
    if AUTH_HASH.startswith("pbkdf2$"):
        try:
            _, it, salt_hex, hash_hex = AUTH_HASH.split("$")
            dk = hashlib.pbkdf2_hmac("sha256", plain.encode(),
                                     bytes.fromhex(salt_hex), int(it))
            return hmac.compare_digest(dk.hex(), hash_hex)
        except Exception:
            return False
    # Klartext-Fallback (nicht empfohlen, nur Dev)
    return hmac.compare_digest(plain, AUTH_HASH)


def sign(user: str, exp: int) -> str:
    msg = f"{user}:{exp}".encode()
    return hmac.new(AUTH_SECRET.encode(), msg, hashlib.sha256).hexdigest()


def make_cookie(user: str) -> str:
    exp = int(time.time()) + SESSION_TTL
    return f"{user}:{exp}:{sign(user, exp)}"


def check_cookie(header: str | None) -> str | None:
    if not header:
        return None
    cookies = {}
    for part in header.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            cookies[k] = v
    val = cookies.get("auth")
    if not val:
        return None
    try:
        user, exp_s, sig = val.split(":")
    except ValueError:
        return None
    if user != AUTH_USER:
        return None
    try:
        if int(exp_s) < int(time.time()):
            return None
    except ValueError:
        return None
    if not hmac.compare_digest(sign(user, int(exp_s)), sig):
        return None
    return user


class H(BaseHTTPRequestHandler):
    server_version = "code-auth/1.0"

    def log_message(self, *a):
        pass

    def _send(self, code: int, body: bytes = b"", ctype: str = "text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _user(self):
        return check_cookie(self.headers.get("Cookie"))

    def do_GET(self):
        if self.path in ("/check", "/api/me"):
            user = self._user()
            if user:
                if self.path == "/api/me":
                    self._send(200, json.dumps({"user": user}).encode(), "application/json")
                else:
                    self._send(200, b"OK")
            else:
                self._send(401, b"Unauthorized")
        elif self.path in ("/", "/health"):
            self._send(200, b"code-auth ok")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        if self.path not in ("/login", "/api/login", "/logout", "/api/logout"):
            self._send(404, b"not found")
            return
        if self.path.endswith("logout"):
            self.send_response(200)
            self.send_header("Set-Cookie",
                             "auth=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b""
        ctype = self.headers.get("Content-Type", "")
        username, password = "", ""
        if "application/json" in ctype:
            try:
                data = json.loads(raw.decode() or "{}")
                username = data.get("username", "")
                password = data.get("password", "")
            except Exception:
                pass
        else:
            form = parse_qs(raw.decode(errors="replace"))
            username = form.get("username", [""])[0] or form.get("user", [""])[0]
            password = form.get("password", [""])[0]
        # Single-User: leeres username-Feld = AUTH_USER (nur Passwort-Formular)
        if not username:
            username = AUTH_USER
        if username == AUTH_USER and verify_password(password):
            cookie = make_cookie(username)
            body = json.dumps({"ok": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Set-Cookie",
                             f"auth={cookie}; Path=/; Max-Age={SESSION_TTL}; "
                             f"HttpOnly; Secure; SameSite=Lax")
            self.end_headers()
            self.wfile.write(body)
        else:
            time.sleep(0.5)  # minimales Rate-Limit gegen Brute-Force
            self._send(401, json.dumps({"ok": False}).encode(), "application/json")


if __name__ == "__main__":
    if not AUTH_SECRET:
        raise SystemExit("AUTH_SECRET fehlt")
    if not AUTH_HASH:
        raise SystemExit("AUTH_HASH fehlt (siehe README: caddy hash-password)")
    print(f"code-auth lauscht auf :{LISTEN_PORT} als {AUTH_USER}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), H).serve_forever()
