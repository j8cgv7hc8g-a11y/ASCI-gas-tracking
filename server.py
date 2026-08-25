#!/usr/bin/env python3
"""
Gas Tracking Management System - Backend API
Python 3 + SQLite (stdlib only)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# -------------------- Config --------------------
HOST = "0.0.0.0"
PORT = 8765
DB_PATH = os.environ.get("GAS_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "gas_system.db"))
SECRET = os.environ.get("GAS_SECRET", "asci-gas-tracking-secret-change-me")
TOKEN_TTL = 60 * 60 * 24 * 7  # 7 days

# -------------------- DB --------------------
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            full_name TEXT NOT NULL,
            department TEXT DEFAULT '',
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at REAL NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS usage_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            usage_date TEXT NOT NULL,
            usage_time TEXT NOT NULL,
            gas_type TEXT NOT NULL,
            cylinder_code TEXT NOT NULL,
            amount TEXT NOT NULL,
            operator_name TEXT NOT NULL,
            tool TEXT DEFAULT '',
            note TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS cylinders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            gas_type TEXT NOT NULL,
            location TEXT NOT NULL,
            pressure_bar REAL NOT NULL DEFAULT 0,
            purity TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'normal',
            responsible TEXT DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        """
    )
    # seed admin
    cur = conn.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if not cur.fetchone():
        salt, ph = hash_password("1234")
        conn.execute(
            "INSERT INTO users (username, password_hash, salt, full_name, department, role) VALUES (?,?,?,?,?,?)",
            ("admin", ph, salt, "ผู้ดูแลระบบ", "ASci", "admin"),
        )
    # seed cylinders if empty
    cur = conn.execute("SELECT COUNT(*) AS c FROM cylinders")
    if cur.fetchone()["c"] == 0:
        samples = [
            ("CYL-001", "Nitrogen (N₂)", "ห้อง LAB-03", 12, "99.999%", "critical", "คุณกิตติพงศ์"),
            ("CYL-002", "Oxygen (O₂)", "ห้อง LAB-01", 145, "99.5%", "normal", "คุณณัฐชา"),
            ("CYL-003", "Argon (Ar)", "คลังแก๊สกลาง", 98, "99.999%", "low", "คุณสุวิทย์"),
            ("CYL-004", "Carbon Dioxide (CO₂)", "ห้องเครื่องมือ", 65, "99.9%", "normal", "คุณอรทัย"),
        ]
        conn.executemany(
            "INSERT INTO cylinders (code, gas_type, location, pressure_bar, purity, status, responsible) VALUES (?,?,?,?,?,?,?)",
            samples,
        )
    conn.commit()
    conn.close()


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return salt, dk.hex()


def verify_password(password: str, salt: str, password_hash: str) -> bool:
    _, h = hash_password(password, salt)
    return hmac.compare_digest(h, password_hash)


def create_token(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires = time.time() + TOKEN_TTL
    conn = get_db()
    conn.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)",
        (token, user_id, expires),
    )
    conn.commit()
    conn.close()
    return token


def get_user_by_token(token: str | None):
    if not token:
        return None
    conn = get_db()
    row = conn.execute(
        """
        SELECT u.* FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ? AND s.expires_at > ?
        """,
        (token, time.time()),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def user_public(u: dict) -> dict:
    return {
        "id": u["id"],
        "username": u["username"],
        "fullName": u["full_name"],
        "department": u["department"] or "",
        "role": u["role"],
        "createdAt": u.get("created_at"),
    }


# -------------------- HTTP Handler --------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "GasTracking/1.0"

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {args[0]}")

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _json(self, status: int, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _auth_user(self):
        auth = self.headers.get("Authorization") or ""
        token = auth[7:].strip() if auth.startswith("Bearer ") else None
        return get_user_by_token(token)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # static files
        if path in ("/", "/index.html"):
            return self._serve_file("index.html", "text/html; charset=utf-8")
        if path == "/logo.png":
            return self._serve_file("logo.png", "image/jpeg")

        if path == "/api/health":
            return self._json(200, {"ok": True, "service": "gas-tracking"})

        user = self._auth_user()

        if path == "/api/me":
            if not user:
                return self._json(401, {"error": "ไม่ได้เข้าสู่ระบบ"})
            return self._json(200, {"user": user_public(user)})

        if path == "/api/users":
            if not user:
                return self._json(401, {"error": "ไม่ได้เข้าสู่ระบบ"})
            if user["role"] != "admin":
                return self._json(403, {"error": "สิทธิ์ไม่เพียงพอ"})
            conn = get_db()
            rows = conn.execute(
                "SELECT id, username, full_name, department, role, created_at FROM users ORDER BY id"
            ).fetchall()
            conn.close()
            users = [
                {
                    "id": r["id"],
                    "username": r["username"],
                    "fullName": r["full_name"],
                    "department": r["department"] or "",
                    "role": r["role"],
                    "createdAt": r["created_at"],
                }
                for r in rows
            ]
            return self._json(200, {"users": users})

        if path == "/api/cylinders":
            if not user:
                return self._json(401, {"error": "ไม่ได้เข้าสู่ระบบ"})
            conn = get_db()
            rows = conn.execute("SELECT * FROM cylinders ORDER BY code").fetchall()
            conn.close()
            items = [dict(r) for r in rows]
            return self._json(200, {"cylinders": items})

        if path == "/api/usage":
            if not user:
                return self._json(401, {"error": "ไม่ได้เข้าสู่ระบบ"})
            conn = get_db()
            rows = conn.execute(
                "SELECT * FROM usage_records ORDER BY id DESC LIMIT 100"
            ).fetchall()
            conn.close()
            items = [
                {
                    "id": r["id"],
                    "date": r["usage_date"],
                    "time": r["usage_time"],
                    "gas": r["gas_type"],
                    "cyl": r["cylinder_code"],
                    "amount": r["amount"],
                    "user": r["operator_name"],
                    "tool": r["tool"] or "",
                    "note": r["note"] or "",
                    "createdAt": r["created_at"],
                }
                for r in rows
            ]
            return self._json(200, {"records": items})

        if path == "/api/stats":
            if not user:
                return self._json(401, {"error": "ไม่ได้เข้าสู่ระบบ"})
            conn = get_db()
            total = conn.execute("SELECT COUNT(*) AS c FROM cylinders").fetchone()["c"]
            critical = conn.execute(
                "SELECT COUNT(*) AS c FROM cylinders WHERE status = 'critical'"
            ).fetchone()["c"]
            low = conn.execute(
                "SELECT COUNT(*) AS c FROM cylinders WHERE status = 'low'"
            ).fetchone()["c"]
            normal = conn.execute(
                "SELECT COUNT(*) AS c FROM cylinders WHERE status = 'normal'"
            ).fetchone()["c"]
            usage_count = conn.execute("SELECT COUNT(*) AS c FROM usage_records").fetchone()["c"]
            conn.close()
            return self._json(
                200,
                {
                    "totalCylinders": total,
                    "inUse": normal + low + critical,  # demo figure
                    "low": low,
                    "critical": critical,
                    "alerts": critical + (1 if low else 0),
                    "usageCount": usage_count,
                },
            )

        self._json(404, {"error": "ไม่พบ endpoint"})

    def do_POST(self):
        path = urlparse(self.path).path
        data = self._read_json()

        if path == "/api/register":
            full_name = (data.get("fullName") or "").strip()
            username = (data.get("username") or "").strip().lower()
            department = (data.get("department") or "").strip()
            password = data.get("password") or ""
            password2 = data.get("password2") or ""

            if not full_name or not username or not password:
                return self._json(400, {"error": "กรุณากรอกข้อมูลให้ครบ"})
            if len(username) < 4:
                return self._json(400, {"error": "ชื่อผู้ใช้ต้องมีอย่างน้อย 4 ตัวอักษร"})
            if not all(c.isalnum() or c in "._-" for c in username):
                return self._json(400, {"error": "ชื่อผู้ใช้ใช้ได้เฉพาะ a-z, 0-9, . _ -"})
            if len(password) < 4:
                return self._json(400, {"error": "รหัสผ่านต้องมีอย่างน้อย 4 ตัวอักษร"})
            if password != password2:
                return self._json(400, {"error": "รหัสผ่านกับยืนยันรหัสผ่านไม่ตรงกัน"})

            salt, ph = hash_password(password)
            conn = get_db()
            try:
                conn.execute(
                    "INSERT INTO users (username, password_hash, salt, full_name, department, role) VALUES (?,?,?,?,?,?)",
                    (username, ph, salt, full_name, department, "user"),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                conn.close()
                return self._json(409, {"error": "ชื่อผู้ใช้นี้มีคนใช้แล้ว"})
            conn.close()
            return self._json(201, {"ok": True, "message": "สมัครสมาชิกสำเร็จ"})

        if path == "/api/login":
            username = (data.get("username") or "").strip().lower()
            password = data.get("password") or ""
            if not username or not password:
                return self._json(400, {"error": "กรุณากรอกชื่อผู้ใช้และรหัสผ่าน"})
            conn = get_db()
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            conn.close()
            if not row or not verify_password(password, row["salt"], row["password_hash"]):
                return self._json(401, {"error": "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"})
            user = dict(row)
            token = create_token(user["id"])
            return self._json(200, {"token": token, "user": user_public(user)})

        if path == "/api/logout":
            auth = self.headers.get("Authorization") or ""
            token = auth[7:].strip() if auth.startswith("Bearer ") else None
            if token:
                conn = get_db()
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                conn.commit()
                conn.close()
            return self._json(200, {"ok": True})

        user = self._auth_user()
        if not user:
            return self._json(401, {"error": "ไม่ได้เข้าสู่ระบบ"})

        if path == "/api/usage":
            required = ["date", "time", "gas", "cyl", "amount", "user"]
            for k in required:
                if not (data.get(k) or "").strip():
                    return self._json(400, {"error": f"กรุณากรอก {k}"})
            conn = get_db()
            cur = conn.execute(
                """
                INSERT INTO usage_records
                (user_id, usage_date, usage_time, gas_type, cylinder_code, amount, operator_name, tool, note)
                VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (
                    user["id"],
                    data["date"].strip(),
                    data["time"].strip(),
                    data["gas"].strip(),
                    data["cyl"].strip(),
                    data["amount"].strip(),
                    data["user"].strip(),
                    (data.get("tool") or "").strip(),
                    (data.get("note") or "").strip(),
                ),
            )
            rid = cur.lastrowid
            conn.commit()
            conn.close()
            return self._json(201, {"ok": True, "id": rid})

        self._json(404, {"error": "ไม่พบ endpoint"})

    def do_DELETE(self):
        path = urlparse(self.path).path
        user = self._auth_user()
        if not user:
            return self._json(401, {"error": "ไม่ได้เข้าสู่ระบบ"})

        if path.startswith("/api/users/"):
            if user["role"] != "admin":
                return self._json(403, {"error": "สิทธิ์ไม่เพียงพอ"})
            try:
                uid = int(path.rsplit("/", 1)[-1])
            except ValueError:
                return self._json(400, {"error": "id ไม่ถูกต้อง"})
            conn = get_db()
            row = conn.execute("SELECT username FROM users WHERE id = ?", (uid,)).fetchone()
            if not row:
                conn.close()
                return self._json(404, {"error": "ไม่พบผู้ใช้"})
            if row["username"] == "admin":
                conn.close()
                return self._json(400, {"error": "ไม่สามารถลบบัญชี admin ได้"})
            conn.execute("DELETE FROM users WHERE id = ?", (uid,))
            conn.commit()
            conn.close()
            return self._json(200, {"ok": True})

        self._json(404, {"error": "ไม่พบ endpoint"})

    def _serve_file(self, name: str, content_type: str):
        base = os.path.dirname(os.path.abspath(__file__))
        fpath = os.path.join(base, name)
        if not os.path.isfile(fpath):
            return self._json(404, {"error": "ไม่พบไฟล์"})
        with open(fpath, "rb") as f:
            data = f.read()
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Gas Tracking API running at http://127.0.0.1:{PORT}")
    print(f"Open http://127.0.0.1:{PORT}/ in browser")
    print("Default admin: admin / 1234")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.server_close()


if __name__ == "__main__":
    main()
