"""Real account auth for the hosted demo (v2).

SQLite-backed users with salted PBKDF2 password hashing (stdlib only — no extra
deps). Self-serve signup + login. The 3 original demo users are seeded so the
Tuesday flow still works; anyone can also create a real account.

Identity: each user has a stable `id` (uuid) used as the on-chain `grantee_id`,
plus an email and an optional short username for convenient login.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("XINSERE_DATA_DIR", os.path.join(HERE, "data"))
DB_PATH = os.path.join(DATA_DIR, "users.db")

_PBKDF2_ROUNDS = 200_000

# Deterministic avatar gradients (by user id) — keeps the branded look.
_GRADS = [
    ("#8A6BFF", "#5B3DF5"), ("#4FE3C1", "#2E9E8A"), ("#FF8B7A", "#B4503F"),
    ("#9277FF", "#5B3DF5"), ("#5BC8FF", "#2E6FF5"), ("#F5A15B", "#B4703F"),
    ("#C15BFF", "#7A2EF5"), ("#5BFF9E", "#2E9E5A"),
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _initials(name: str) -> str:
    parts = [p for p in name.strip().split() if p]
    if not parts:
        return "?"
    if len(parts) == 1:
        return parts[0][:2].upper()
    return (parts[0][0] + parts[-1][0]).upper()


class UserDB:
    def __init__(self, path: str = DB_PATH) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._path = path
        self._lock = threading.Lock()
        self._init()
        self._seed_demo_users()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._path)
        c.row_factory = sqlite3.Row
        return c

    def _init(self) -> None:
        with self._conn() as c:
            c.execute(
                """CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    username TEXT UNIQUE,
                    name TEXT NOT NULL,
                    pw_salt BLOB NOT NULL,
                    pw_hash BLOB NOT NULL,
                    created_at TEXT NOT NULL
                )"""
            )

    # --- password hashing ---------------------------------------------------

    @staticmethod
    def _hash(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ROUNDS)

    # --- creation / lookup --------------------------------------------------

    def create_user(self, email: str, password: str, name: str,
                    username: str | None = None) -> dict:
        email = email.lower().strip()
        if not email or "@" not in email:
            raise ValueError("A valid email is required")
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters")
        salt = os.urandom(16)
        uid = "usr_" + uuid.uuid4().hex[:16]
        with self._lock, self._conn() as c:
            if c.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
                raise ValueError("That email is already registered")
            if username and c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                raise ValueError("That username is taken")
            c.execute(
                "INSERT INTO users (id,email,username,name,pw_salt,pw_hash,created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (uid, email, username, name.strip() or email, salt,
                 self._hash(password, salt), _now()),
            )
        return self.get(uid)

    def verify(self, identifier: str, password: str) -> dict | None:
        """Log in by email or username."""
        ident = identifier.lower().strip()
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM users WHERE email=? OR username=?", (ident, ident)
            ).fetchone()
        if not row:
            return None
        if not hmac.compare_digest(self._hash(password, row["pw_salt"]), row["pw_hash"]):
            return None
        return self._to_dict(row)

    def get(self, user_id: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return self._to_dict(row) if row else None

    def all_except(self, user_id: str) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM users WHERE id!=? ORDER BY name", (user_id,)
            ).fetchall()
        return [self._to_dict(r) for r in rows]

    def _to_dict(self, row: sqlite3.Row) -> dict:
        return {"id": row["id"], "email": row["email"], "username": row["username"],
                "name": row["name"], "created_at": row["created_at"]}

    def public(self, user: dict) -> dict:
        """Fields safe to send to the client."""
        idx = int(user["id"][-4:], 36) % len(_GRADS) if user["id"][-4:].isalnum() else 0
        return {"id": user["id"], "name": user["name"], "email": user["email"],
                "initials": _initials(user["name"]), "grad": list(_GRADS[idx])}

    # --- seed the original demo users --------------------------------------

    def _seed_demo_users(self) -> None:
        seeds = [
            ("mark@xinsere.demo", "mark", "Mark Turner"),
            ("jeremy@xinsere.demo", "jeremy", "Jeremy Katz"),
            ("joshua@xinsere.demo", "joshua", "Joshua Katz"),
        ]
        with self._conn() as c:
            have = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if have:
            return
        for email, username, name in seeds:
            try:
                self.create_user(email, "xinsere", name, username=username)
            except ValueError:
                pass


USERS_DB = UserDB()
