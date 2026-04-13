import datetime
import os
import sqlite3


def _resolve_db_path(db_path: str) -> str:
    if not isinstance(db_path, str) or not db_path:
        raise RuntimeError(
            "Invalid database path: db_path must be a non-empty string ending in '.db'."
        )

    base = os.path.dirname(os.path.abspath(__file__))
    abs_path = os.path.normpath(os.path.join(base, db_path))
    allowed_root = os.path.dirname(base)

    if not db_path.lower().endswith(".db"):
        raise RuntimeError("Invalid database path: db_path must end with '.db'.")

    # Allow paths under base and up to one level above base; reject deeper traversal.
    if not (abs_path == allowed_root or abs_path.startswith(allowed_root + os.sep)):
        raise RuntimeError(
            "Invalid database path: resolved path cannot go more than one directory "
            "level above module base."
        )

    if not os.path.isfile(abs_path):
        raise RuntimeError(f"Database file not found: {abs_path}")

    return abs_path


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_all_devices(db_path: str) -> list[dict]:
    resolved_path = _resolve_db_path(db_path)

    try:
        with sqlite3.connect(resolved_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, ip, mac, vendor FROM devices")
            rows = cursor.fetchall()
    except sqlite3.Error as exc:
        raise RuntimeError(f"Failed to read devices from database: {exc}") from exc

    return [
        {"id": row[0], "ip": row[1], "mac": row[2], "vendor": row[3]}
        for row in rows
    ]


def start_session(db_path: str, device_id: int) -> int:
    resolved_path = _resolve_db_path(db_path)
    started_at = _utc_now_iso()

    try:
        with sqlite3.connect(resolved_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO sessions (device_id, start_time, end_time) VALUES (?, ?, NULL)",
                (device_id, started_at),
            )
            session_id = cursor.lastrowid
    except sqlite3.Error as exc:
        raise RuntimeError(f"Failed to start session in database: {exc}") from exc

    if session_id is None:
        raise RuntimeError("Failed to start session: no session id returned.")

    return int(session_id)


def end_session(db_path: str, session_id: int) -> None:
    resolved_path = _resolve_db_path(db_path)
    ended_at = _utc_now_iso()

    try:
        with sqlite3.connect(resolved_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE sessions SET end_time = ? WHERE id = ?",
                (ended_at, session_id),
            )
    except sqlite3.Error as exc:
        raise RuntimeError(f"Failed to end session in database: {exc}") from exc