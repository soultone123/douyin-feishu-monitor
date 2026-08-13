"""Douyin direct-message webhook -> Feishu bot broadcaster.

Runs with only the Python standard library so it can be deployed on a small
VM or container without a dependency installation step.
"""

from __future__ import annotations

import base64
from contextlib import closing
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env_file(ROOT / ".env")
DB_PATH = Path(os.getenv("DB_PATH", str(ROOT / "data" / "messages.db")))
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8080"))
DOUYIN_CLIENT_SECRET = os.getenv("DOUYIN_CLIENT_SECRET", "")
FEISHU_WEBHOOK_URL = os.getenv("FEISHU_WEBHOOK_URL", "")
FEISHU_SIGN_SECRET = os.getenv("FEISHU_SIGN_SECRET", "")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", "1048576"))
logger = logging.getLogger("douyin-feishu")
db_lock = threading.Lock()


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(DB_PATH)) as db, db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute(
            """CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dedupe_key TEXT NOT NULL UNIQUE,
                event TEXT NOT NULL,
                from_user_id TEXT,
                to_user_id TEXT,
                message_text TEXT,
                raw_json TEXT NOT NULL,
                received_at TEXT NOT NULL,
                feishu_sent INTEGER NOT NULL DEFAULT 0,
                feishu_error TEXT,
                delivery_attempts INTEGER NOT NULL DEFAULT 0
            )"""
        )
        columns = {row[1] for row in db.execute("PRAGMA table_info(messages)")}
        if "delivery_attempts" not in columns:
            db.execute("ALTER TABLE messages ADD COLUMN delivery_attempts INTEGER NOT NULL DEFAULT 0")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def local_now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def verify_douyin_signature(body: bytes, signature: str) -> bool:
    """Douyin signs SHA1(client_secret + complete request body)."""
    if not DOUYIN_CLIENT_SECRET:
        return os.getenv("ALLOW_UNSIGNED_DOUYIN", "0") == "1"
    expected = hashlib.sha1(DOUYIN_CLIENT_SECRET.encode() + body).hexdigest()
    return bool(signature) and hmac.compare_digest(expected, signature.strip())


def feishu_signature(timestamp: int) -> str:
    string_to_sign = f"{timestamp}\n{FEISHU_SIGN_SECRET}"
    digest = hmac.new(string_to_sign.encode(), digestmod=hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


def parse_json_content(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return value
    return value


def extract_message_text(payload: dict[str, Any]) -> str:
    content: Any = parse_json_content(payload.get("content", {}))
    candidates: list[Any] = []
    if isinstance(content, dict):
        candidates.extend([content.get("text"), content.get("message"), content.get("content")])
        nested = parse_json_content(content.get("data"))
        if isinstance(nested, dict):
            candidates.extend([nested.get("text"), nested.get("message")])
    elif content:
        candidates.append(content)
    for candidate in candidates:
        if isinstance(candidate, (dict, list)):
            return json.dumps(candidate, ensure_ascii=False)
        if candidate is not None and str(candidate).strip():
            return str(candidate).strip()
    return "[非文本私信]"


def send_to_feishu(message: str) -> None:
    if not FEISHU_WEBHOOK_URL:
        raise RuntimeError("FEISHU_WEBHOOK_URL is not configured")
    payload: dict[str, Any] = {"msg_type": "text", "content": {"text": message}}
    if FEISHU_SIGN_SECRET:
        timestamp = int(time.time())
        payload["timestamp"] = str(timestamp)
        payload["sign"] = feishu_signature(timestamp)
    request = Request(
        FEISHU_WEBHOOK_URL,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=8) as response:
        result = json.loads(response.read().decode("utf-8"))
    if result.get("code", 0) != 0 or result.get("StatusCode", 0) not in (0, None):
        raise RuntimeError(f"Feishu webhook rejected message: {result}")


def format_feishu_message(payload: dict[str, Any], text: str) -> str:
    event = payload.get("event", "im_receive_msg")
    sender = payload.get("from_user_id") or "未知用户"
    receiver = payload.get("to_user_id") or "当前账号"
    return "\n".join(
        [
            "【抖音新私信】",
            f"时间：{local_now()}",
            f"发送人：{sender}",
            f"接收账号：{receiver}",
            f"事件：{event}",
            f"内容：{text}",
        ]
    )


def save_message(payload: dict[str, Any], body: bytes, header_msg_id: str = "") -> tuple[int, bool]:
    raw_id = header_msg_id or payload.get("msg_id") or payload.get("log_id") or payload.get("event_id")
    dedupe_key = str(raw_id or hashlib.sha256(body).hexdigest())
    text = extract_message_text(payload)
    with db_lock, closing(sqlite3.connect(DB_PATH)) as db, db:
        try:
            cursor = db.execute(
                """INSERT INTO messages
                (dedupe_key,event,from_user_id,to_user_id,message_text,raw_json,received_at)
                VALUES (?,?,?,?,?,?,?)""",
                (
                    dedupe_key,
                    str(payload.get("event", "")),
                    str(payload.get("from_user_id", "")),
                    str(payload.get("to_user_id", "")),
                    text,
                    json.dumps(payload, ensure_ascii=False),
                    utc_now(),
                ),
            )
            return cursor.lastrowid, True
        except sqlite3.IntegrityError:
            row = db.execute("SELECT id FROM messages WHERE dedupe_key=?", (dedupe_key,)).fetchone()
            return int(row[0]), False


def mark_feishu(message_id: int, sent: bool, error: str = "") -> None:
    with db_lock, closing(sqlite3.connect(DB_PATH)) as db, db:
        db.execute(
            "UPDATE messages SET feishu_sent=?, feishu_error=?, delivery_attempts=delivery_attempts+1 WHERE id=?",
            (int(sent), error[:500], message_id),
        )


def deliver_message(message_id: int, payload: dict[str, Any]) -> None:
    try:
        text = extract_message_text(payload)
        send_to_feishu(format_feishu_message(payload, text))
        mark_feishu(message_id, True)
    except Exception as exc:
        logger.exception("Feishu broadcast failed")
        mark_feishu(message_id, False, str(exc))


def retry_failed_messages() -> None:
    while True:
        time.sleep(60)
        with db_lock, closing(sqlite3.connect(DB_PATH)) as db:
            rows = db.execute(
                """SELECT id,raw_json FROM messages
                WHERE feishu_sent=0 AND delivery_attempts BETWEEN 0 AND 4
                ORDER BY id LIMIT 20"""
            ).fetchall()
        for message_id, raw_json in rows:
            try:
                payload = json.loads(raw_json)
            except json.JSONDecodeError:
                mark_feishu(message_id, False, "stored payload is invalid JSON")
                continue
            deliver_message(message_id, payload)


def list_messages(limit: int = 100) -> list[dict[str, Any]]:
    with db_lock, closing(sqlite3.connect(DB_PATH)) as db, db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            """SELECT id,event,from_user_id,to_user_id,message_text,received_at,
            feishu_sent,feishu_error,delivery_attempts FROM messages ORDER BY id DESC LIMIT ?""",
            (max(1, min(limit, 500)),),
        ).fetchall()
    return [dict(row) for row in rows]


def authorized(handler: BaseHTTPRequestHandler) -> bool:
    if not ADMIN_TOKEN:
        return True
    token = handler.headers.get("X-Admin-Token", "")
    if hmac.compare_digest(token, ADMIN_TOKEN):
        return True
    auth = handler.headers.get("Authorization", "")
    if auth.startswith("Basic "):
        try:
            username, password = base64.b64decode(auth[6:]).decode().split(":", 1)
            return username == "admin" and hmac.compare_digest(password, ADMIN_TOKEN)
        except (ValueError, UnicodeDecodeError):
            return False
    return False


class Handler(BaseHTTPRequestHandler):
    server_version = "DouyinFeishuMonitor/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        logger.info("%s - %s", self.address_string(), fmt % args)

    def send_json(self, data: Any, status: int = 200) -> None:
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def send_unauthorized(self) -> None:
        raw = b'{"error":"unauthorized"}'
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Douyin monitor"')
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.send_json({"ok": True, "service": "douyin-feishu-monitor"})
        elif self.path == "/api/messages":
            if not authorized(self):
                self.send_unauthorized()
            else:
                self.send_json({"messages": list_messages()})
        elif self.path in ("/", "/index.html"):
            if ADMIN_TOKEN and not authorized(self):
                self.send_unauthorized()
            else:
                page = (ROOT / "static" / "index.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(page)))
                self.end_headers()
                self.wfile.write(page)
        else:
            self.send_json({"error": "not_found"}, 404)

    def do_POST(self) -> None:
        if self.path != "/douyin/webhook":
            self.send_json({"error": "not_found"}, 404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_BODY_BYTES:
            self.send_json({"error": "payload_too_large"}, 413)
            return
        body = self.rfile.read(length)
        if not verify_douyin_signature(body, self.headers.get("X-Douyin-Signature", "")):
            self.send_json({"error": "invalid_signature"}, 401)
            return
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_json({"error": "invalid_json"}, 400)
            return
        if payload.get("event") == "verify_webhook":
            challenge = payload.get("content", {}).get("challenge")
            self.send_json({"challenge": challenge})
            return
        if payload.get("event") not in ("im_receive_msg", "im_send_msg", "im_enter_direct_msg"):
            self.send_json({"ok": True, "ignored": True})
            return
        message_id, inserted = save_message(payload, body, self.headers.get("Msg-Id", ""))
        if not inserted:
            self.send_json({"ok": True, "duplicate": True})
            return
        threading.Thread(target=deliver_message, args=(message_id, payload), daemon=True).start()
        self.send_json({"ok": True, "message_id": message_id})


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    init_db()
    threading.Thread(target=retry_failed_messages, daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    logger.info("listening on %s:%s", HOST, PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
