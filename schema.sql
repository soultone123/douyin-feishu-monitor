CREATE TABLE IF NOT EXISTS messages (
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
);

CREATE INDEX IF NOT EXISTS idx_messages_received_at ON messages(received_at DESC);
