const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function timingSafeEqual(left, right) {
  if (left.length !== right.length) return false;
  let result = 0;
  for (let i = 0; i < left.length; i += 1) {
    result |= left.charCodeAt(i) ^ right.charCodeAt(i);
  }
  return result === 0;
}

async function digestHex(algorithm, value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest(algorithm, bytes);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function verifyDouyinSignature(body, signature, secret) {
  if (!secret || !signature) return false;
  const expected = await digestHex("SHA-1", secret + body);
  return timingSafeEqual(expected, signature.trim().toLowerCase());
}

function parseJsonValue(value) {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

export function extractMessageText(payload) {
  const content = parseJsonValue(payload.content ?? {});
  const candidates = [];
  if (content && typeof content === "object" && !Array.isArray(content)) {
    candidates.push(content.text, content.message, content.content);
    const nested = parseJsonValue(content.data);
    if (nested && typeof nested === "object" && !Array.isArray(nested)) {
      candidates.push(nested.text, nested.message, nested.content);
    }
  } else if (content) {
    candidates.push(content);
  }
  for (const candidate of candidates) {
    if (candidate && typeof candidate === "object") return JSON.stringify(candidate);
    if (candidate != null && String(candidate).trim()) return String(candidate).trim();
  }
  return "[非文本私信]";
}

function formatLocalTime() {
  return new Intl.DateTimeFormat("zh-CN", {
    timeZone: "Asia/Shanghai",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date());
}

export function formatWeComMessage(payload) {
  const sender = payload.from_user_id || "未知用户";
  const receiver = payload.to_user_id || "当前账号";
  return [
    "【抖音新私信】",
    `时间：${formatLocalTime()}`,
    `发送人：${sender}`,
    `接收账号：${receiver}`,
    `内容：${extractMessageText(payload)}`,
  ].join("\n");
}

async function sendToWeCom(env, payload) {
  if (!env.WEWORK_WEBHOOK_URL) throw new Error("WEWORK_WEBHOOK_URL is not configured");
  const outgoing = {
    msgtype: "text",
    text: { content: formatWeComMessage(payload) },
  };
  const response = await fetch(env.WEWORK_WEBHOOK_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(outgoing),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || (result.errcode ?? 0) !== 0) {
    throw new Error(`WeCom rejected message: HTTP ${response.status} ${JSON.stringify(result)}`);
  }
}

async function reserveMessage(env, dedupeKey, payload, rawBody) {
  const result = await env.DB.prepare(
    `INSERT OR IGNORE INTO messages
      (dedupe_key, event, from_user_id, to_user_id, message_text, raw_json, received_at)
     VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
  )
    .bind(
      dedupeKey,
      String(payload.event || ""),
      String(payload.from_user_id || ""),
      String(payload.to_user_id || ""),
      extractMessageText(payload),
      rawBody,
    )
    .run();
  return result.meta.changes > 0;
}

async function markDelivery(env, dedupeKey, sent, error = "") {
  await env.DB.prepare(
    `UPDATE messages
     SET feishu_sent = ?, feishu_error = ?, delivery_attempts = delivery_attempts + 1
     WHERE dedupe_key = ?`,
  ).bind(sent ? 1 : 0, error.slice(0, 500), dedupeKey).run();
}

async function deliverAndRecord(env, dedupeKey, payload) {
  try {
    await sendToWeCom(env, payload);
    await markDelivery(env, dedupeKey, true);
  } catch (error) {
    await markDelivery(env, dedupeKey, false, error instanceof Error ? error.message : String(error));
    throw error;
  }
}

function getChallenge(payload) {
  const content = parseJsonValue(payload.content);
  if (content && typeof content === "object") {
    return content.challenge ?? content.CHALLENGE;
  }
  return payload.challenge ?? payload.CHALLENGE;
}

async function handleWebhook(request, env, ctx) {
  const rawBody = await request.text();
  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return json({ error: "invalid_json" }, 400);
  }

  if (payload.event === "verify_webhook") {
    return json({ challenge: getChallenge(payload) });
  }
  const signature = request.headers.get("x-douyin-signature") || "";
  if (!(await verifyDouyinSignature(rawBody, signature, env.DOUYIN_CLIENT_SECRET))) {
    return json({ error: "invalid_signature" }, 401);
  }
  if (payload.event !== "im_receive_msg") {
    return json({ ok: true, ignored: true });
  }

  const headerId = request.headers.get("msg-id");
  const dedupeKey = String(
    headerId || payload.msg_id || payload.log_id || payload.event_id || await digestHex("SHA-256", rawBody),
  );
  const inserted = await reserveMessage(env, dedupeKey, payload, rawBody);
  if (!inserted) return json({ ok: true, duplicate: true });

  ctx.waitUntil(deliverAndRecord(env, dedupeKey, payload));
  return json({ ok: true });
}

async function listMessages(request, env) {
  if (!env.ADMIN_TOKEN) return json({ error: "ADMIN_TOKEN is not configured" }, 503);
  const token = request.headers.get("x-admin-token") || "";
  if (!timingSafeEqual(token, env.ADMIN_TOKEN)) return json({ error: "unauthorized" }, 401);
  const { results } = await env.DB.prepare(
    `SELECT id, event, from_user_id, to_user_id, message_text, received_at,
            feishu_sent, feishu_error, delivery_attempts
     FROM messages ORDER BY id DESC LIMIT 100`,
  ).all();
  return json({ messages: results });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/healthz") {
      return json({ ok: true, service: "douyin-feishu-monitor" });
    }
    if (request.method === "GET" && url.pathname === "/") {
      return new Response("抖音私信转飞书服务运行正常", {
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }
    if (request.method === "GET" && url.pathname === "/api/messages") {
      return listMessages(request, env);
    }
    if (request.method === "POST" && url.pathname === "/douyin/webhook") {
      return handleWebhook(request, env, ctx);
    }
    return json({ error: "not_found" }, 404);
  },
};
