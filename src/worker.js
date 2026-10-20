/**
 * Telegram Web Bot – Cloudflare Worker (여러 봇 지원)
 *
 * 필요한 설정 (Worker → Settings → Variables and Secrets / Bindings):
 *   Secret  BOT_TOKEN       : 기본 텔레그램 봇 토큰 (첫 번째 탭, 제거 불가)
 *   Secret  PIN             : 접속 PIN 번호
 *   Secret  SESSION_SECRET  : (선택) 세션 서명 / 추가 봇 토큰 암호화용 임의 문자열. 없으면 BOT_TOKEN(+PIN) 으로 파생
 *   KV      BANS            : PIN 실패 횟수 / IP 차단 저장용 KV namespace
 *   D1      DB              : 메시지 저장(봇·대화방마다 최근 N개 – 환경 변수 KEEP_PER_CHAT, 1~1000, 없으면 20) + 추가 봇 목록(토큰은 AES-GCM 암호화)
 *   RateLimit RL            : (선택) Workers Rate Limiting 바인딩 (비로그인 요청에 적용)
 *
 * 코드/HTML 어디에도 토큰과 PIN 은 들어있지 않으며, 모두 서버(Worker) 쪽에서만 사용됩니다.
 * 웹 화면에서 추가한 봇 토큰도 브라우저로 다시 내려보내지 않습니다.
 * 파일 업로드/다운로드는 Worker 가 스트리밍으로 중계하므로 브라우저에 토큰이 노출되지 않습니다.
 */

const COOKIE = "tgw_sess";
const SESSION_TTL = 12 * 3600;      // 세션 12시간
const MAX_FAIL = 5;                 // PIN 5회 실패 시
const BAN_SEC = 3600;               // 1시간 차단
const RPM_ANON = 60;                // 비로그인 IP 당 분당 최대 요청 (isolate 단위)
const RPM_AUTH = 300;               // 로그인 IP 당 분당 최대 요청 (이미지 미리보기 고려)
const MAX_UP = 50 * 1024 * 1024;    // 봇 업로드 한도 50MB
const IMG_TYPES = { jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", webp: "image/webp", gif: "image/gif" };

// ---------- 메모리 기반 간이 rate limit / KV 미설정 시 대체 저장소 ----------
const memHits = new Map();
const memStore = new Map();

function memRateOk(ip, limit) {
  const now = Date.now();
  let e = memHits.get(ip);
  if (!e || now - e.t > 60000) { e = { t: now, n: 0 }; memHits.set(ip, e); }
  e.n++;
  if (memHits.size > 5000) memHits.clear();
  return e.n <= limit;
}

async function kvGet(env, k) {
  if (env.BANS) return env.BANS.get(k);
  const v = memStore.get(k);
  if (!v) return null;
  if (v.exp < Date.now()) { memStore.delete(k); return null; }
  return v.val;
}
async function kvPut(env, k, val, ttl) {
  if (env.BANS) return env.BANS.put(k, val, { expirationTtl: Math.max(60, ttl) });
  memStore.set(k, { val, exp: Date.now() + ttl * 1000 });
}
async function kvDel(env, k) {
  if (env.BANS) return env.BANS.delete(k);
  memStore.delete(k);
}

// ---------- crypto helpers ----------
const enc = new TextEncoder();
async function hmacKey(env) {
  const secret = env.SESSION_SECRET || `${env.BOT_TOKEN}|${env.PIN}|tgw`;
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}
async function hmacHex(env, msg) {
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(env), enc.encode(msg));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}
function safeEq(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function makeSession(env, ttl = SESSION_TTL, kind = "s") {  // kind: s = PIN 세션, o = 텔레그램 승인(임시) 세션
  const exp = Math.floor(Date.now() / 1000) + ttl;
  return kind === "o" ? `${exp}.o.${await hmacHex(env, "o:" + exp)}` : `${exp}.${await hmacHex(env, "s:" + exp)}`;
}
async function validSession(env, req) {
  if (!env.BOT_TOKEN || !env.PIN) return false;
  const m = (req.headers.get("Cookie") || "").match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  if (!m) return false;
  const parts = m[1].split(".");
  const exp = parts[0], kind = parts.length === 3 ? parts[1] : "s", sig = parts[parts.length - 1];
  if (!exp || !sig || (kind !== "s" && kind !== "o") || Number(exp) < Date.now() / 1000) return false;
  return safeEq(sig, await hmacHex(env, kind + ":" + exp)) ? { kind, exp: Number(exp) } : false;
}
// 추가 봇 토큰 암호화 (AES-GCM). PIN 을 바꿔도 복호화되도록 PIN 은 키에 넣지 않음
async function aesKey(env) {
  const raw = await crypto.subtle.digest("SHA-256", enc.encode("botkey|" + (env.SESSION_SECRET || env.BOT_TOKEN)));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
const b64 = (u8) => btoa(String.fromCharCode(...u8));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
async function encToken(env, token) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(env), enc.encode(token)));
  return b64(iv) + "." + b64(ct);
}
async function decToken(env, s) {
  const [iv, ct] = String(s).split(".");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, await aesKey(env), unb64(ct));
  return new TextDecoder().decode(pt);
}

// ---------- response helpers ----------
const SEC_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store",
};
function json(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj), {
    status, headers: { "Content-Type": "application/json; charset=utf-8", ...SEC_HEADERS, ...extra },
  });
}
function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy":
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data: blob:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
      ...SEC_HEADERS,
    },
  });
}

// ---------- telegram ----------
async function tg(token, method, params) {
  const r = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params || {}),
  });
  return r.json().catch(() => ({ ok: false, description: "HTTP " + r.status }));
}
function nameOf(u) {
  if (!u) return "";
  return [u.first_name, u.last_name].filter(Boolean).join(" ") || u.title || u.username || String(u.id);
}
function fileOf(m) {
  const f = (o, kind, name, thumb) => ({
    id: o.file_id, kind, name: o.file_name || name, size: o.file_size || 0, mime: o.mime_type || "",
    thumb: thumb || (o.thumbnail && o.thumbnail.file_id) || (o.thumb && o.thumb.file_id) || "",
  });
  const id = m.message_id;
  if (m.photo && m.photo.length) {
    const big = m.photo[m.photo.length - 1];
    const th = [...m.photo].reverse().find(p => p.width <= 800 && p.height <= 800) || m.photo[0];
    return f(big, "photo", `photo_${id}.jpg`, th.file_id);
  }
  if (m.sticker) {
    const s = m.sticker, ext = s.is_animated ? "tgs" : s.is_video ? "webm" : "webp";
    return f(s, "sticker", `sticker_${id}.${ext}`, ext === "webp" ? s.file_id : "");
  }
  if (m.animation) return f(m.animation, "animation", `animation_${id}.mp4`);
  if (m.video) return f(m.video, "video", `video_${id}.mp4`);
  if (m.video_note) return f(m.video_note, "video_note", `videonote_${id}.mp4`);
  if (m.audio) return f(m.audio, "audio", (m.audio.title || `audio_${id}`) + ".mp3");
  if (m.voice) return f(m.voice, "voice", `voice_${id}.ogg`);
  if (m.document) return f(m.document, "document", `file_${id}`);
  return null;
}
function describe(m) {
  if (m.text) return m.text;
  const kind = m.location ? "위치" : m.contact ? "연락처" : m.poll ? "투표"
    : m.new_chat_members ? "새 참여자: " + m.new_chat_members.map(nameOf).join(", ")
    : m.left_chat_member ? "퇴장: " + nameOf(m.left_chat_member) : "기타 메시지";
  return `[${kind}]` + (m.caption ? " " + m.caption : "");
}
function slimMsg(m, edited) {
  const file = fileOf(m);
  return {
    message_id: m.message_id,
    date: m.date,
    edited: !!edited,
    chat: { id: m.chat.id, type: m.chat.type, title: m.chat.title || nameOf(m.chat) },
    from: m.from ? { id: m.from.id, name: nameOf(m.from), username: m.from.username || "", is_bot: !!m.from.is_bot }
      : { id: m.chat.id, name: m.author_signature || m.chat.title || "", username: "", is_bot: false },
    text: file ? (m.caption || "") : describe(m),
    file,
  };
}

// ---------- D1 (메시지: 봇·대화방마다 최근 KEEP_PER_CHAT 개만 유지 / 추가 봇 목록) ----------
const KEEP_DEFAULT = 20; const keepN = (env) => { const n = parseInt(env.KEEP_PER_CHAT, 10); return n >= 1 && n <= 1000 ? n : KEEP_DEFAULT; };  // 환경 변수 KEEP_PER_CHAT (1~1000) 이 없거나 잘못되면 20
let dbDone = false;
// 주의: 진행 중인 Promise 를 요청끼리 공유하면 먼저 시작한 요청이 끝날 때 멈출 수 있으므로 완료 여부만 기억
async function dbInit(env) {
  if (dbDone) return;
  const DB = env.DB;
  await DB.prepare("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id TEXT NOT NULL, message_id INTEGER NOT NULL, date INTEGER NOT NULL, data TEXT NOT NULL, bot TEXT NOT NULL DEFAULT 'main')").run();
  const { results } = await DB.prepare("PRAGMA table_info(messages)").all();
  if (!results.some((c) => c.name === "bot")) {
    try { await DB.prepare("ALTER TABLE messages ADD COLUMN bot TEXT NOT NULL DEFAULT 'main'").run(); }
    catch (e) { if (!/duplicate column/i.test(String(e && e.message))) throw e; }
  }
  await DB.batch([
    DB.prepare("DROP INDEX IF EXISTS idx_msg_chat"),
    DB.prepare("DROP INDEX IF EXISTS idx_msg_uniq"),
    DB.prepare("CREATE INDEX IF NOT EXISTS idx_msg_bot_chat ON messages (bot, chat_id, id)"),
    DB.prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_msg_bot_uniq ON messages (bot, chat_id, message_id) WHERE message_id > 0"),
    DB.prepare("CREATE TABLE IF NOT EXISTS bots (id TEXT PRIMARY KEY, token_enc TEXT NOT NULL, name TEXT, username TEXT, created INTEGER)"), DB.prepare("CREATE TABLE IF NOT EXISTS auth_req (id TEXT PRIMARY KEY, st TEXT NOT NULL, code TEXT, exp INTEGER NOT NULL)"),
  ]);
  dbDone = true;
}
async function dbSave(env, bot, msgs) {
  if (!env.DB || !msgs || !msgs.length) return;
  try {
    await dbInit(env);
    const st = [], chats = new Set();
    for (const m of msgs) {
      const cid = String(m.chat.id);
      chats.add(cid);
      if (m.edited) {
        if (m.message_id) st.push(env.DB.prepare("UPDATE messages SET data = json_set(data, '$.text', ?) WHERE bot = ? AND chat_id = ? AND message_id = ?").bind((m.text || "") + " (수정됨)", bot, cid, m.message_id));
      } else {
        st.push(env.DB.prepare("INSERT OR IGNORE INTO messages (bot, chat_id, message_id, date, data) VALUES (?, ?, ?, ?, ?)").bind(bot, cid, m.message_id || 0, m.date || 0, JSON.stringify(m)));
      }
    }
    for (const cid of chats)
      st.push(env.DB.prepare("DELETE FROM messages WHERE bot = ? AND chat_id = ? AND id NOT IN (SELECT id FROM messages WHERE bot = ? AND chat_id = ? ORDER BY id DESC LIMIT ?)").bind(bot, cid, bot, cid, keepN(env)));
    if (st.length) await env.DB.batch(st);
  } catch (e) { console.log("D1 save error:", e && e.message); }
}

// ---------- 봇 선택 ----------
const botCache = new Map();   // id -> { token, t }  (다른 isolate 에서 제거된 봇 반영을 위해 60초만 캐시)
let mainInfo = null;
function botIdOf(v) {
  const s = String(v || "main");
  return s === "main" || /^\d{1,20}$/.test(s) ? s : null;
}
async function botToken(env, id) {
  if (id === "main") return env.BOT_TOKEN;
  if (!env.DB) return null;
  const c = botCache.get(id);
  if (c && Date.now() - c.t < 60000) return c.token;
  await dbInit(env);
  const row = await env.DB.prepare("SELECT token_enc FROM bots WHERE id = ?").bind(id).first();
  if (!row) { botCache.delete(id); return null; }
  const token = await decToken(env, row.token_enc);
  botCache.set(id, { token, t: Date.now() });
  return token;
}
async function needBot(env, v) {
  const id = botIdOf(v);
  if (!id) return null;
  const token = await botToken(env, id).catch(() => null);
  return token ? { id, token } : null;
}
const NO_BOT = () => json({ ok: false, error: "봇을 찾을 수 없습니다. 새로고침 후 다시 시도하세요." }, 404);
async function mainBot(env) {
  if (mainInfo) return mainInfo;
  const r = await tg(env.BOT_TOKEN, "getMe");
  if (!r.ok) return { tgid: "", name: "기본 봇", username: "", error: r.description };
  mainInfo = { tgid: String(r.result.id), name: r.result.first_name || "기본 봇", username: r.result.username || "" };
  return mainInfo;
}
async function handleBots(env, sess) {
  const m = await mainBot(env);
  const list = [{ id: "main", name: m.name, username: m.username, main: true }];
  if (env.DB) {
    try {
      await dbInit(env);
      const { results } = await env.DB.prepare("SELECT id, name, username FROM bots ORDER BY created, id").all();
      for (const b of results) list.push({ id: b.id, name: b.name || b.username || b.id, username: b.username || "" });
    } catch (e) { return json({ ok: false, error: "DB 오류: " + (e && e.message) }, 500); }
  }
  return json({ ok: true, db: !!env.DB, keep: keepN(env), limited: !!(sess && sess.kind === "o"), session_exp: sess ? sess.exp : 0, bots: list });
}
async function handleBotAdd(req, env) {
  if (!env.DB) return json({ ok: false, error: "봇 추가에는 D1(DB) 바인딩이 필요합니다." }, 400);
  let b = {};
  try { b = await req.json(); } catch { }
  const token = String(b.token || "").trim();
  if (!/^\d{5,20}:[A-Za-z0-9_-]{30,64}$/.test(token))
    return json({ ok: false, error: "토큰 형식이 올바르지 않습니다. (예: 123456789:AAH...)" }, 400);
  const r = await tg(token, "getMe");
  if (!r.ok) return json({ ok: false, error: "토큰 확인 실패: " + (r.description || "") }, 400);
  const id = String(r.result.id);
  const m = await mainBot(env);
  if (id === m.tgid) return json({ ok: false, error: "기본 봇과 같은 봇입니다." }, 400);
  const name = r.result.first_name || r.result.username || id, username = r.result.username || "";
  try {
    await dbInit(env);
    await env.DB.prepare("INSERT INTO bots (id, token_enc, name, username, created) VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET token_enc = excluded.token_enc, name = excluded.name, username = excluded.username")
      .bind(id, await encToken(env, token), name, username, Math.floor(Date.now() / 1000)).run();
  } catch (e) { return json({ ok: false, error: "DB 오류: " + (e && e.message) }, 500); }
  botCache.delete(id);
  return json({ ok: true, bot: { id, name, username } });
}
async function handleBotRemove(req, env) {
  let b = {};
  try { b = await req.json(); } catch { }
  const id = botIdOf(b.id);
  if (!id || id === "main") return json({ ok: false, error: "기본 봇은 제거할 수 없습니다." }, 400);
  if (!env.DB) return json({ ok: false, error: "D1(DB) 바인딩이 없습니다." }, 400);
  try {
    await dbInit(env);
    await env.DB.batch([
      env.DB.prepare("DELETE FROM bots WHERE id = ?").bind(id),
      env.DB.prepare("DELETE FROM messages WHERE bot = ?").bind(id),
    ]);
  } catch (e) { return json({ ok: false, error: "DB 오류: " + (e && e.message) }, 500); }
  botCache.delete(id);
  return json({ ok: true });
}

// ---------- 기록 조회 / 삭제 ----------
async function handleHistory(url, env, sess) {
  if (sess && sess.kind === "o") return json({ ok: true, db: true, limited: true, messages: [] });  // 임시 세션에는 서버 기록을 보여주지 않음
  const bot = botIdOf(url.searchParams.get("bot"));
  if (!bot) return NO_BOT();
  if (!env.DB) return json({ ok: true, db: false, messages: [] });
  try {
    await dbInit(env);
    const { results } = await env.DB.prepare("SELECT data FROM messages WHERE bot = ? ORDER BY chat_id, id").bind(bot).all();
    return json({ ok: true, db: true, messages: results.map((r) => JSON.parse(r.data)) });
  } catch (e) { return json({ ok: false, error: "DB 오류: " + (e && e.message) }, 500); }
}
async function handleDelete(req, env) {
  let b = {};
  try { b = await req.json(); } catch { }
  const bot = botIdOf(b.bot);
  const cid = String(b.chat_id ?? "");
  if (!bot) return NO_BOT();
  if (!/^-?\d+$/.test(cid)) return json({ ok: false, error: "chat_id 확인" }, 400);
  if (!env.DB) return json({ ok: true, db: false });
  try {
    await dbInit(env);
    if (b.all) await env.DB.prepare("DELETE FROM messages WHERE bot = ? AND chat_id = ?").bind(bot, cid).run();
    else await env.DB.prepare("DELETE FROM messages WHERE bot = ? AND chat_id = ? AND message_id = ? AND date = ?").bind(bot, cid, Number(b.message_id) || 0, Number(b.date) || 0).run();
    return json({ ok: true, db: true });
  } catch (e) { return json({ ok: false, error: "DB 오류: " + (e && e.message) }, 500); }
}

// ---------- 텔레그램 승인 로그인 (AUTHBOT_TOKEN 봇으로 허가 요청 → 허가하면 ONETIME_SESSION_SEC 초짜리 세션) ----------
// 필요: Secret AUTHBOT_TOKEN, Variable AUTH_CHAT_ID(허가할 텔레그램 사용자 ID), Variable ONETIME_SESSION_SEC(허가 대기·세션 시간, 초), D1 DB
const NL = String.fromCharCode(10);
const onetimeSec = (env) => { const n = parseInt(env.ONETIME_SESSION_SEC, 10); return n >= 10 && n <= 86400 ? n : 120; };
const authChat = (env) => String(env.AUTH_CHAT_ID || "").trim();
const randHex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, "0")).join("");
const okAuthId = (id) => typeof id === "string" && id.length === 32 && !/[^0-9a-f]/.test(id);
let hookSetFor = "";
async function hookSecret(env) { return (await hmacHex(env, "authhook")).slice(0, 48); }
async function ensureAuthHook(env, origin) {
  const url = origin + "/api/authhook";
  // 미리보기 주소와 실제 주소를 오갈 수 있으므로 요청마다 웹훅 주소를 현재 주소로 맞춤
  const r = await tg(env.AUTHBOT_TOKEN, "setWebhook", { url, secret_token: await hookSecret(env), allowed_updates: ["callback_query"] });
  if (r.ok) hookSetFor = url;
  return r.ok;
}
async function handleAuthRequest(req, env, ip, url) {
  if (!env.AUTHBOT_TOKEN || !authChat(env) || !env.DB) return json({ ok: false, error: "텔레그램 승인 로그인이 설정되지 않았습니다 (AUTHBOT_TOKEN / AUTH_CHAT_ID / DB)." }, 500);
  const now = Math.floor(Date.now() / 1000);
  const banUntil = Number(await kvGet(env, "ban:" + ip) || 0);
  if (banUntil > now) return json({ ok: false, banned: true, retry_after: banUntil - now }, 429);
  const cntKey = "areq:" + ip, cnt = Number(await kvGet(env, cntKey) || 0);
  if (cnt >= 5) return json({ ok: false, error: "승인 요청이 너무 많습니다. 10분 후 다시 시도하세요." }, 429);
  await kvPut(env, cntKey, String(cnt + 1), 600);
  if (!(await ensureAuthHook(env, url.origin))) return json({ ok: false, error: "인증 봇 웹훅 설정 실패 (AUTHBOT_TOKEN 확인)" }, 502);
  const ttl = onetimeSec(env), id = randHex(16), code = randHex(2).toUpperCase();
  await dbInit(env);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM auth_req WHERE exp < ?").bind(now - 600),
    env.DB.prepare("INSERT INTO auth_req (id, st, code, exp) VALUES (?, 'pending', ?, ?)").bind(id, code, now + ttl),
  ]);
  const ua = (req.headers.get("User-Agent") || "").slice(0, 150);
  const when = new Date().toLocaleString("ko-KR", { timeZone: "Asia/Seoul" });
  const text = ["🔐 웹 로그인 승인 요청", "", "확인 코드: " + code, "IP: " + ip, "브라우저: " + ua, "시각: " + when, "",
    ttl + "초 안에 허가하지 않으면 만료됩니다. 직접 요청한 것이 아니면 거절하세요."].join(NL);
  const r = await tg(env.AUTHBOT_TOKEN, "sendMessage", { chat_id: authChat(env), text,
    reply_markup: { inline_keyboard: [[{ text: "✅ 허가하기", callback_data: "ok:" + id }, { text: "❌ 거절", callback_data: "no:" + id }]] } });
  if (!r.ok) {
    await env.DB.prepare("DELETE FROM auth_req WHERE id = ?").bind(id).run();
    return json({ ok: false, error: "텔레그램 전송 실패: " + (r.description || "") + " (인증 봇에게 먼저 /start 를 보냈는지 확인하세요)" }, 502);
  }
  return json({ ok: true, id, code, expires_in: ttl });
}
async function handleAuthStatus(url, env) {
  const id = url.searchParams.get("id") || "";
  if (!okAuthId(id) || !env.DB) return json({ ok: false, error: "bad id" }, 400);
  await dbInit(env);
  const now = Math.floor(Date.now() / 1000);
  const a = await env.DB.prepare("SELECT st, exp FROM auth_req WHERE id = ?").bind(id).first();
  if (!a) return json({ ok: true, status: "expired" });
  if (a.st === "approved") {
    const del = await env.DB.prepare("DELETE FROM auth_req WHERE id = ? AND st = 'approved'").bind(id).run();
    if (!del.meta || del.meta.changes !== 1) return json({ ok: true, status: "expired" });
    const ttl = onetimeSec(env), tok = await makeSession(env, ttl, "o");
    return json({ ok: true, status: "approved", session_sec: ttl }, 200,
      { "Set-Cookie": COOKIE + "=" + tok + "; Path=/; Max-Age=" + ttl + "; HttpOnly; Secure; SameSite=Strict" });
  }
  if (a.st === "denied") { await env.DB.prepare("DELETE FROM auth_req WHERE id = ?").bind(id).run(); return json({ ok: true, status: "denied" }); }
  if (a.exp < now) return json({ ok: true, status: "expired" });
  return json({ ok: true, status: "pending", remain: a.exp - now });
}
async function handleAuthHook(req, env) {
  if (!env.AUTHBOT_TOKEN || !env.DB || req.headers.get("X-Telegram-Bot-Api-Secret-Token") !== await hookSecret(env))
    return new Response("forbidden", { status: 403 });
  let u = {};
  try { u = await req.json(); } catch { }
  const q = u.callback_query;
  if (!q) return json({ ok: true });
  const answer = (text) => tg(env.AUTHBOT_TOKEN, "answerCallbackQuery", { callback_query_id: q.id, text });
  if (String(q.from && q.from.id) !== authChat(env)) { await answer("권한이 없습니다"); return json({ ok: true }); }
  const [act, id] = String(q.data || "").split(":");
  const now = Math.floor(Date.now() / 1000);
  let result = "⌛ 만료되었거나 이미 처리된 요청입니다";
  if (okAuthId(id) && (act === "ok" || act === "no")) {
    await dbInit(env);
    const up = await env.DB.prepare("UPDATE auth_req SET st = ? WHERE id = ? AND st = 'pending' AND exp >= ?").bind(act === "ok" ? "approved" : "denied", id, now).run();
    if (up.meta && up.meta.changes === 1) result = act === "ok" ? "✅ 허가했습니다" : "❌ 거절했습니다";
  }
  await answer(result);
  if (q.message) await tg(env.AUTHBOT_TOKEN, "editMessageText", { chat_id: q.message.chat.id, message_id: q.message.message_id, text: (q.message.text || "") + NL + NL + "→ " + result });
  return json({ ok: true });
}

// ---------- handlers ----------
async function handleLogin(req, env, ip) {
  const banKey = `ban:${ip}`, failKey = `fail:${ip}`;
  const banUntil = Number(await kvGet(env, banKey) || 0);
  const now = Math.floor(Date.now() / 1000);
  if (banUntil > now) return json({ ok: false, banned: true, retry_after: banUntil - now }, 429);

  let pin = "";
  try { pin = String((await req.json()).pin || "").trim(); } catch { }
  if (!env.PIN || !env.BOT_TOKEN) return json({ ok: false, error: "서버 설정(BOT_TOKEN/PIN)이 없습니다." }, 500);

  // 타이밍 공격 방지: 해시끼리 비교
  const ok = safeEq(await hmacHex(env, "p:" + pin), await hmacHex(env, "p:" + String(env.PIN)));
  if (ok) {
    await kvDel(env, failKey);
    const tok = await makeSession(env);
    return json({ ok: true }, 200, {
      "Set-Cookie": `${COOKIE}=${tok}; Path=/; Max-Age=${SESSION_TTL}; HttpOnly; Secure; SameSite=Strict`,
    });
  }
  const fails = Number(await kvGet(env, failKey) || 0) + 1;
  if (fails >= MAX_FAIL) {
    await kvPut(env, banKey, String(now + BAN_SEC), BAN_SEC);
    await kvDel(env, failKey);
    return json({ ok: false, banned: true, retry_after: BAN_SEC }, 429);
  }
  await kvPut(env, failKey, String(fails), BAN_SEC);
  return json({ ok: false, remaining: MAX_FAIL - fails }, 401);
}

async function handleUpdates(url, env) {
  const B = await needBot(env, url.searchParams.get("bot"));
  if (!B) return NO_BOT();
  const offset = Number(url.searchParams.get("offset") || 0);
  const r = await tg(B.token, "getUpdates", {
    offset: offset || undefined, timeout: 0, limit: 100,
    allowed_updates: ["message", "edited_message", "channel_post", "edited_channel_post", "my_chat_member"],
  });
  if (!r.ok) return json({ ok: false, error: r.description, code: r.error_code }, 502);
  const out = [];
  let next = offset;
  for (const u of r.result) {
    next = Math.max(next, u.update_id + 1);
    const m = u.message || u.channel_post, em = u.edited_message || u.edited_channel_post;
    if (m) out.push(slimMsg(m, false));
    else if (em) out.push(slimMsg(em, true));
    else if (u.my_chat_member) {
      const c = u.my_chat_member.chat;
      out.push({ message_id: 0, date: u.my_chat_member.date, system: true,
        chat: { id: c.id, type: c.type, title: c.title || nameOf(c) },
        from: { name: "system" }, text: `봇 상태 변경: ${u.my_chat_member.new_chat_member.status}` });
    }
  }
  await dbSave(env, B.id, out);
  return json({ ok: true, next_offset: next, messages: out });
}

async function handleSend(req, env) {
  let b = {};
  try { b = await req.json(); } catch { }
  const B = await needBot(env, b.bot);
  if (!B) return NO_BOT();
  const text = String(b.text || "");
  const chat_id = b.chat_id;
  if (text.length > 4096) return json({ ok: false, error: "4096자를 넘는 메시지는 한 번에 보낼 수 없습니다." }, 400);
  if (!text.trim() || chat_id === undefined || !/^-?\d+$/.test(String(chat_id)))
    return json({ ok: false, error: "chat_id / text 확인" }, 400);
  const r = await tg(B.token, "sendMessage", { chat_id: Number(chat_id), text });
  if (!r.ok) return json({ ok: false, error: r.description }, 502);
  const msg = slimMsg(r.result, false);
  msg.mine = true;
  await dbSave(env, B.id, [msg]);
  return json({ ok: true, message: msg });
}

// 업로드: 브라우저가 만든 multipart 본문을 파싱하지 않고 그대로 텔레그램에 스트리밍 (CPU 사용 최소화)
async function handleUpload(req, url, env) {
  const B = await needBot(env, url.searchParams.get("bot"));
  if (!B) return NO_BOT();
  const chat_id = url.searchParams.get("chat_id") || "";
  const kind = url.searchParams.get("kind") === "photo" ? "photo" : "document";
  const caption = (url.searchParams.get("caption") || "").slice(0, 1024);
  const ct = req.headers.get("Content-Type") || "";
  const len = Number(req.headers.get("Content-Length") || 0);
  if (!/^-?\d+$/.test(chat_id)) return json({ ok: false, error: "chat_id 확인" }, 400);
  if (!ct.startsWith("multipart/form-data")) return json({ ok: false, error: "multipart 필요" }, 400);
  if (len > MAX_UP + 64 * 1024) return json({ ok: false, error: "50MB 초과 파일은 보낼 수 없습니다." }, 413);
  const q = new URLSearchParams({ chat_id });
  if (caption) q.set("caption", caption);
  const method = kind === "photo" ? "sendPhoto" : "sendDocument";
  const r = await fetch(`https://api.telegram.org/bot${B.token}/${method}?${q}`, {
    method: "POST", headers: { "Content-Type": ct }, body: req.body,
  });
  let j = {};
  try { j = await r.json(); } catch { }
  if (!j.ok) return json({ ok: false, error: j.description || "업로드 실패 " + r.status, code: j.error_code }, 502);
  const msg = slimMsg(j.result, false);
  msg.mine = true;
  await dbSave(env, B.id, [msg]);
  return json({ ok: true, message: msg });
}

// 다운로드: getFile → 파일 스트리밍 중계 (봇 API 한도 20MB)
async function handleFile(url, env) {
  const B = await needBot(env, url.searchParams.get("bot"));
  if (!B) return NO_BOT();
  const id = url.searchParams.get("id") || "";
  if (!/^[A-Za-z0-9_-]{10,256}$/.test(id)) return json({ ok: false, error: "bad id" }, 400);
  const r = await tg(B.token, "getFile", { file_id: id });
  if (!r.ok || !r.result.file_path) return json({ ok: false, error: r.description || "파일 없음" }, 502);
  const fp = r.result.file_path;
  const fr = await fetch(`https://api.telegram.org/file/bot${B.token}/${fp}`);
  if (!fr.ok) return json({ ok: false, error: "다운로드 실패 " + fr.status }, 502);
  const ext = (fp.split(".").pop() || "").toLowerCase();
  const name = (url.searchParams.get("name") || fp.split("/").pop() || "file").replace(/[\r\n"\\/]/g, "_").slice(0, 200);
  const inline = url.searchParams.get("inline") === "1" && IMG_TYPES[ext];
  const ascii = name.replace(/[^\x20-\x7e]/g, "_");
  const h = {
    "Content-Type": inline ? IMG_TYPES[ext] : "application/octet-stream",
    "Content-Disposition": `${inline ? "inline" : "attachment"}; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`,
    "Cache-Control": "private, max-age=86400",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; sandbox",
    "Referrer-Policy": "no-referrer",
  };
  const cl = fr.headers.get("Content-Length");
  if (cl) h["Content-Length"] = cl;
  return new Response(fr.body, { status: 200, headers: h });
}

// ---------- CLI (터미널용: bash <(curl -s https://<worker>/cli)) ----------
// 기본 봇(BOT_TOKEN) ↔ AUTH_CHAT_ID 대화방만 사용. 웹 쿠키 세션과 별개인 Bearer 토큰(kind c) 사용
const CLI_TTL = 12 * 3600;
const cliText = (s, status = 200) => new Response(s + "\n", { status, headers: { "Content-Type": "text/plain; charset=utf-8", ...SEC_HEADERS } });
async function cliAuthed(env, req) {
  const m = (req.headers.get("Authorization") || "").match(/^Bearer (\d+)\.c\.([0-9a-f]{64})$/);
  if (!m || !env.BOT_TOKEN || !env.PIN || Number(m[1]) < Date.now() / 1000) return false;
  return safeEq(m[2], await hmacHex(env, "c:" + m[1]));
}
// PIN 확인 (웹 로그인과 같은 실패 횟수 / IP 차단 키 사용)
async function cliLogin(req, env, ip) {
  const banKey = `ban:${ip}`, failKey = `fail:${ip}`;
  const now = Math.floor(Date.now() / 1000);
  const banUntil = Number(await kvGet(env, banKey) || 0);
  if (banUntil > now) return cliText(`Blocked: try again in ${banUntil - now}s`, 429);
  if (!env.PIN || !env.BOT_TOKEN) return cliText("Server not configured (BOT_TOKEN/PIN)", 500);
  const pin = (await req.text().catch(() => "")).slice(0, 200).trim();
  if (safeEq(await hmacHex(env, "p:" + pin), await hmacHex(env, "p:" + String(env.PIN)))) {
    await kvDel(env, failKey);
    const exp = now + CLI_TTL;
    return cliText(`${exp}.c.${await hmacHex(env, "c:" + exp)}`);
  }
  const fails = Number(await kvGet(env, failKey) || 0) + 1;
  if (fails >= MAX_FAIL) {
    await kvPut(env, banKey, String(now + BAN_SEC), BAN_SEC);
    await kvDel(env, failKey);
    return cliText(`Wrong PIN ${MAX_FAIL} times: blocked for ${BAN_SEC}s`, 429);
  }
  await kvPut(env, failKey, String(fails), BAN_SEC);
  return cliText(`Wrong PIN (${MAX_FAIL - fails} attempts left)`, 401);
}
// 긴 글/파일 → sendDocument (본문을 메모리에 모으지 않고 multipart 로 감싸 스트리밍)
async function cliSendDoc(env, chat, name, body, len) {
  const bd = "----memocli" + randHex(12);
  const safe = name.replace(/[\r\n"\\]/g, "_").slice(0, 200) || "file.bin";
  const head = enc.encode(`--${bd}\r\nContent-Disposition: form-data; name="chat_id"\r\n\r\n${chat}\r\n--${bd}\r\nContent-Disposition: form-data; name="document"; filename="${safe}"\r\nContent-Type: application/octet-stream\r\n\r\n`);
  const tail = enc.encode(`\r\n--${bd}--\r\n`);
  const { readable, writable } = typeof FixedLengthStream === "function" ? new FixedLengthStream(head.length + len + tail.length) : new TransformStream();
  (async () => {
    const w = writable.getWriter();
    try {
      await w.write(head);
      if (body instanceof Uint8Array) await w.write(body);
      else { const r = body.getReader(); for (;;) { const { done, value } = await r.read(); if (done) break; await w.write(value); } }
      await w.write(tail); await w.close();
    } catch (e) { try { await w.abort(e); } catch { } }
  })();
  const r = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendDocument`, {
    method: "POST", headers: { "Content-Type": `multipart/form-data; boundary=${bd}` }, body: readable,
  });
  return r.json().catch(() => ({ ok: false, description: "HTTP " + r.status }));
}
async function cliSaved(env, r) {
  if (!r.ok) return cliText("Failed: " + (r.description || "unknown error"), 502);
  const msg = slimMsg(r.result, false);
  msg.mine = true;
  await dbSave(env, "main", [msg]);
  return cliText("ok");
}
async function cliInbox(env) {
  const chat = authChat(env);
  const r = await tg(env.BOT_TOKEN, "getUpdates", {
    timeout: 0, limit: 100,
    allowed_updates: ["message", "edited_message", "channel_post", "edited_channel_post", "my_chat_member"],
  });
  if (!r.ok) return cliText("Failed: " + r.description + (r.error_code === 409 ? " (another client is fetching at the same time, retry shortly)" : ""), 502);
  const out = [];
  let last = 0;
  for (const u of r.result) {
    last = Math.max(last, u.update_id);
    const m = u.message || u.channel_post, em = u.edited_message || u.edited_channel_post;
    if (m) out.push(slimMsg(m, false));
    else if (em) out.push(slimMsg(em, true));
    else if (u.my_chat_member) {
      const c = u.my_chat_member.chat;
      out.push({ message_id: 0, date: u.my_chat_member.date, system: true,
        chat: { id: c.id, type: c.type, title: c.title || nameOf(c) },
        from: { name: "system" }, text: `봇 상태 변경: ${u.my_chat_member.new_chat_member.status}` });
    }
  }
  // 웹과 같은 방식으로 전부 D1 에 저장 → 웹(PIN 로그인)에서 기록으로 보임
  await dbSave(env, "main", out);
  if (last) await tg(env.BOT_TOKEN, "getUpdates", { offset: last + 1, timeout: 0, limit: 1 });
  const lines = [];
  let other = 0, hasFile = false;
  for (const m of out) {
    if (String(m.chat.id) !== chat) { other++; continue; }
    let s = "< " + (m.edited ? "(edited) " : "") + (m.text || "").replace(/\n/g, "\n  ");
    if (m.file) { s += (m.text ? "\n  " : "") + `[${m.file.kind}] ${m.file.name} ${cliSize(m.file.size)}`; hasFile = true; }
    lines.push(s);
  }
  if (!lines.length) lines.push("  (no new messages)");
  if (other) lines.push(`  (${other} message(s) from other chats: see the web UI)`);
  if (hasFile) lines.push("#FILES");   // 클라이언트가 이 줄을 보면 파일 목록을 자동 표시
  return cliText(lines.join("\n"));
}
const cliSize = (n) => n >= 1048576 ? (n / 1048576).toFixed(1) + "MB" : n >= 1024 ? Math.round(n / 1024) + "KB" : (n || 0) + "B";
const cliName = (s) => String(s || "file").replace(/[\x00-\x1f\x7f\/\\:*?"<>|]/g, "_").replace(/^[.\-\s]+/, "").slice(0, 150) || "file";
// 파일 목록: D1 에 저장된 내 대화방(AUTH_CHAT_ID) 메시지 중 파일만 (오래된 것 → 최신). 줄 형식: 행id \t 종류 \t 이름 \t 크기 \t 방향 \t 시각
async function cliFiles(env, chat) {
  if (!env.DB) return cliText("D1 (DB) binding missing: file list unavailable", 500);
  await dbInit(env);
  const { results } = await env.DB.prepare("SELECT id, data FROM messages WHERE bot = 'main' AND chat_id = ? AND json_extract(data, '$.file.id') IS NOT NULL ORDER BY id DESC LIMIT 30").bind(chat).all();
  const rows = results.reverse().map((r) => {
    const m = JSON.parse(r.data), f = m.file;
    const d = new Date(((m.date || 0) + 9 * 3600) * 1000), z = (n) => String(n).padStart(2, "0");   // 한국 시간
    const t = `${z(d.getUTCMonth() + 1)}/${z(d.getUTCDate())} ${z(d.getUTCHours())}:${z(d.getUTCMinutes())}`;
    return [r.id, f.kind, cliName(f.name), cliSize(f.size), m.mine ? "sent" : "recv", t].join("\t");
  });
  return cliText(rows.join("\n"));
}
async function cliDl(url, env, chat) {
  const row = url.searchParams.get("row") || "";
  if (!env.DB || !/^\d{1,15}$/.test(row)) return cliText("bad row", 400);
  await dbInit(env);
  const r = await env.DB.prepare("SELECT data FROM messages WHERE id = ? AND bot = 'main' AND chat_id = ?").bind(Number(row), chat).first();
  const f = r && JSON.parse(r.data).file;
  if (!f || !f.id) return cliText("File not found", 404);
  const u = new URL(url.origin + "/x");
  u.searchParams.set("id", f.id); u.searchParams.set("name", cliName(f.name));
  return handleFile(u, env);
}
async function handleCli(req, env, ip, url) {
  const p = url.pathname;
  if (p === "/cli" && req.method === "GET")
    return new Response(CLI_SH.replace("__ORIGIN__", url.origin), { headers: { "Content-Type": "text/plain; charset=utf-8", ...SEC_HEADERS } });
  if (p === "/cli/api/login" && req.method === "POST") return cliLogin(req, env, ip);
  if (!(await cliAuthed(env, req))) return cliText("Unauthorized (log in again)", 401);
  const chat = authChat(env);
  if (!/^-?\d+$/.test(chat)) return cliText("Server not configured (AUTH_CHAT_ID)", 500);
  if (p === "/cli/api/ping" && req.method === "GET") return cliText("ok");
  if (p === "/cli/api/inbox" && req.method === "GET") return cliInbox(env);
  if (p === "/cli/api/files" && req.method === "GET") return cliFiles(env, chat);
  if (p === "/cli/api/dl" && req.method === "GET") return cliDl(url, env, chat);
  if (p === "/cli/api/send" && req.method === "POST") {
    const len = Number(req.headers.get("Content-Length") || 0);
    if (len > MAX_UP) return cliText("Too large (max 50MB)", 413);
    const raw = new Uint8Array(await req.arrayBuffer());
    const text = new TextDecoder().decode(raw).replace(/\r\n?/g, "\n").trim();
    if (!text) return cliText("Empty message", 400);
    if (text.length <= 4096) return cliSaved(env, await tg(env.BOT_TOKEN, "sendMessage", { chat_id: Number(chat), text }));
    const t = enc.encode(text);   // 4096자 초과 → 텍스트 파일로
    return cliSaved(env, await cliSendDoc(env, chat, `memo_${Math.floor(Date.now() / 1000)}.txt`, t, t.length));
  }
  if (p === "/cli/api/sendfile" && req.method === "POST") {
    const len = Number(req.headers.get("Content-Length") || 0);
    if (!len || !req.body) return cliText("Content-Length required", 411);
    if (len > MAX_UP) return cliText("File too large (max 50MB)", 413);
    return cliSaved(env, await cliSendDoc(env, chat, url.searchParams.get("name") || "file.bin", req.body, len));
  }
  return cliText("not found", 404);
}
// 클라이언트 스크립트 (비밀값 없음). 주의: 이 안에는 백틱과 달러+중괄호 금지
const CLI_SH = String.raw`#!/usr/bin/env bash
# memo CLI - type text + Enter to send, /h for help
W="__ORIGIN__"
command -v curl >/dev/null || { echo "curl is required"; exit 1; }
if [ -z "$TG_PIN" ]; then read -rsp "PIN: " TG_PIN </dev/tty; echo; fi
T=$(printf %s "$TG_PIN" | curl -s -w '\n%{http_code}' --data-binary @- "$W/cli/api/login")
unset TG_PIN
C=$(printf %s "$T" | tail -n1); T=$(printf %s "$T" | sed '$d')
[ "$C" = 200 ] || { echo "Login failed: $T"; exit 1; }
H="Authorization: Bearer $T"
ue()   { printf %s "$1" | od -An -tx1 -v | tr -d ' \n' | sed 's/../%&/g'; }
post() { r=$(curl -s -w '\n%{http_code}' -H "$H" "$@"); c=$(printf %s "$r" | tail -n1); b=$(printf %s "$r" | sed '$d'); }
ok()   { if [ "$c" = 200 ]; then echo "  ✓ $1"; elif [ "$c" = 401 ]; then echo "  ✗ Session expired: run the script again"; else echo "  ✗ $c $b"; fi; }
# file list: FL holds "no<TAB>rowid<TAB>name" lines ($1=q: quiet)
flist() {
  post "$W/cli/api/files"; [ "$c" = 200 ] || { ok; return 1; }
  FL=""; i=0
  while IFS=$'\t' read -r id kind nm sz dir t; do
    [ -z "$id" ] && continue
    i=$((i+1)); FL+="$i"$'\t'"$id"$'\t'"$nm"$'\n'
    [ "$1" = q ] || printf '  %2d) %s %s %6s  %s  [%s]\n' "$i" "$t" "$dir" "$sz" "$nm" "$kind"
  done <<<"$b"
  [ "$1" = q ] || { [ $i = 0 ] && echo "  (no files)" || echo "  Download: /d no [no...]"; }
}
dl() {
  [ -z "$FL" ] && flist q
  for n in "$@"; do
    id=$(printf %s "$FL" | awk -F'\t' -v n="$n" '$1==n{print $2}')
    nm=$(printf %s "$FL" | awk -F'\t' -v n="$n" '$1==n{print $3}')
    if [ -z "$id" ]; then echo "  ✗ No such number: $n (see /l)"; continue; fi
    out=$nm; k=1
    while [ -e "$out" ]; do out="$k"_"$nm"; k=$((k+1)); done
    if curl -sf -H "$H" -o "$out" "$W/cli/api/dl?row=$id"; then echo "  ✓ Saved: $(pwd)/$out ($(wc -c <"$out" | tr -d ' ')B)"
    else rm -f "$out"; echo "  ✗ Download failed: $n"; fi
  done
}
help() {
  echo "text+Enter: send | /m: multi-line | /r: receive | /f path: send file"
  echo "/l: file list | /d no [no...]: download | /pwd: current folder | /h: help | /q: quit"
}
echo "Connected: $W"; help
while IFS= read -rep "> " line </dev/tty; do
  read -r cmd a b2 <<<"$line"
  case "$cmd" in
    "") ;;
    /q) break ;;
    /h) help ;;
    /r) post "$W/cli/api/inbox"
        if [ "$c" = 200 ]; then printf '%s\n' "$b" | grep -v '^#FILES$'; printf '%s\n' "$b" | grep -q '^#FILES$' && flist
        else ok; fi ;;
    /l) flist ;;
    /pwd) echo "  $(pwd)" ;;
    /m) echo "  Paste/type lines, then Ctrl+D on a new line"
        msg=$(cat </dev/tty | tr -d '\r')
        if [ -z "$msg" ]; then echo "  (cancelled)"
        else post --data-binary @- "$W/cli/api/send" <<<"$msg"; ok "Sent"; fi ;;
    /f) f=$(printf %s "$line" | sed -e 's/^\/f[[:space:]]*//' -e 's/[[:space:]]*$//' -e "s/^'\(.*\)'$/\1/" -e 's/^"\(.*\)"$/\1/' -e 's/\\ / /g')
        case "$f" in "~"/*) f="$HOME/$(printf %s "$f" | cut -c3-)" ;; esac
        if [ -z "$f" ]; then echo "  Usage: /f path"
        elif [ -f "$f" ] && [ -r "$f" ]; then post -H "Content-Type: application/octet-stream" --data-binary @"$f" "$W/cli/api/sendfile?name=$(ue "$(basename "$f")")"; ok "File sent"
        elif [ -f "$f" ]; then echo "  Cannot read (permission): '$f'"
        else echo "  File not found: '$f'"; fi ;;
    /d) if [ -z "$a" ]; then flist; else dl $(printf %s "$line" | sed 's/^\/d//'); fi ;;
    *)  if [[ "$line" =~ ^[dlrfmhq]([[:space:]][0-9[:space:]]*)?$ ]]; then echo "  Not sent. Did you mean /$line ? (commands start with /)"
        else post --data-binary @- "$W/cli/api/send" <<<"$line"; ok "Sent"; fi ;;
  esac
done
`;

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const ip = req.headers.get("CF-Connecting-IP") || "0.0.0.0";
    const authed = await validSession(env, req);

    // 1) 요청량 제한 (비로그인 요청은 더 엄격하게)
    if (!memRateOk(ip, authed ? RPM_AUTH : RPM_ANON))
      return json({ ok: false, error: "rate limited" }, 429, { "Retry-After": "60" });
    if (!authed && env.RL) {
      try { const { success } = await env.RL.limit({ key: ip }); if (!success) return json({ ok: false, error: "rate limited" }, 429, { "Retry-After": "60" }); } catch { }
    }

    // 2) POST 요청 CSRF 방지 (Origin 확인)
    if (req.method === "POST") {
      const origin = req.headers.get("Origin");
      if (origin && origin !== url.origin) return json({ ok: false, error: "bad origin" }, 403);
    }

    const p = url.pathname;
    if (p === "/favicon.ico" || p === "/robots.txt")
      return new Response(p === "/robots.txt" ? "User-agent: *\nDisallow: /\n" : null, { status: p === "/robots.txt" ? 200 : 204 });

    if (p === "/cli" || p.startsWith("/cli/")) return handleCli(req, env, ip, url);   // 터미널용 CLI (Bearer 토큰, 웹 세션과 별개)

    if (p === "/api/login" && req.method === "POST") return handleLogin(req, env, ip); if (p === "/api/auth/request" && req.method === "POST") return handleAuthRequest(req, env, ip, url); if (p === "/api/auth/status" && req.method === "GET") return handleAuthStatus(url, env); if (p === "/api/authhook" && req.method === "POST") return handleAuthHook(req, env);

    if (p === "/" && req.method === "GET") {
      // 터미널(curl/wget)로 첫 화면을 열면 HTML 대신 CLI 사용법 (| bash 로 넘겨도 사용법만 출력)
      if (/^(curl|wget|httpie|xh)\//i.test(req.headers.get("User-Agent") || ""))
        return new Response(`# memo CLI: curl -s ${url.origin}/cli | bash\necho "memo CLI: curl -s ${url.origin}/cli | bash"\n`, { headers: { "Content-Type": "text/plain; charset=utf-8", ...SEC_HEADERS } });
      if (authed) return html(APP_HTML);
      const banUntil = Number(await kvGet(env, `ban:${ip}`) || 0);
      return html(LOGIN_HTML, banUntil > Date.now() / 1000 ? 429 : 200);
    }

    // 이 아래는 로그인 필요
    if (!authed) return json({ ok: false, error: "unauthorized" }, 401);

    if (p === "/api/logout" && req.method === "POST")
      return json({ ok: true }, 200, { "Set-Cookie": `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict` });
    if (p === "/api/me" && req.method === "GET") {
      const m = await mainBot(env);
      return m.tgid ? json({ ok: true, name: m.name, username: m.username }) : json({ ok: false, error: m.error }, 502);
    }
    if (p === "/api/bots" && req.method === "GET") return handleBots(env, authed);
    if (p === "/api/bots/add" && req.method === "POST") return handleBotAdd(req, env);
    if (p === "/api/bots/remove" && req.method === "POST") return handleBotRemove(req, env);
    if (p === "/api/updates" && req.method === "GET") return handleUpdates(url, env);
    if (p === "/api/send" && req.method === "POST") return handleSend(req, env);
    if (p === "/api/upload" && req.method === "POST") return handleUpload(req, url, env);
    if (p === "/api/file" && req.method === "GET") return handleFile(url, env);
    if (p === "/api/history" && req.method === "GET") return handleHistory(url, env, authed);
    if (p === "/api/delete" && req.method === "POST") return handleDelete(req, env);

    return json({ ok: false, error: "not found" }, 404);
  },
};

// =====================================================================
//  HTML (비밀값 없음)
// =====================================================================
const BASE_CSS = `
:root{--bg:#0e1621;--panel:#17212b;--panel2:#202b36;--txt:#e9eef3;--muted:#7f91a4;--acc:#2ea6ff;--me:#2b5278;--err:#ff6b6b}
@media (prefers-color-scheme: light){:root{--bg:#f1f3f6;--panel:#fff;--panel2:#f4f6f8;--txt:#111;--muted:#6b7785;--acc:#2481cc;--me:#d9f0ff;--err:#d93636}}
*{box-sizing:border-box}html,body{margin:0;height:100%;background:var(--bg);color:var(--txt);font:15px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI","Apple SD Gothic Neo","Malgun Gothic",sans-serif}
button{font:inherit;cursor:pointer;border:0;border-radius:10px;background:var(--acc);color:#fff;padding:10px 16px}
button:disabled{opacity:.5;cursor:default}
input,textarea{font:inherit;color:var(--txt);background:var(--panel2);border:1px solid transparent;border-radius:10px;padding:10px 12px;outline:none}
input:focus,textarea:focus{border-color:var(--acc)}
`;

const LOGIN_HTML = `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Bot Login</title><style>${BASE_CSS}
.box{max-width:320px;margin:18vh auto 0;padding:28px 24px;background:var(--panel);border-radius:16px;text-align:center}
h1{font-size:18px;margin:0 0 18px}input{width:100%;text-align:center;letter-spacing:6px;font-size:22px;margin-bottom:12px}
button{width:100%}#msg{min-height:22px;margin-top:12px;color:var(--err);font-size:14px}.or{margin:14px 0 10px;color:var(--muted);font-size:13px}.tg{background:var(--panel2);color:var(--txt);border:1px solid var(--acc)}#tgs{min-height:20px;margin-top:10px;font-size:14px;color:var(--muted);line-height:1.7}#tgs b{color:var(--acc);font-size:20px;letter-spacing:3px}</style></head><body>
<form class="box" id="f" autocomplete="off"><h1>🔒 PIN 입력</h1>
<input id="pin" type="password" inputmode="numeric" maxlength="16" autofocus>
<button id="b">입장</button><div id="msg"></div><div class="or">또는</div><button type="button" id="tgb" class="tg">📱 인증요청 (텔레그램 승인)</button><div id="tgs"></div></form>
<script>
const f=document.getElementById('f'),pin=document.getElementById('pin'),msg=document.getElementById('msg'),b=document.getElementById('b');
f.onsubmit=async e=>{e.preventDefault();if(!pin.value)return;b.disabled=true;msg.textContent='';
 try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pin:pin.value})});
  const j=await r.json().catch(()=>({}));
  if(j.ok){location.reload();return}
  if(j.banned)msg.textContent='시도 횟수 초과: '+Math.ceil(j.retry_after/60)+'분 후 다시 시도하세요.';
  else if(j.remaining!==undefined)msg.textContent='PIN이 틀렸습니다. 남은 시도: '+j.remaining+'회';
  else msg.textContent=j.error||'오류 ('+r.status+')';
 }catch(err){msg.textContent='네트워크 오류'}
 pin.value='';b.disabled=false;pin.focus();};const tgb=document.getElementById('tgb'),tgs=document.getElementById('tgs');let tgT=null;tgb.onclick=async()=>{tgb.disabled=true;msg.textContent='';tgs.textContent='요청 중…';clearInterval(tgT);try{const r=await fetch('/api/auth/request',{method:'POST'});const j=await r.json().catch(()=>({}));if(!j.ok){tgs.textContent=j.banned?'잠시 후 다시 시도하세요.':(j.error||'요청 실패 ('+r.status+')');tgb.disabled=false;return}let left=j.expires_in,n=0;const show=()=>{tgs.textContent='';const c=document.createElement('b');c.textContent=j.code;tgs.append('텔레그램에서 [허가하기]를 눌러주세요',document.createElement('br'),'확인 코드 ',c,document.createElement('br'),'남은 시간 '+Math.max(0,left)+'초')};show();const end=t=>{clearInterval(tgT);tgs.textContent=t;tgb.disabled=false};tgT=setInterval(async()=>{left--;show();if(++n%3)return;if(left<-5){end('시간이 지나 만료되었습니다. 다시 요청하세요.');return}try{const s=await (await fetch('/api/auth/status?id='+j.id)).json();if(s.status==='approved'){clearInterval(tgT);tgs.textContent='허가됨 · 접속 중…';location.reload()}else if(s.status==='denied')end('거절되었습니다.');else if(s.status==='expired')end('만료되었습니다. 다시 요청하세요.')}catch(e){}},1000)}catch(e){tgs.textContent='네트워크 오류';tgb.disabled=false}};
</script></body></html>`;

const APP_HTML = `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Telegram Web Bot</title><style>${BASE_CSS}
.app{display:flex;height:100vh;height:100dvh}
.side{width:280px;flex:none;background:var(--panel);display:flex;flex-direction:column;border-right:1px solid var(--panel2)}
.tabbar{display:flex;align-items:stretch;gap:6px;padding:8px 6px;border-bottom:1px solid var(--panel2);flex:none;background:var(--bg)}
.tnav{flex:none;width:32px;padding:0;border-radius:12px;background:var(--panel2);color:var(--txt);font-size:24px;font-weight:700;line-height:1}
.tnav:hover:not(:disabled){background:var(--acc);color:#fff}.tnav:disabled{opacity:.25}
.tabs{flex:1;display:flex;gap:6px;overflow-x:auto;scroll-snap-type:x proximity;scrollbar-width:none;min-width:0;padding:2px 0}
.tabs::-webkit-scrollbar{display:none}
.tab{display:flex;align-items:center;gap:5px;padding:9px 11px;border-radius:12px;background:var(--panel2);color:var(--muted);font-size:14px;white-space:nowrap;flex:none;max-width:132px;cursor:pointer;border:2px solid transparent;user-select:none;scroll-snap-align:center;transition:background .15s,color .15s,border-color .15s}
.tab span{overflow:hidden;text-overflow:ellipsis}.tab:hover{color:var(--txt);border-color:var(--acc)}
.tab.on{background:var(--acc);color:#fff;font-weight:700;border-color:var(--acc);box-shadow:0 2px 10px rgba(46,166,255,.45)}
.tab.on::before{content:'●';font-size:9px}
.tab i{font-style:normal;opacity:.6;padding:0 4px;border-radius:6px;font-size:16px;line-height:1}.tab i:hover{opacity:1;background:rgba(0,0,0,.2)}
.tabs .addb{background:none;color:var(--acc);padding:6px 12px;font-size:20px;line-height:1;flex:none;border:2px dashed var(--acc);border-radius:12px}
.side h2{margin:0;padding:14px 16px;font-size:16px;display:flex;justify-content:space-between;align-items:center;gap:8px}
.side h2 #bot{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#chats{flex:1;overflow:auto}
.chat{padding:12px 16px;cursor:pointer;border-bottom:1px solid var(--panel2)}
.chat.on{background:var(--panel2)}.chat b{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.chat span{color:var(--muted);font-size:13px;display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.side .foot{padding:10px 16px;font-size:12px;color:var(--muted);display:flex;justify-content:space-between;align-items:center;gap:8px}
.side .foot button{padding:6px 10px;font-size:12px;background:var(--panel2);color:var(--txt);white-space:nowrap;flex:none}
.main{flex:1;display:flex;flex-direction:column;min-width:0;position:relative}
.main.drag::after{content:'여기에 놓으면 전송';position:absolute;inset:8px;border:3px dashed var(--acc);border-radius:16px;display:flex;align-items:center;justify-content:center;background:rgba(46,166,255,.14);font-size:20px;font-weight:600;pointer-events:none}
.head{padding:12px 16px;background:var(--panel);display:flex;align-items:center;gap:10px}
.head #back{display:none;padding:6px 10px;background:var(--panel2);color:var(--txt)}
.head b{flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.head #rf2,.head #clr{padding:6px 10px;background:var(--panel2);color:var(--txt)}#clr[hidden]{display:none}
#log{flex:1;overflow-y:auto;overflow-x:hidden;padding:16px 96px;display:flex;flex-direction:column;gap:8px}
.m{position:relative;max-width:min(560px,85%);padding:8px 12px;border-radius:12px;background:var(--panel);white-space:pre-wrap;word-break:break-word}
.m.me{align-self:flex-end;background:var(--me)}.m.sys{align-self:center;background:none;color:var(--muted);font-size:13px}
.m .who{font-size:12px;color:var(--acc);font-weight:600}.m .t{font-size:11px;color:var(--muted);text-align:right;margin-top:2px}
.m .acts{position:absolute;top:50%;transform:translateY(-50%);right:-92px;display:flex;flex-direction:row;gap:4px;opacity:0;transition:opacity .15s}
.m.me .acts{right:auto;left:-92px}.m:hover .acts,.m .acts:focus-within{opacity:1}
.m .acts button{border:0;background:none;color:var(--muted);width:40px;height:40px;padding:0;display:flex;align-items:center;justify-content:center;border-radius:10px}.m .acts svg{width:24px;height:24px;display:block}
.m .acts button:hover{background:var(--panel2);color:var(--txt)}
@media (hover:none){.m .acts{opacity:.7}}
.file img{display:block;max-width:min(280px,100%);max-height:280px;border-radius:8px;margin:2px 0 4px;cursor:zoom-in;background:var(--panel2)}
.file a{color:var(--acc);text-decoration:none;font-size:14px;cursor:pointer}.file a:hover{text-decoration:underline}
.file .big{color:var(--muted);font-size:12px}
#ups{padding:0 16px;max-height:40vh;overflow:auto}
.up{background:var(--panel);border-radius:10px;padding:8px 12px;margin:6px 0;font-size:13px}
.up .nm{display:flex;justify-content:space-between;gap:10px}.up .nm span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.up .nm span:last-child{color:var(--muted);flex:none}
.up .bar{height:6px;background:var(--panel2);border-radius:3px;overflow:hidden;margin-top:6px}
.up .bar i{display:block;height:100%;width:0;background:var(--acc);transition:width .2s}
.up.wait{opacity:.6}.up.busy .bar i{animation:pl 1s ease-in-out infinite alternate}
@keyframes pl{from{opacity:1}to{opacity:.35}}
#cnt{padding:0 16px 2px;text-align:right;font-size:12px;color:var(--muted)}#cnt.over{color:var(--err);font-weight:600}
.dlg{position:fixed;inset:0;background:rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center;z-index:10;padding:16px}
.dlg[hidden],#cnt[hidden]{display:none}
.dlg .box{background:var(--panel);border-radius:14px;padding:20px;max-width:380px;width:100%;display:flex;flex-direction:column;gap:8px;outline:none;box-shadow:0 10px 40px rgba(0,0,0,.3)}
.dlg h3{margin:0 0 2px;font-size:17px}.dlg p{margin:0 0 8px;color:var(--muted);font-size:14px}
.dlg button{text-align:left}.dlg button small{display:block;font-size:12px;opacity:.8;font-weight:400}
.dlg .ghost{background:var(--panel2);color:var(--txt);text-align:center}
.dlg #bOk{text-align:center}.dlg .err{color:var(--err);font-size:13px;min-height:18px}
.empty{margin:auto;color:var(--muted);text-align:center;padding:20px}
form.send{display:flex;gap:8px;padding:10px;background:var(--panel)}
form.send{align-items:flex-end}form.send textarea{flex:1;resize:none;height:44px;max-height:140px}form.send.big textarea{height:45vh;max-height:none;resize:vertical}form.send #ex{flex:none;width:44px;height:44px;padding:0;display:flex;align-items:center;justify-content:center;background:var(--panel2);color:var(--txt)}form.send #ex svg{width:22px;height:22px}form.send.big #ex{background:var(--acc);color:#fff}form.send #at,form.send #sb{height:44px}form.send #og{flex:none;width:44px;height:44px;padding:0;background:var(--panel2);color:var(--txt);font-size:18px}form.send #og.on{background:var(--acc);color:#fff}
form.send #at{background:var(--panel2);color:var(--txt);padding:10px 12px}
#st{padding:0 16px 10px;font-size:12px;color:var(--muted);border-bottom:1px solid var(--panel2)}
.side h2 button{padding:6px 12px;font-size:13px;flex:none}
@media (max-width:720px){.side{width:100%}.app.inchat .side{display:none}.app:not(.inchat) .main{display:none}.head #back{display:block}#log{padding:12px}.m .acts{position:static;transform:none;justify-content:flex-end;margin:2px -6px -4px 0;opacity:.75}}
</style></head><body>
<div class="app" id="app">
 <aside class="side"><div class="tabbar"><button type="button" class="tnav" id="tl" title="이전 봇">‹</button><div class="tabs" id="tabs"></div><button type="button" class="tnav" id="tr" title="다음 봇">›</button></div>
  <h2><span id="bot">봇</span><button id="rf" title="새 메시지 확인">🔄 새 메시지 확인</button></h2>
  <div id="st">🔄 버튼을 눌러 새 메시지를 확인하세요</div>
  <div id="chats"></div>
  <div class="foot"><span id="keepi">최근 20개씩 서버 저장</span><button id="out">로그아웃</button></div></aside>
 <section class="main" id="main">
  <div class="head"><button id="back">←</button><b id="title">대화방을 선택하세요</b><button id="clr" type="button" title="이 대화방 기록 모두 지우기 (서버 기록 포함)" hidden>🗑</button><button id="rf2" title="새 메시지 확인">🔄</button></div>
  <div id="log"><div class="empty">봇이 받은 메시지가 여기 표시됩니다.<br>그룹/개인 대화에서 봇에게 메시지를 보내면 목록에 나타납니다.</div></div>
  <div id="ups"></div>
  <div id="cnt" hidden></div>
  <form class="send" id="sf"><button type="button" id="at" title="파일 첨부 (끌어다 놓기·붙여넣기 가능)" disabled>📁</button><button type="button" id="og" aria-pressed="false">🖼️</button><input type="file" id="fi" multiple hidden>
   <textarea id="tx" placeholder="메시지 입력 (Enter 전송, Shift+Enter 줄바꿈) · 파일은 끌어다 놓기" disabled></textarea><button type="button" id="ex" title="입력창 크게 (여러 줄 입력)" aria-pressed="false"></button><button id="sb" disabled>전송</button></form>
 </section>
</div>
<div class="dlg" id="dlg" hidden><div class="box" tabindex="-1" id="dBox">
 <h3 id="dTitle">긴 메시지</h3><p>텔레그램 메시지는 한 번에 최대 4,096자까지 보낼 수 있습니다. 어떻게 보낼까요?</p>
 <button id="dSplit">✂ 나눠 보내기<small id="dSplitInfo"></small></button>
 <button id="dFile">📄 텍스트 파일(.txt)로 보내기<small>메시지 하나로 전송 · 받는 사람이 파일을 열어 확인</small></button>
 <button id="dCancel" class="ghost">취소</button>
</div></div>
<div class="dlg" id="bdlg" hidden><form class="box" id="bForm" autocomplete="off">
 <h3>봇 추가</h3><p>@BotFather 에서 받은 API 토큰을 입력하세요. 토큰은 서버에 암호화되어 저장되며 화면에는 다시 표시되지 않습니다.</p>
 <input id="bTok" type="password" placeholder="123456789:AAH..." autocomplete="off" spellcheck="false">
 <div class="err" id="bErr"></div>
 <button id="bOk">추가</button><button type="button" id="bCancel" class="ghost">취소</button>
</form></div>
<script>
const $=id=>document.getElementById(id);
const MB=1048576;let KEEP=20;
let BOTS=[],BOT=null,LIMITED=false;const MEM={};
let S={offset:0,chats:{},msgs:{}};
let cur=null,busy=false,sending=false,uploading=0;
const lsKey=b=>b==='main'?'tgw_v1':'tgw_v1_'+b;
function load(b){if(LIMITED&&MEM[b]){S=MEM[b];return}S={offset:0,chats:{},msgs:{}};try{const s=JSON.parse(localStorage.getItem(lsKey(b))||'null');if(s&&s.msgs){if(LIMITED)S.offset=s.offset||0;else S=s}}catch(e){}}
const save=()=>{if(!BOT)return;try{if(LIMITED){MEM[BOT]=S;const s=JSON.parse(localStorage.getItem(lsKey(BOT))||'null')||{offset:0,chats:{},msgs:{}};if(S.offset>(s.offset||0)){s.offset=S.offset;localStorage.setItem(lsKey(BOT),JSON.stringify(s))}return}localStorage.setItem(lsKey(BOT),JSON.stringify(S))}catch(e){}};
const fmt=d=>{const x=new Date(d*1000);return x.toLocaleString('ko-KR',{month:'numeric',day:'numeric',hour:'2-digit',minute:'2-digit'})};
const human=n=>n>=MB?(n/MB).toFixed(1)+'MB':n>=1024?Math.round(n/1024)+'KB':n+'B';
const KIND={photo:'사진',sticker:'스티커',animation:'GIF',video:'동영상',video_note:'영상메시지',audio:'오디오',voice:'음성',document:'파일'};
function el(tag,cls,txt){const e=document.createElement(tag);if(cls)e.className=cls;if(txt!==undefined)e.textContent=txt;return e}
const preview=m=>m.text||(m.file?'📎 '+(KIND[m.file.kind]||'파일')+(m.file.kind==='document'?' '+m.file.name:''):'');
const post=(u,b)=>fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)})
 .then(r=>{if(r.status===401){location.reload();return {ok:false,error:'로그인 필요'}}return r.json().catch(()=>({ok:false,error:'HTTP '+r.status}))})
 .catch(()=>({ok:false,error:'네트워크 오류'}));
const isBusy=()=>busy||sending||uploading>0;

function add(m){
 const id=String(m.chat.id);
 S.chats[id]={id,title:m.chat.title,type:m.chat.type,last:preview(m),date:m.date};
 const arr=S.msgs[id]||(S.msgs[id]=[]);
 if(m.edited){const o=arr.find(x=>x.message_id===m.message_id);if(o){o.text=m.text+' (수정됨)';return}}
 if(m.message_id&&arr.some(x=>x.message_id===m.message_id))return;
 arr.push(m);if(arr.length>KEEP)arr.splice(0,arr.length-KEEP);
}
function syncLast(id){const a=S.msgs[id]||[],c=S.chats[id];if(!c)return;const m=a[a.length-1];c.last=m?preview(m):''}
function fileUrl(id,name,inline){return '/api/file?bot='+encodeURIComponent(BOT)+'&id='+encodeURIComponent(id)+(name?'&name='+encodeURIComponent(name):'')+(inline?'&inline=1':'')}
function download(f){
 if(f.size>20*MB){alert('20MB를 넘는 파일은 봇 API로 받을 수 없습니다. 텔레그램 앱에서 확인하세요.');return}
 const a=document.createElement('a');a.href=fileUrl(f.id,f.name);a.download=f.name||'';document.body.appendChild(a);a.click();a.remove();
}
function fileBox(f){
 const box=el('div','file');
 if(f.thumb){const img=el('img');img.loading='lazy';img.alt=f.name||'';img.src=fileUrl(f.thumb,'',true);
  img.onerror=()=>img.remove();
  img.onclick=()=>{if(f.kind==='photo'||(f.kind==='sticker'&&f.thumb===f.id))window.open(fileUrl(f.id,f.name,true),'_blank','noopener');else download(f)};
  box.appendChild(img)}
 const a=el('a','','⬇ '+(KIND[f.kind]||'파일')+' · '+(f.name||'')+(f.size?' ('+human(f.size)+')':''));
 a.onclick=e=>{e.preventDefault();download(f)};box.appendChild(a);
 if(f.size>20*MB)box.appendChild(el('div','big','20MB 초과 – 텔레그램 앱에서만 받을 수 있음'));
 return box;
}

// ---------- 봇 탭 ----------
function renderTabs(){
 const t=$('tabs');t.textContent='';
 for(const b of BOTS){
  const d=el('div','tab'+(b.id===BOT?' on':''));d.title=b.name+(b.username?' (@'+b.username+')':'')+(b.main?' · 기본 봇':'');
  d.appendChild(el('span','',(b.main?'★ ':'')+b.name));
  if(!b.main){const x=el('i','','×');x.title='이 봇 제거';x.onclick=e=>{e.stopPropagation();removeBot(b)};d.appendChild(x)}
  d.onclick=()=>switchBot(b.id);t.appendChild(d)}
 const a=el('button','addb','＋');a.type='button';a.title='봇 추가 (API 토큰 입력)';a.onclick=openAdd;t.appendChild(a);
 const on=t.querySelector('.tab.on');if(on)on.scrollIntoView({block:'nearest',inline:'center',behavior:'smooth'});navUpd();
}
function navUpd(){const i=BOTS.findIndex(x=>x.id===BOT);$('tl').disabled=i<=0;$('tr').disabled=i<0||i>=BOTS.length-1}function navBot(d){const i=BOTS.findIndex(x=>x.id===BOT),n=BOTS[i+d];if(n)switchBot(n.id)}$('tl').onclick=()=>navBot(-1);$('tr').onclick=()=>navBot(1);$('tabs').addEventListener('wheel',e=>{if(Math.abs(e.deltaY)>Math.abs(e.deltaX)){$('tabs').scrollLeft+=e.deltaY;e.preventDefault()}},{passive:false});function switchBot(id){
 if(id===BOT)return;
 if(isBusy()){alert('전송·업로드·확인 중에는 봇을 바꿀 수 없습니다. 끝난 뒤 다시 눌러 주세요.');return}
 save();BOT=id;try{localStorage.setItem('tgw_bot',id)}catch(e){}
 load(id);cur=null;
 const b=BOTS.find(x=>x.id===id);const nm=b?b.name:'봇';
 $('bot').textContent='🤖 '+nm;$('bot').title=b&&b.username?'@'+b.username:'';document.title=nm+' – Telegram Web';
 $('title').textContent='대화방을 선택하세요';$('tx').disabled=$('sb').disabled=$('at').disabled=true;$('clr').hidden=true;
 $('app').classList.remove('inchat');$('ups').textContent='';
 $('st').textContent='🔄 버튼을 눌러 새 메시지를 확인하세요';
 renderTabs();renderChats();renderLog();loadHistory();
}
function startLimited(exp){const k=$('keepi');const tick=()=>{const left=exp-Math.floor(Date.now()/1000);if(left<=0){location.reload();return}k.textContent='⏱ 임시 세션 · 새 메시지만 표시 · '+Math.floor(left/60)+':'+String(left%60).padStart(2,'0')};tick();setInterval(tick,1000)}
async function loadBots(){
 try{const r=await fetch('/api/bots');if(r.status===401){location.reload();return}
  const j=await r.json();if(!j.ok){$('st').textContent='오류: '+(j.error||'');return}
  BOTS=j.bots;if(j.keep>0){KEEP=j.keep;$('keepi').textContent='최근 '+KEEP+'개씩 서버 저장'}LIMITED=!!j.limited;if(LIMITED)startLimited(j.session_exp);let want=null;try{want=localStorage.getItem('tgw_bot')}catch(e){}
  if(!BOTS.some(b=>b.id===want))want='main';
  BOT=null;switchBot(want);
 }catch(e){$('st').textContent='네트워크 오류'}
}
function openAdd(){$('bTok').value='';$('bErr').textContent='';$('bOk').disabled=false;$('bdlg').hidden=false;$('bTok').focus()}
function closeAdd(){$('bdlg').hidden=true;$('bTok').value=''}
$('bCancel').onclick=closeAdd;
$('bdlg').onclick=e=>{if(e.target===$('bdlg'))closeAdd()};
$('bdlg').addEventListener('keydown',e=>{if(e.key==='Escape')closeAdd()});
$('bForm').onsubmit=async e=>{e.preventDefault();const t=$('bTok').value.trim();if(!t)return;
 $('bOk').disabled=true;$('bErr').textContent='토큰 확인 중…';
 const j=await post('/api/bots/add',{token:t});$('bOk').disabled=false;
 if(!j.ok){$('bErr').textContent=j.error||'추가 실패';return}
 closeAdd();
 const i=BOTS.findIndex(x=>x.id===j.bot.id);if(i>=0)BOTS[i]=j.bot;else BOTS.push(j.bot);
 if(isBusy())renderTabs();else{switchBot(j.bot.id);renderTabs()}
};
async function removeBot(b){
 if(b.id===BOT&&isBusy()){alert('전송·업로드·확인이 끝난 뒤 다시 시도하세요.');return}
 if(!confirm('"'+b.name+'" 봇을 목록에서 제거할까요? 이 봇의 서버 기록과 이 브라우저 기록도 함께 지워집니다. (텔레그램의 봇 자체는 그대로 남습니다)'))return;
 const j=await post('/api/bots/remove',{id:b.id});
 if(!j.ok){alert('제거 실패: '+(j.error||''));return}
 try{localStorage.removeItem(lsKey(b.id))}catch(e){}
 BOTS=BOTS.filter(x=>x.id!==b.id);
 if(BOT===b.id){BOT=null;switchBot('main')}else renderTabs();
}

// ---------- 대화방 / 메시지 ----------
function renderChats(){
 const box=$('chats');box.textContent='';
 const list=Object.values(S.chats).sort((a,b)=>b.date-a.date);
 if(!list.length){box.appendChild(el('div','empty','아직 대화가 없습니다'));return}
 for(const c of list){const d=el('div','chat'+(c.id===cur?' on':''));
  d.appendChild(el('b','',(c.type==='private'?'👤 ':c.type==='channel'?'📢 ':'👥 ')+c.title));
  d.appendChild(el('span','',c.last||''));d.onclick=()=>openChat(c.id);box.appendChild(d)}
}
function renderLog(){
 const log=$('log');const atBottom=log.scrollHeight-log.scrollTop-log.clientHeight<80;log.textContent='';
 $('clr').hidden=!cur;
 if(!cur){log.appendChild(el('div','empty','대화방을 선택하세요'));return}
 for(const m of (S.msgs[cur]||[])){
  const d=el('div','m'+(m.mine?' me':'')+(m.system?' sys':''));
  if(!m.mine&&!m.system&&S.chats[cur].type!=='private')d.appendChild(el('div','who',m.from.name+(m.from.username?' @'+m.from.username:'')));
  if(m.file)d.appendChild(fileBox(m.file));
  if(m.text)d.appendChild(document.createTextNode(m.text));
  if(!m.system)d.appendChild(el('div','t',fmt(m.date)));
  const acts=el('div','acts');
  if(m.text||m.file){const cp=el('button');cp.innerHTML=ICO.copy;cp.type='button';cp.title='메시지 복사';cp.onclick=e=>{e.stopPropagation();copyMsg(m,cp)};acts.appendChild(cp)}
  const dl=el('button');dl.innerHTML=ICO.del;dl.type='button';dl.title='이 메시지 지우기';dl.onclick=e=>{e.stopPropagation();delMsg(m)};acts.appendChild(dl);
  d.appendChild(acts);
  log.appendChild(d)}
 if(atBottom||renderLog.force){log.scrollTop=log.scrollHeight;renderLog.force=false}
}
function openChat(id){cur=id;$('title').textContent=S.chats[id].title+'  ('+id+')';
 $('tx').disabled=$('sb').disabled=$('at').disabled=false;$('app').classList.add('inchat');renderChats();renderLog.force=true;renderLog();$('tx').focus()}
$('back').onclick=()=>{$('app').classList.remove('inchat')};

// ---------- 복사 ----------
const SV='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">';const ICO={copy:SV+'<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',del:SV+'<path d="M6 6l12 12M18 6L6 18"/></svg>',ok:SV+'<path d="M5 12l5 5L20 7"/></svg>',err:SV+'<circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 17h.01"/></svg>'};async function copyText(t){
 try{await navigator.clipboard.writeText(t);return true}catch(e){}
 const ta=el('textarea');ta.value=t;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();
 let ok=false;try{ok=document.execCommand('copy')}catch(e){}ta.remove();return ok;
}
async function copyMsg(m,btn){
 const t=m.text?m.text.replace(/ \\(수정됨\\)$/,''):(m.file&&m.file.name)||'';
 if(!t)return;const ok=await copyText(t);
 btn.innerHTML=ok?ICO.ok:ICO.err;btn.title=ok?'복사됨':'복사 실패';
 setTimeout(()=>{btn.innerHTML=ICO.copy;btn.title='메시지 복사'},1200);
}

// ---------- 삭제 (서버 기록 + 이 브라우저, 텔레그램에는 남음) ----------
async function delMsg(m){const a=S.msgs[cur];if(!a)return;
 if(!confirm('이 메시지를 지울까요? (서버 기록과 이 브라우저에서 지워지고, 텔레그램에는 남습니다)'))return;
 const j=await post('/api/delete',{bot:BOT,chat_id:cur,message_id:m.message_id||0,date:m.date||0});
 if(!j.ok){alert('서버에서 지우지 못했습니다: '+(j.error||''));return}
 const k=a.indexOf(m);if(k>=0)a.splice(k,1);syncLast(cur);save();renderChats();renderLog()}
$('clr').onclick=async()=>{if(!cur)return;const n=(S.msgs[cur]||[]).length;if(!n)return;
 if(!confirm('이 대화방의 메시지 '+n+'건을 모두 지울까요? (서버 기록과 이 브라우저에서 지워지고, 텔레그램에는 남습니다)'))return;
 const j=await post('/api/delete',{bot:BOT,chat_id:cur,all:true});
 if(!j.ok){alert('서버에서 지우지 못했습니다: '+(j.error||''));return}
 S.msgs[cur]=[];syncLast(cur);save();renderChats();renderLog()};

// ---------- 서버(D1) 기록 불러오기 ----------
function loadHistory(){if(LIMITED)return;const b=BOT;
 fetch('/api/history?bot='+encodeURIComponent(b)).then(r=>r.json()).then(j=>{if(b!==BOT||!j.ok||!j.db)return;
  const by={};for(const m of j.messages){const id=String(m.chat.id);(by[id]||(by[id]=[])).push(m)}
  for(const id in by){const list=by[id],last=list[list.length-1];S.msgs[id]=list;S.chats[id]={id,title:last.chat.title,type:last.chat.type,last:preview(last),date:last.date}}
  for(const id in S.msgs){const a=S.msgs[id];if(a.length>KEEP)a.splice(0,a.length-KEEP)}
  save();renderChats();if(cur&&S.chats[cur])renderLog()}).catch(()=>{});
}

// 새 메시지 확인은 버튼을 눌렀을 때만 (여러 브라우저의 동시 getUpdates 방지)
async function check(){
 if(busy||!BOT)return;busy=true;$('rf').disabled=$('rf2').disabled=true;$('st').textContent='확인 중…';
 try{
  const r=await fetch('/api/updates?bot='+encodeURIComponent(BOT)+'&offset='+S.offset);
  if(r.status===401){location.reload();return}
  if(r.status===429){$('st').textContent='요청 제한 – 1분 후 다시 시도';return}
  const j=await r.json();
  if(!j.ok){$('st').textContent=j.code===409?'다른 곳에서 확인 중이거나 웹훅이 설정된 봇입니다':'오류: '+(j.error||r.status);return}
  if(j.messages.length){j.messages.forEach(add);renderChats();if(cur)renderLog()}
  if(j.next_offset>S.offset)S.offset=j.next_offset;save();
  $('st').textContent=(j.messages.length?'새 메시지 '+j.messages.length+'건':'새 메시지 없음')+' · '+new Date().toLocaleTimeString('ko-KR',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
 }catch(e){$('st').textContent='네트워크 오류'}
 finally{busy=false;$('rf').disabled=$('rf2').disabled=false}
}
$('rf').onclick=check;$('rf2').onclick=check;

// ---------- 파일 업로드 ----------
function progressRow(file){
 const row=el('div','up wait'),nm=el('div','nm'),lab=el('span','','⬆ '+file.name),pct=el('span','','대기 중 · '+human(file.size)),bar=el('div','bar'),fill=el('i');
 nm.append(lab,pct);bar.append(fill);row.append(nm,bar);$('ups').appendChild(row);
 return {
  set(p,loaded){row.className='up';fill.style.width=p+'%';pct.textContent=p+'% · '+human(loaded)+' / '+human(file.size)},
  phase(t){row.className='up busy';fill.style.width='100%';pct.textContent=t},
  label(t){lab.textContent=t},
  remove(){row.remove()}
 };
}
function xhrUpload(file,caption,kind,ui){
 return new Promise(res=>{
  const fd=new FormData();fd.append(kind,file,file.name||'file');
  const q='bot='+encodeURIComponent(BOT)+'&chat_id='+encodeURIComponent(cur)+'&kind='+kind+(caption?'&caption='+encodeURIComponent(caption):'');
  const x=new XMLHttpRequest();x.open('POST','/api/upload?'+q);
  ui.set(0,0);
  x.upload.onprogress=e=>{if(e.lengthComputable)ui.set(Math.round(e.loaded/e.total*100),Math.min(e.loaded,file.size))};
  x.upload.onload=()=>ui.phase('텔레그램으로 전송 중…');
  x.onload=()=>{let j={};try{j=JSON.parse(x.responseText)}catch(e){};if(!j.ok&&!j.error)j.error='HTTP '+x.status;res(j)};
  x.onerror=()=>res({ok:false,error:'네트워크 오류'});
  x.send(fd);
 });
}
async function upload(file,caption,ui){
 if(file.size>50*MB){ui.remove();alert(file.name+': 50MB를 넘는 파일은 봇으로 보낼 수 없습니다.');return false}
 if(!file.size){ui.remove();alert(file.name+': 빈 파일이거나 폴더입니다.');return false}
 const isImg=!ORIG&&/^image\\/(jpeg|png|webp)$/.test(file.type)&&file.size<=10*MB;if(ORIG&&/^image\\//.test(file.type))ui.label('⬆ '+file.name+' (원본 파일)');
 uploading++;
 try{
  let j=await xhrUpload(file,caption,isImg?'photo':'document',ui);
  if(!j.ok&&isImg){ui.label('⬆ '+file.name+' (파일로 재전송)');j=await xhrUpload(file,caption,'document',ui)}
  ui.remove();
  if(j.ok){j.message.mine=true;add(j.message);save();renderChats();renderLog.force=true;renderLog();return true}
  alert('업로드 실패 ('+file.name+'): '+j.error);return false;
 }finally{uploading--}
}
async function sendFiles(list){
 const files=[...list];if(!files.length)return;
 if(!cur){alert('먼저 대화방을 선택하세요');return}
 let cap=$('tx').value.trim();if(cap.length>1024)cap='';else if(cap){$('tx').value='';upd()}
 const rows=files.map(progressRow);
 uploading++;
 try{for(let i=0;i<files.length;i++){await upload(files[i],cap,rows[i]);cap=''}}finally{uploading--}
}
let ORIG=false;try{ORIG=localStorage.getItem('tgw_orig')==='1'}catch(e){}function setOrig(on,say){ORIG=on;const b=$('og');b.textContent=on?'💾':'🖼️';b.classList.toggle('on',on);b.setAttribute('aria-pressed',on?'true':'false');b.title=on?'이미지 전송: 원본 파일 (압축 없음) · 누르면 사진으로 전환':'이미지 전송: 사진 (텔레그램이 압축) · 누르면 원본 파일로 전환';try{localStorage.setItem('tgw_orig',on?'1':'')}catch(e){}if(say)$('st').textContent=on?'💾 이미지를 원본 파일로 보냅니다 (압축 없음)':'🖼️ 이미지를 사진으로 보냅니다 (텔레그램이 압축)'}setOrig(ORIG,false);$('og').onclick=()=>setOrig(!ORIG,true);$('at').onclick=()=>$('fi').click();
$('fi').onchange=()=>{sendFiles($('fi').files);$('fi').value=''};
$('tx').addEventListener('paste',e=>{const fs=e.clipboardData&&e.clipboardData.files;if(fs&&fs.length){e.preventDefault();sendFiles(fs)}});
let dragN=0;const main=$('main');
const hasFiles=e=>e.dataTransfer&&[...e.dataTransfer.types].includes('Files');
window.addEventListener('dragover',e=>e.preventDefault());
window.addEventListener('drop',e=>e.preventDefault());
main.addEventListener('dragenter',e=>{if(!hasFiles(e))return;e.preventDefault();dragN++;if(cur)main.classList.add('drag')});
main.addEventListener('dragleave',()=>{if(--dragN<=0){dragN=0;main.classList.remove('drag')}});
main.addEventListener('drop',e=>{e.preventDefault();dragN=0;main.classList.remove('drag');if(e.dataTransfer)sendFiles(e.dataTransfer.files)});

// ---------- 텍스트 전송 (4,096자 초과 시 분할/파일 선택) ----------
const LIMIT=4096;
function upd(){const tx=$('tx');if(!$('sf').classList.contains('big')){tx.style.height='44px';tx.style.height=tx.value?Math.max(44,Math.min(tx.scrollHeight+2,140))+'px':'44px'}const n=tx.value.length,c=$('cnt');
 if(n>3500){c.hidden=false;c.textContent=n.toLocaleString()+' / 4,096자'+(n>LIMIT?' · 전송 시 분할 또는 파일 전송을 선택합니다':'');c.classList.toggle('over',n>LIMIT)}else c.hidden=true}
$('tx').addEventListener('input',upd);
function splitText(t){
 const out=[];let rest=t;
 while(rest.length>LIMIT){
  let cut=rest.lastIndexOf('\\n',LIMIT);
  if(cut<LIMIT*0.5){cut=rest.lastIndexOf(' ',LIMIT);if(cut<LIMIT*0.5)cut=LIMIT}
  const c=rest.charCodeAt(cut-1);if(c>=0xD800&&c<=0xDBFF)cut--;
  out.push(rest.slice(0,cut));rest=rest.slice(cut).replace(/^\\n/,'');
 }
 out.push(rest);return out.filter(x=>x.trim());
}
function ask(len,n){return new Promise(res=>{
 const d=$('dlg');$('dTitle').textContent='긴 메시지 ('+len.toLocaleString()+'자)';
 $('dSplitInfo').textContent=n+'개 메시지로 순서대로 전송 · 줄바꿈 위치에서 나눔';
 d.hidden=false;$('dBox').focus();
 const done=v=>{d.hidden=true;document.removeEventListener('keydown',esc);res(v)};
 const esc=e=>{if(e.key==='Escape')done(null)};document.addEventListener('keydown',esc);
 $('dSplit').onclick=()=>done('split');$('dFile').onclick=()=>done('file');$('dCancel').onclick=()=>done(null);
 d.onclick=e=>{if(e.target===d)done(null)};
})}
async function postText(t){
 const j=await post('/api/send',{bot:BOT,chat_id:cur,text:t});
 if(j.ok){j.message.mine=true;add(j.message);save();renderChats();renderLog.force=true;renderLog()}
 return j;
}
$('sf').onsubmit=async e=>{e.preventDefault();const t=$('tx').value;if(!t.trim()||!cur||sending)return;
 let how='single',parts=[t];
 if(t.length>LIMIT){parts=splitText(t);how=await ask(t.length,parts.length);if(!how){$('tx').focus();return}}
 sending=true;$('sb').disabled=true;
 try{
  if(how==='file'){
   const d=new Date(),p=n=>String(n).padStart(2,'0');
   const name='message_'+d.getFullYear()+p(d.getMonth()+1)+p(d.getDate())+'_'+p(d.getHours())+p(d.getMinutes())+'.txt';
   const f=new File(['\\uFEFF'+t],name,{type:'text/plain'});
   const first=t.trim().split('\\n')[0].slice(0,200);
   const cap=first+' … ('+t.length.toLocaleString()+'자)';
   $('tx').value='';upd();
   if(!await upload(f,cap,progressRow(f))){$('tx').value=t;upd()}
  }else{
   for(let i=0;i<parts.length;i++){
    if(parts.length>1)$('sb').textContent=(i+1)+'/'+parts.length;
    const j=await postText(parts[i]);
    if(!j.ok){$('tx').value=parts.slice(i).join('\\n');upd();
     alert((parts.length>1?(i+1)+'번째 메시지 ':'')+'전송 실패: '+(j.error||'')+(parts.length>1?'\\n보내지 못한 내용은 입력칸에 남겨두었습니다.':''));break}
    if(i===parts.length-1){$('tx').value='';upd()}
   }
  }
 }finally{sending=false;$('sb').disabled=false;$('sb').textContent='전송';$('tx').focus()}
};
$('tx').addEventListener('keydown',e=>{if(e.key!=='Enter'||e.isComposing)return;const big=$('sf').classList.contains('big');if(big?(e.ctrlKey||e.metaKey):!e.shiftKey){e.preventDefault();$('sf').requestSubmit()}});const EXI={o:SV+'<path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/></svg>',c:SV+'<path d="M4 14h6v6M20 10h-6V4M14 10l7-7M3 21l7-7"/></svg>'};function setBig(on){const f=$('sf'),b=$('ex'),tx=$('tx');f.classList.toggle('big',on);b.innerHTML=on?EXI.c:EXI.o;b.title=on?'입력창 작게':'입력창 크게 (여러 줄 입력)';b.setAttribute('aria-pressed',on?'true':'false');tx.placeholder=on?'여러 줄 입력 모드 · Enter 줄바꿈 · Ctrl+Enter 전송':'메시지 입력 (Enter 전송, Shift+Enter 줄바꿈) · 파일은 끌어다 놓기';tx.style.height='';upd();try{localStorage.setItem('tgw_big',on?'1':'')}catch(e){}}$('ex').onclick=()=>{setBig(!$('sf').classList.contains('big'));$('tx').focus()};{let b0=false;try{b0=localStorage.getItem('tgw_big')==='1'}catch(e){}setBig(b0)}
$('out').onclick=async()=>{await fetch('/api/logout',{method:'POST'});location.reload()};

renderTabs();renderChats();
loadBots();
</script></body></html>`;
