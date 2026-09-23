require("dotenv").config();

const express = require("express");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const TelegramBot = require("node-telegram-bot-api");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_ADMIN_ID = String(process.env.TELEGRAM_ADMIN_ID || "");

if (!JWT_SECRET || !ADMIN_API_KEY) {
  console.error("Missing JWT_SECRET or ADMIN_API_KEY in .env");
  process.exit(1);
}

if (!fs.existsSync(path.join(__dirname, "data"))) {
  fs.mkdirSync(path.join(__dirname, "data"), { recursive: true });
}

const db = new Database(path.join(__dirname, "data", "licenses.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_login_at TEXT,
  login_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS login_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  username TEXT,
  success INTEGER NOT NULL,
  ip TEXT,
  user_agent TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_expires ON users(expires_at);
CREATE INDEX IF NOT EXISTS idx_logs_created ON login_logs(created_at);
`);

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "20kb" }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 25,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { ok: false, error: "Too many login attempts. Try again later." }
});

app.use(express.static(path.join(__dirname, "public")));

function nowIso() {
  return new Date().toISOString();
}

function parseDuration(value, unit) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0 || n > 3650) {
    throw new Error("Invalid duration");
  }
  const ms = {
    minute: 60 * 1000,
    minutes: 60 * 1000,
    hour: 60 * 60 * 1000,
    hours: 60 * 60 * 1000,
    day: 24 * 60 * 60 * 1000,
    days: 24 * 60 * 60 * 1000
  }[String(unit).toLowerCase()];
  if (!ms) throw new Error("Unit must be minutes, hours, or days");
  return n * ms;
}

function normalizeUsername(username) {
  return String(username || "").trim();
}

function validateUsername(username) {
  return /^[A-Za-z0-9_.-]{3,32}$/.test(username);
}

function publicUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    active: Boolean(row.active),
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    expired: new Date(row.expires_at).getTime() <= Date.now(),
    lastLoginAt: row.last_login_at,
    loginCount: row.login_count
  };
}

function adminAuth(req, res, next) {
  const supplied = req.get("x-admin-api-key");
  if (!supplied || supplied.length !== ADMIN_API_KEY.length ||
      !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(ADMIN_API_KEY))) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  next();
}

function issueToken(user) {
  return jwt.sign(
    { sub: String(user.id), username: user.username, type: "license" },
    JWT_SECRET,
    { expiresIn: "12h", issuer: "license-server" }
  );
}

function requireLicense(req, res, next) {
  try {
    const auth = req.get("authorization") || "";
    if (!auth.startsWith("Bearer ")) {
      return res.status(401).json({ ok: false, error: "Missing token" });
    }

    const payload = jwt.verify(auth.slice(7), JWT_SECRET, {
      issuer: "license-server"
    });

    const row = db.prepare("SELECT * FROM users WHERE id = ?").get(Number(payload.sub));
    if (!row || !row.active) {
      return res.status(401).json({ ok: false, error: "Account disabled" });
    }

    if (new Date(row.expires_at).getTime() <= Date.now()) {
      return res.status(401).json({ ok: false, error: "Account expired" });
    }

    req.licenseUser = row;
    next();
  } catch {
    return res.status(401).json({ ok: false, error: "Invalid or expired token" });
  }
}

/* Health */
app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "secure-license-server", time: nowIso() });
});

/* Login */
app.post("/api/login", loginLimiter, async (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || "");

  if (!username || !password) {
    return res.status(400).json({ ok: false, error: "Username and password are required" });
  }

  const row = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  const ip = req.ip;
  const ua = req.get("user-agent") || "";
  const created = nowIso();

  let success = false;
  if (row) {
    success = await bcrypt.compare(password, row.password_hash);
  }

  db.prepare(`
    INSERT INTO login_logs(user_id, username, success, ip, user_agent, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(row ? row.id : null, username, success ? 1 : 0, ip, ua, created);

  if (!success || !row.active) {
    return res.status(401).json({ ok: false, error: "Invalid username or password" });
  }

  if (new Date(row.expires_at).getTime() <= Date.now()) {
    return res.status(403).json({ ok: false, error: "Account expired", expiresAt: row.expires_at });
  }

  db.prepare(`
    UPDATE users
    SET last_login_at = ?, login_count = login_count + 1
    WHERE id = ?
  `).run(created, row.id);

  const fresh = db.prepare("SELECT * FROM users WHERE id = ?").get(row.id);
  res.json({
    ok: true,
    token: issueToken(fresh),
    user: publicUser(fresh)
  });
});

/* Authenticated account info */
app.get("/api/me", requireLicense, (req, res) => {
  res.json({ ok: true, user: publicUser(req.licenseUser) });
});

/* Admin: create */
app.post("/api/admin/users", adminAuth, async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username);
    const password = String(req.body.password || "");
    const duration = Number(req.body.duration);
    const unit = req.body.unit;

    if (!validateUsername(username)) {
      return res.status(400).json({
        ok: false,
        error: "Username must be 3-32 characters: letters, numbers, _, ., -"
      });
    }
    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({ ok: false, error: "Password must be 8-128 characters" });
    }

    const ms = parseDuration(duration, unit);
    const created = new Date();
    const expires = new Date(created.getTime() + ms);
    const hash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users(username, password_hash, active, created_at, expires_at)
      VALUES (?, ?, 1, ?, ?)
    `).run(username, hash, created.toISOString(), expires.toISOString());

    const row = db.prepare("SELECT * FROM users WHERE id = ?").get(result.lastInsertRowid);
    res.status(201).json({ ok: true, user: publicUser(row) });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) {
      return res.status(409).json({ ok: false, error: "Username already exists" });
    }
    res.status(400).json({ ok: false, error: e.message });
  }
});

/* Admin: list */
app.get("/api/admin/users", adminAuth, (req, res) => {
  const rows = db.prepare("SELECT * FROM users ORDER BY created_at DESC").all();
  res.json({ ok: true, users: rows.map(publicUser) });
});

/* Admin: find */
app.get("/api/admin/users/:username", adminAuth, (req, res) => {
  const row = db.prepare("SELECT * FROM users WHERE username = ?").get(req.params.username);
  if (!row) return res.status(404).json({ ok: false, error: "User not found" });
  res.json({ ok: true, user: publicUser(row) });
});

/* Admin: extend */
app.post("/api/admin/users/:username/extend", adminAuth, (req, res) => {
  try {
    const row = db.prepare("SELECT * FROM users WHERE username = ?").get(req.params.username);
    if (!row) return res.status(404).json({ ok: false, error: "User not found" });

    const ms = parseDuration(req.body.duration, req.body.unit);
    const current = Math.max(Date.now(), new Date(row.expires_at).getTime());
    const expires = new Date(current + ms).toISOString();

    db.prepare("UPDATE users SET expires_at = ? WHERE id = ?").run(expires, row.id);
    const fresh = db.prepare("SELECT * FROM users WHERE id = ?").get(row.id);
    res.json({ ok: true, user: publicUser(fresh) });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

/* Admin: enable/disable */
app.post("/api/admin/users/:username/status", adminAuth, (req, res) => {
  const row = db.prepare("SELECT * FROM users WHERE username = ?").get(req.params.username);
  if (!row) return res.status(404).json({ ok: false, error: "User not found" });

  const active = req.body.active ? 1 : 0;
  db.prepare("UPDATE users SET active = ? WHERE id = ?").run(active, row.id);
  const fresh = db.prepare("SELECT * FROM users WHERE id = ?").get(row.id);
  res.json({ ok: true, user: publicUser(fresh) });
});

/* Admin: delete */
app.delete("/api/admin/users/:username", adminAuth, (req, res) => {
  const result = db.prepare("DELETE FROM users WHERE username = ?").run(req.params.username);
  if (!result.changes) return res.status(404).json({ ok: false, error: "User not found" });
  res.json({ ok: true });
});

/* Admin: logs */
app.get("/api/admin/logs", adminAuth, (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 500);
  const rows = db.prepare(`
    SELECT id, user_id, username, success, ip, user_agent, created_at
    FROM login_logs
    ORDER BY id DESC LIMIT ?
  `).all(limit);
  res.json({ ok: true, logs: rows });
});

/* Telegram bot */
let bot = null;

function telegramAdminOnly(msg) {
  return TELEGRAM_ADMIN_ID && String(msg.from?.id) === TELEGRAM_ADMIN_ID;
}

function durationText(ms) {
  const mins = Math.round(ms / 60000);
  if (mins % (60 * 24) === 0) return `${mins / (60 * 24)}d`;
  if (mins % 60 === 0) return `${mins / 60}h`;
  return `${mins}m`;
}

function formatUser(row) {
  const remaining = new Date(row.expires_at).getTime() - Date.now();
  return [
    `👤 ${row.username}`,
    `Status: ${row.active ? "Active" : "Disabled"}`,
    `Created: ${row.created_at}`,
    `Expires: ${row.expires_at}`,
    `Remaining: ${remaining > 0 ? durationText(remaining) : "Expired"}`,
    `Logins: ${row.login_count}`
  ].join("\n");
}

function telegramHelp() {
  return [
    "🔐 License Admin",
    "",
    "/add username password 30d",
    "/users",
    "/info username",
    "/extend username 7d",
    "/enable username",
    "/disable username",
    "/delete username",
    "/logs",
    "/help",
    "",
    "Duration: m/min, h/hour, d/day"
  ].join("\n");
}

function parseTelegramDuration(s) {
  const m = /^([1-9]\\d*)(m|min|minute|minutes|h|hr|hour|hours|d|day|days)$/i.exec(s || "");
  if (!m) throw new Error("Duration example: 30d, 12h, 90m");
  const unitMap = { m:"minutes",min:"minutes",minute:"minutes",minutes:"minutes",
                    h:"hours",hr:"hours",hour:"hours",hours:"hours",
                    d:"days",day:"days",days:"days" };
  return { duration: Number(m[1]), unit: unitMap[m[2].toLowerCase()] };
}

if (TELEGRAM_BOT_TOKEN && TELEGRAM_ADMIN_ID) {
  bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true });

  bot.onText(/^\/start$/, msg => {
    if (telegramAdminOnly(msg)) bot.sendMessage(msg.chat.id, telegramHelp());
  });

  bot.onText(/^\/help$/, msg => {
    if (telegramAdminOnly(msg)) bot.sendMessage(msg.chat.id, telegramHelp());
  });

  bot.onText(/^\/add\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)$/, async (msg, match) => {
    if (!telegramAdminOnly(msg)) return;
    try {
      const username = normalizeUsername(match[1]);
      const password = match[2];
      const d = parseTelegramDuration(match[3]);

      if (!validateUsername(username)) throw new Error("Invalid username");
      if (password.length < 8) throw new Error("Password must be at least 8 characters");

      const hash = await bcrypt.hash(password, 12);
      const created = new Date();
      const expires = new Date(created.getTime() + parseDuration(d.duration, d.unit));

      const result = db.prepare(`
        INSERT INTO users(username, password_hash, active, created_at, expires_at)
        VALUES (?, ?, 1, ?, ?)
      `).run(username, hash, created.toISOString(), expires.toISOString());

      const row = db.prepare("SELECT * FROM users WHERE id = ?").get(result.lastInsertRowid);
      await bot.sendMessage(msg.chat.id, "✅ Account created\\n\\n" + formatUser(row));
    } catch (e) {
      await bot.sendMessage(msg.chat.id, "❌ " + (String(e.message).includes("UNIQUE")
        ? "Username already exists"
        : e.message));
    }
  });

  bot.onText(/^\/users$/, async msg => {
    if (!telegramAdminOnly(msg)) return;
    const rows = db.prepare("SELECT * FROM users ORDER BY expires_at ASC").all();
    if (!rows.length) return bot.sendMessage(msg.chat.id, "No accounts.");
    const text = rows.map((r, i) => `${i + 1}. ${r.username} — ${r.active ? "ON" : "OFF"} — ${r.expires_at}`).join("\n");
    await bot.sendMessage(msg.chat.id, "👥 Accounts\n\n" + text);
  });

  bot.onText(/^\/info\\s+(\\S+)$/, async (msg, match) => {
    if (!telegramAdminOnly(msg)) return;
    const row = db.prepare("SELECT * FROM users WHERE username = ?").get(match[1]);
    await bot.sendMessage(msg.chat.id, row ? formatUser(row) : "❌ User not found");
  });

  bot.onText(/^\/extend\\s+(\\S+)\\s+(\\S+)$/, async (msg, match) => {
    if (!telegramAdminOnly(msg)) return;
    try {
      const row = db.prepare("SELECT * FROM users WHERE username = ?").get(match[1]);
      if (!row) throw new Error("User not found");
      const d = parseTelegramDuration(match[2]);
      const newExpiry = new Date(
        Math.max(Date.now(), new Date(row.expires_at).getTime()) +
        parseDuration(d.duration, d.unit)
      ).toISOString();

      db.prepare("UPDATE users SET expires_at = ? WHERE id = ?").run(newExpiry, row.id);
      const fresh = db.prepare("SELECT * FROM users WHERE id = ?").get(row.id);
      await bot.sendMessage(msg.chat.id, "✅ Extended\\n\\n" + formatUser(fresh));
    } catch (e) {
      await bot.sendMessage(msg.chat.id, "❌ " + e.message);
    }
  });

  for (const [command, active] of [["enable",1],["disable",0]]) {
    bot.onText(new RegExp(`^\\/${command}\\\\s+(\\\\S+)$`), async (msg, match) => {
      if (!telegramAdminOnly(msg)) return;
      const row = db.prepare("SELECT * FROM users WHERE username = ?").get(match[1]);
      if (!row) return bot.sendMessage(msg.chat.id, "❌ User not found");
      db.prepare("UPDATE users SET active = ? WHERE id = ?").run(active, row.id);
      const fresh = db.prepare("SELECT * FROM users WHERE id = ?").get(row.id);
      await bot.sendMessage(msg.chat.id, `✅ ${command}:\\n\\n` + formatUser(fresh));
    });
  }

  bot.onText(/^\/delete\\s+(\\S+)$/, async (msg, match) => {
    if (!telegramAdminOnly(msg)) return;
    const result = db.prepare("DELETE FROM users WHERE username = ?").run(match[1]);
    await bot.sendMessage(msg.chat.id, result.changes ? "🗑️ Deleted" : "❌ User not found");
  });

  bot.onText(/^\/logs$/, async msg => {
    if (!telegramAdminOnly(msg)) return;
    const rows = db.prepare(`
      SELECT username, success, ip, created_at
      FROM login_logs ORDER BY id DESC LIMIT 20
    `).all();

    if (!rows.length) return bot.sendMessage(msg.chat.id, "No login logs.");
    const text = rows.map(r =>
      `${r.success ? "✅" : "❌"} ${r.username} | ${r.created_at} | ${r.ip || "-"}`
    ).join("\n");
    await bot.sendMessage(msg.chat.id, "📝 Last 20 logins\\n\\n" + text);
  });

  bot.on("polling_error", err => console.error("Telegram polling error:", err.message));
  console.log("Telegram admin bot enabled.");
} else {
  console.log("Telegram bot disabled: configure TELEGRAM_BOT_TOKEN and TELEGRAM_ADMIN_ID.");
}

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ ok: false, error: "Internal server error" });
});

app.listen(PORT, () => {
  console.log(`License server running on port ${PORT}`);
});
