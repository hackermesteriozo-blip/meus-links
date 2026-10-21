import "dotenv/config";
import express from "express";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import fs from "node:fs";
import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { Server } from "socket.io";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: false } });
const PORT = Number(process.env.PORT || 3000);
const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET.length < 32) {
  console.error("Configure JWT_SECRET com pelo menos 32 caracteres no ambiente.");
  process.exit(1);
}
const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "matrysarts.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin','owner')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL REFERENCES users(id),
  recipient_id INTEGER REFERENCES users(id),
  room TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS messages_room_id ON messages(room, id);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  items_json TEXT NOT NULL,
  total_cents INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','paid','completed','cancelled')),
  payment_note TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

const ownerEmail = (process.env.OWNER_EMAIL || "").trim().toLowerCase();
const ownerPassword = process.env.OWNER_PASSWORD || "";
const ownerName = (process.env.OWNER_NAME || "Fundador MatrysArts").trim();
if (ownerEmail && ownerPassword.length >= 12) {
  const existing = db.prepare("SELECT id FROM users WHERE email=?").get(ownerEmail);
  if (!existing) {
    const hash = bcrypt.hashSync(ownerPassword, 12);
    db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'owner')")
      .run(ownerName.slice(0,70), ownerEmail, hash);
    console.log("Conta do fundador criada a partir das variáveis de ambiente.");
  }
} else {
  console.warn("OWNER_EMAIL/OWNER_PASSWORD não configurados ou senha menor que 12 caracteres; configure antes de publicar.");
}

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "30kb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });
const chatLimiter = rateLimit({ windowMs: 60 * 1000, limit: 90, standardHeaders: true, legacyHeaders: false });

function publicUser(row) {
  return { id: row.id, name: row.name, email: row.email, role: row.role, createdAt: row.created_at };
}
function makeToken(user) {
  return jwt.sign({ sub: user.id, role: user.role }, SECRET, { expiresIn: "7d", issuer: "matrysarts" });
}
function setAuthCookie(res, token) {
  res.cookie("matrys_session", token, {
    httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000, path: "/"
  });
}
function getUserFromRequest(req) {
  const token = req.cookies?.matrys_session;
  if (!token) return null;
  try {
    const payload = jwt.verify(token, SECRET, { issuer: "matrysarts" });
    return db.prepare("SELECT id,name,email,role,created_at FROM users WHERE id=?").get(Number(payload.sub)) || null;
  } catch { return null; }
}
function requireAuth(req, res, next) {
  const user = getUserFromRequest(req);
  if (!user) return res.status(401).json({ error: "Entre na sua conta para continuar." });
  req.user = user;
  next();
}
function requireStaff(req, res, next) {
  if (!["admin", "owner"].includes(req.user.role)) return res.status(403).json({ error: "Apenas administradores podem acessar esta função." });
  next();
}
function cleanText(value, max = 1000) {
  return String(value ?? "").replace(/\u0000/g, "").trim().slice(0, max);
}
function moneyToCents(value) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 && n <= 100000 ? Math.round(n * 100) : 0;
}

app.get("/api/health", (_req, res) => res.json({ ok: true, service: "MatrysArts PRO" }));

app.post("/api/auth/register", authLimiter, async (req, res) => {
  const name = cleanText(req.body?.name, 70);
  const email = cleanText(req.body?.email, 160).toLowerCase();
  const password = String(req.body?.password || "");
  if (name.length < 2) return res.status(400).json({ error: "Informe um nome com pelo menos 2 caracteres." });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Informe um e-mail válido." });
  if (password.length < 10 || password.length > 128) return res.status(400).json({ error: "A senha precisa ter de 10 a 128 caracteres." });
  if (db.prepare("SELECT id FROM users WHERE email=?").get(email)) return res.status(409).json({ error: "Este e-mail já possui conta." });
  const hash = await bcrypt.hash(password, 12);
  try {
    const result = db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'user')").run(name, email, hash);
    const user = db.prepare("SELECT id,name,email,role,created_at FROM users WHERE id=?").get(result.lastInsertRowid);
    setAuthCookie(res, makeToken(user));
    res.status(201).json({ user: publicUser(user) });
  } catch { res.status(500).json({ error: "Não foi possível criar a conta." }); }
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  const email = cleanText(req.body?.email, 160).toLowerCase();
  const password = String(req.body?.password || "");
  const row = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  const valid = row ? await bcrypt.compare(password, row.password_hash) : false;
  if (!valid) return res.status(401).json({ error: "E-mail ou senha incorretos." });
  setAuthCookie(res, makeToken(row));
  res.json({ user: publicUser(row) });
});

app.post("/api/auth/logout", (_req, res) => {
  res.clearCookie("matrys_session", { path: "/", sameSite: "lax", secure: process.env.NODE_ENV === "production" });
  res.json({ ok: true });
});
app.get("/api/auth/me", (req, res) => {
  const user = getUserFromRequest(req);
  res.json({ user: user ? publicUser(user) : null });
});

app.get("/api/users", requireAuth, (req, res) => {
  // Não revela e-mails nem dados sensíveis a outros clientes.
  const users = db.prepare("SELECT id,name,role FROM users ORDER BY name COLLATE NOCASE LIMIT 100").all();
  res.json({ users: users.map(u => ({ id: u.id, name: u.name, role: u.role })) });
});

app.get("/api/chat/history", requireAuth, (req, res) => {
  const kind = cleanText(req.query.kind, 10);
  let rows;
  if (kind === "public") {
    rows = db.prepare(`SELECT m.id,m.room,m.body,m.created_at,u.id AS sender_id,u.name AS sender_name,u.role AS sender_role
      FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.room='public' ORDER BY m.id DESC LIMIT 80`).all().reverse();
  } else {
    const otherId = Number(req.query.userId);
    if (!Number.isInteger(otherId) || otherId < 1 || otherId === req.user.id) return res.status(400).json({ error: "Escolha uma pessoa válida para o chat privado." });
    const room = privateRoom(req.user.id, otherId);
    rows = db.prepare(`SELECT m.id,m.room,m.body,m.created_at,u.id AS sender_id,u.name AS sender_name,u.role AS sender_role
      FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.room=? ORDER BY m.id DESC LIMIT 80`).all(room).reverse();
  }
  res.json({ messages: rows.map(formatMessage) });
});

function privateRoom(a, b) {
  return `private:${Math.min(Number(a), Number(b))}:${Math.max(Number(a), Number(b))}`;
}
function formatMessage(row) {
  return { id: row.id, room: row.room, body: row.body, createdAt: row.created_at,
    sender: { id: row.sender_id, name: row.sender_name, role: row.sender_role } };
}
function socketUser(socket) {
  const token = socket.handshake.headers.cookie?.split(";").map(v => v.trim()).find(v => v.startsWith("matrys_session="))?.slice("matrys_session=".length);
  if (!token) return null;
  try {
    const p = jwt.verify(decodeURIComponent(token), SECRET, { issuer: "matrysarts" });
    return db.prepare("SELECT id,name,email,role,created_at FROM users WHERE id=?").get(Number(p.sub)) || null;
  } catch { return null; }
}
io.use((socket, next) => {
  const user = socketUser(socket);
  if (!user) return next(new Error("Faça login para usar o chat."));
  socket.user = user;
  next();
});
io.on("connection", socket => {
  const user = socket.user;
  socket.join("public");
  socket.emit("chat:ready", { user: publicUser(user) });

  socket.on("chat:join-private", (payload = {}) => {
    const otherId = Number(payload.userId);
    if (!Number.isInteger(otherId) || otherId < 1 || otherId === user.id) return;
    socket.join(privateRoom(user.id, otherId));
  });

  socket.on("chat:send", (payload = {}, callback = () => {}) => {
    const body = cleanText(payload.body, 1000);
    const kind = payload.kind === "private" ? "private" : "public";
    if (!body) return callback({ error: "Digite uma mensagem." });
    if (body.length > 1000) return callback({ error: "Mensagem muito longa." });
    let room = "public";
    let recipient = null;
    if (kind === "private") {
      recipient = Number(payload.userId);
      if (!Number.isInteger(recipient) || recipient < 1 || recipient === user.id) return callback({ error: "Destinatário inválido." });
      room = privateRoom(user.id, recipient);
      // Somente participantes podem entrar na sala privada; o servidor sempre controla o nome da sala.
      socket.join(room);
    }
    const result = db.prepare("INSERT INTO messages(sender_id,recipient_id,room,body) VALUES(?,?,?,?)")
      .run(user.id, recipient, room, body);
    const row = db.prepare(`SELECT m.id,m.room,m.body,m.created_at,u.id AS sender_id,u.name AS sender_name,u.role AS sender_role
      FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?`).get(result.lastInsertRowid);
    const msg = formatMessage(row);
    io.to(room).emit("chat:message", msg);
    callback({ ok: true, id: msg.id });
  });
});

app.post("/api/orders", requireAuth, (req, res) => {
  const items = Array.isArray(req.body?.items) ? req.body.items.slice(0, 20) : [];
  if (!items.length) return res.status(400).json({ error: "Adicione produtos ao pedido." });
  const cleanItems = items.map(item => ({
    name: cleanText(item?.name, 100),
    quantity: Math.max(1, Math.min(99, Number.parseInt(item?.quantity, 10) || 1)),
    unitPrice: Math.max(0, Math.min(100000, Number(item?.unitPrice) || 0))
  })).filter(item => item.name);
  if (!cleanItems.length) return res.status(400).json({ error: "Itens inválidos." });
  // Preços devem ser confirmados pelo dono; não use esse total como cobrança automática.
  const total = cleanItems.reduce((sum, item) => sum + Math.round(item.unitPrice * 100) * item.quantity, 0);
  const result = db.prepare("INSERT INTO orders(user_id,items_json,total_cents) VALUES(?,?,?)")
    .run(req.user.id, JSON.stringify(cleanItems), total);
  res.status(201).json({ order: { id: result.lastInsertRowid, status: "pending", items: cleanItems, totalCents: total } });
});

app.get("/api/orders/mine", requireAuth, (req, res) => {
  const orders = db.prepare("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 100").all(req.user.id);
  res.json({ orders: orders.map(formatOrder) });
});
function formatOrder(o) {
  return { id: o.id, userId: o.user_id, items: JSON.parse(o.items_json), totalCents: o.total_cents,
    status: o.status, paymentNote: o.payment_note, createdAt: o.created_at, updatedAt: o.updated_at };
}
app.get("/api/admin/orders", requireAuth, requireStaff, (_req, res) => {
  const orders = db.prepare(`SELECT o.*,u.name AS customer_name,u.email AS customer_email
    FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 200`).all();
  res.json({ orders: orders.map(o => ({ ...formatOrder(o), customer: { name: o.customer_name, email: o.customer_email } })) });
});
app.patch("/api/admin/orders/:id", requireAuth, requireStaff, (req, res) => {
  const id = Number(req.params.id);
  const status = cleanText(req.body?.status, 20);
  const note = cleanText(req.body?.paymentNote, 300);
  if (!Number.isInteger(id) || !["pending","approved","paid","completed","cancelled"].includes(status)) return res.status(400).json({ error: "Status inválido." });
  const result = db.prepare("UPDATE orders SET status=?,payment_note=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(status, note, id);
  if (!result.changes) return res.status(404).json({ error: "Pedido não encontrado." });
  res.json({ ok: true });
});
app.get("/api/ranking", (_req, res) => {
  const rows = db.prepare(`SELECT u.id,u.name,COUNT(o.id) AS purchases,SUM(o.total_cents) AS total_cents
    FROM users u JOIN orders o ON o.user_id=u.id
    WHERE o.status IN ('paid','completed')
    GROUP BY u.id ORDER BY purchases DESC,total_cents DESC,u.name COLLATE NOCASE ASC LIMIT 20`).all();
  res.json({ ranking: rows.map((r, i) => ({ position: i + 1, name: r.name, purchases: r.purchases, totalCents: r.total_cents || 0 })) });
});

app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api/")) return next();
  res.sendFile(path.join(__dirname, "public", "index.html"));
});
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "Erro interno. Tente novamente." });
});

server.listen(PORT, () => console.log(`MatrysArts PRO online em http://localhost:${PORT}`));
