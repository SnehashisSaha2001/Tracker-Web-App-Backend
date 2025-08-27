// tracker_backend.js
// 🚀 Unified Tracker Backend (Express + PostgreSQL + Socket.IO)
// Tailor-fit for Tracker frontend (EmployeeId/Mobile login, profile, backups)

import express from "express";
import cors from "cors";
import helmet from "helmet";
import http from "http";
import { Server } from "socket.io";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

// ---------------- DB Setup ----------------
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: /localhost|127.0.0.1/.test(process.env.DATABASE_URL || "")
    ? false
    : { rejectUnauthorized: false },
});
async function query(q, params) {
  return pool.query(q, params);
}

// ---------------- Helpers ----------------
function signJwt(payload, expiresIn = "7d") {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn });
}
function requireAuth(req, res, next) {
  try {
    const hdr = req.headers.authorization || "";
    const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Missing token" });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ---------------- Express App ----------------
const app = express();
const allowed = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (allowed.includes(origin)) return cb(null, true);
      return cb(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);
app.use(helmet());
app.use(express.json({ limit: "1mb" }));

// ---------------- Migrations ----------------
async function migrate() {
  const sql = `
  CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

  CREATE TABLE IF NOT EXISTS orgs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );

  CREATE TYPE IF NOT EXISTS user_role AS ENUM ('admin','employee');

  DO $$ BEGIN
    CREATE TYPE task_status AS ENUM ('todo','in_progress','done','blocked');
  EXCEPTION WHEN duplicate_object THEN null; END $$;

  CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES orgs(id) ON DELETE CASCADE,
    role user_role NOT NULL,
    name TEXT NOT NULL,
    email TEXT UNIQUE,
    employee_id TEXT UNIQUE,
    mobile TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    photo_url TEXT,
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );

  CREATE TABLE IF NOT EXISTS locations (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    lat DOUBLE PRECISION NOT NULL,
    lng DOUBLE PRECISION NOT NULL,
    accuracy DOUBLE PRECISION,
    battery NUMERIC,
    ts TIMESTAMPTZ NOT NULL DEFAULT now()
  );

  CREATE TABLE IF NOT EXISTS tasks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES orgs(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT,
    assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
    status task_status NOT NULL DEFAULT 'todo',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );

  CREATE TABLE IF NOT EXISTS backups (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    org_id UUID REFERENCES orgs(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  `;
  await query(sql);
  console.log("✅ Migration complete");
}

// ---------------- Routes ----------------

// Root
app.get("/", (req, res) => res.json({ ok: true, uptime: process.uptime() }));

// Auth: Seed org + admin
app.post("/api/auth/seed", async (req, res) => {
  const { orgName, adminName, adminEmployeeId, adminMobile, adminEmail, adminPassword } = req.body;
  if (!orgName || !adminName || !adminEmployeeId || !adminMobile || !adminPassword)
    return res.status(400).json({ error: "Missing fields" });
  const pw = await bcrypt.hash(adminPassword, 10);
  try {
    const org = await query("INSERT INTO orgs(name) VALUES($1) RETURNING *", [orgName]);
    const admin = await query(
      `INSERT INTO users(org_id, role, name, email, employee_id, mobile, password_hash)
       VALUES($1,$2,$3,$4,$5,$6,$7)
       RETURNING id, org_id, role, name, email, employee_id, mobile, photo_url`,
      [org.rows[0].id, "admin", adminName, adminEmail ?? null, adminEmployeeId, adminMobile, pw]
    );
    const token = signJwt(admin.rows[0]);
    res.json({ org: org.rows[0], admin: admin.rows[0], token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Seed failed" });
  }
});

// Register user
app.post("/api/auth/register", async (req, res) => {
  const { orgId, name, employeeId, mobile, email, password, role = "employee", photoUrl } = req.body;
  if (!orgId || !name || !employeeId || !mobile || !password)
    return res.status(400).json({ error: "Missing fields" });
  const pw = await bcrypt.hash(password, 10);
  try {
    const u = await query(
      `INSERT INTO users(org_id, role, name, email, password_hash, employee_id, mobile, photo_url)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING id, org_id, role, name, email, employee_id, mobile, photo_url`,
      [orgId, role, name, email ?? null, pw, employeeId, mobile, photoUrl ?? null]
    );
    res.json({ user: u.rows[0] });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "User already exists" });
    console.error(e);
    res.status(500).json({ error: "Register failed" });
  }
});

// Login (Employee ID or Mobile)
app.post("/api/auth/login", async (req, res) => {
  const { employeeId, mobile, password } = req.body;
  let rs;
  if (employeeId) rs = await query("SELECT * FROM users WHERE employee_id=$1", [employeeId]);
  else if (mobile) rs = await query("SELECT * FROM users WHERE mobile=$1", [mobile]);
  else return res.status(400).json({ error: "Employee ID or Mobile required" });

  if (!rs.rowCount) return res.status(401).json({ error: "Invalid credentials" });
  const u = rs.rows[0];
  const ok = await bcrypt.compare(password, u.password_hash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const { id, org_id, role, name, employee_id, mobile: mob, email, photo_url } = u;
  const token = signJwt({ id, org_id, role, name, employeeId: employee_id, mobile: mob });
  res.json({
    token,
    user: { id, org_id, role, name, employeeId: employee_id, mobile: mob, email, photoUrl: photo_url }
  });
});

// Get all users
app.get("/api/users", requireAuth, async (req, res) => {
  const rs = await query(
    "SELECT id, name, email, role, org_id, employee_id, mobile, photo_url, last_seen FROM users WHERE org_id=$1 ORDER BY name",
    [req.user.org_id]
  );
  res.json({ users: rs.rows });
});

// Profile update
app.patch("/api/users/me", requireAuth, async (req, res) => {
  const { name, mobile, email, password, photoUrl } = req.body;
  let pwHash = null;
  if (password) pwHash = await bcrypt.hash(password, 10);

  const rs = await query(
    `UPDATE users SET
      name = COALESCE($2,name),
      mobile = COALESCE($3,mobile),
      email = COALESCE($4,email),
      password_hash = COALESCE($5,password_hash),
      photo_url = COALESCE($6,photo_url)
     WHERE id=$1
     RETURNING id, org_id, role, name, employee_id, mobile, email, photo_url`,
    [req.user.id, name ?? null, mobile ?? null, email ?? null, pwHash, photoUrl ?? null]
  );
  res.json({ user: rs.rows[0] });
});

// Locations
app.post("/api/locations", requireAuth, async (req, res) => {
  const { lat, lng, accuracy, battery, ts } = req.body;
  if (typeof lat !== "number" || typeof lng !== "number")
    return res.status(400).json({ error: "lat/lng required" });
  const rs = await query(
    "INSERT INTO locations(user_id, lat, lng, accuracy, battery, ts) VALUES($1,$2,$3,$4,$5, COALESCE($6, now())) RETURNING *",
    [req.user.id, lat, lng, accuracy ?? null, battery ?? null, ts ?? null]
  );
  await query("UPDATE users SET last_seen=now() WHERE id=$1", [req.user.id]);
  req.app.get("io").to(`org:${req.user.org_id}`).emit("location:update", {
    user_id: req.user.id, name: req.user.name, lat, lng, accuracy, battery, ts: rs.rows[0].ts
  });
  res.json({ location: rs.rows[0] });
});

app.get("/api/locations/recent", requireAuth, async (req, res) => {
  const { sinceMinutes = 180 } = req.query;
  const rs = await query(
    `SELECT l.*, u.name, u.employee_id FROM locations l
     JOIN users u ON u.id=l.user_id
     WHERE u.org_id=$1 AND l.ts > now() - ($2::int || ' minutes')::interval
     ORDER BY l.ts DESC LIMIT 2000`,
    [req.user.org_id, sinceMinutes]
  );
  res.json({ locations: rs.rows });
});

// Tasks (Follow-ups)
app.get("/api/tasks", requireAuth, async (req, res) => {
  const rs = await query(
    "SELECT * FROM tasks WHERE org_id=$1 ORDER BY updated_at DESC LIMIT 500",
    [req.user.org_id]
  );
  res.json({ tasks: rs.rows });
});
app.post("/api/tasks", requireAuth, async (req, res) => {
  const { title, description, assigned_to } = req.body;
  const rs = await query(
    "INSERT INTO tasks(org_id, title, description, assigned_to) VALUES($1,$2,$3,$4) RETURNING *",
    [req.user.org_id, title, description ?? null, assigned_to ?? null]
  );
  const task = rs.rows[0];
  req.app.get("io").to(`org:${req.user.org_id}`).emit("task:create", task);
  res.json({ task });
});

// Backups
app.post("/api/backups", requireAuth, async (req, res) => {
  try {
    const { type, payload } = req.body;
    if (!type || !payload) return res.status(400).json({ error: "Missing type or payload" });
    const rs = await query(
      `INSERT INTO backups (user_id, org_id, type, payload) VALUES ($1,$2,$3,$4) RETURNING *`,
      [req.user.id, req.user.org_id, type, JSON.stringify(payload)]
    );
    res.json({ backup: rs.rows[0] });
  } catch (e) {
    console.error("❌ Backup save failed:", e);
    res.status(500).json({ error: "Backup save failed" });
  }
});
app.get("/api/backups", requireAuth, async (req, res) => {
  try {
    const rs = await query(
      "SELECT * FROM backups WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100",
      [req.user.id]
    );
    res.json({ backups: rs.rows });
  } catch (e) {
    console.error("❌ Fetch backups failed:", e);
    res.status(500).json({ error: "Fetch failed" });
  }
});

// ---------------- Socket.IO ----------------
function attachSockets(io) {
  io.use((socket, next) => {
    try {
      const token = socket.handshake.auth?.token || socket.handshake.headers["x-auth-token"];
      if (!token) return next(new Error("Missing token"));
      const user = jwt.verify(token, process.env.JWT_SECRET);
      socket.user = user;
      return next();
    } catch (e) {
      return next(new Error("Bad token"));
    }
  });
  io.on("connection", async (socket) => {
    const { org_id, id: user_id } = socket.user;
    const room = `org:${org_id}`;
    socket.join(room);
    await query("UPDATE users SET last_seen=now() WHERE id=$1", [user_id]);
    io.to(room).emit("presence:online", { user_id });
    socket.on("location:push", async (payload) => {
      const { lat, lng, accuracy, battery, ts } = payload || {};
      if (typeof lat !== "number" || typeof lng !== "number") return;
      const rs = await query(
        "INSERT INTO locations(user_id, lat, lng, accuracy, battery, ts) VALUES($1,$2,$3,$4,$5, COALESCE($6, now())) RETURNING ts",
        [user_id, lat, lng, accuracy ?? null, battery ?? null, ts ?? null]
      );
      await query("UPDATE users SET last_seen=now() WHERE id=$1", [user_id]);
      io.to(room).emit("location:update", { user_id, name: socket.user.name, lat, lng, accuracy, battery, ts: rs.rows[0].ts });
    });
    socket.on("disconnect", async () => {
      await query("UPDATE users SET last_seen=now() WHERE id=$1", [user_id]);
      io.to(room).emit("presence:offline", { user_id });
    });
  });
}

// ---------------- Start Server ----------------
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: allowed } });
attachSockets(io);
app.set("io", io);

const PORT = process.env.PORT || 8080;
migrate().then(() => {
  server.listen(PORT, () => console.log(`🚀 Tracker backend running on :${PORT}`));
});
