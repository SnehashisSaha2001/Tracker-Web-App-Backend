// tracker_backend_express_socket_full.js
import express from "express";
import http from "http";
import { Server as SocketIOServer } from "socket.io";
import cors from "cors";
import helmet from "helmet";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

/* ---------------------------- App & Server ---------------------------- */
const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: (process.env.CORS_ORIGINS?.split(",") ?? ["*"]).map(s => s.trim()),
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    credentials: true,
  },
});
app.use(cors());
app.use(helmet());
app.use(express.json({ limit: "1mb" }));

/* ----------------------------- Postgres ------------------------------ */
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

/* -------------------------- Helper Utilities ------------------------- */
const asyncRoute = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function signToken(user) {
  return jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1d" });
}

function authenticate(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = decoded;
    next();
  });
}
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  };
}

/* ------------------------------- Migrate ----------------------------- */
async function migrate() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE EXTENSION IF NOT EXISTS "pgcrypto";

      DO $$ BEGIN
        CREATE TYPE user_role AS ENUM ('admin','employee');
      EXCEPTION WHEN duplicate_object THEN null; END $$;

      DO $$ BEGIN
        CREATE TYPE activity_type AS ENUM ('checkin','checkout','visit');
      EXCEPTION WHEN duplicate_object THEN null; END $$;

      CREATE TABLE IF NOT EXISTS orgs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        org_id UUID REFERENCES orgs(id) ON DELETE SET NULL,
        role user_role NOT NULL,
        name TEXT NOT NULL,
        email TEXT UNIQUE,
        employee_id TEXT UNIQUE,
        mobile TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        photo_url TEXT,
        last_seen TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS states (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT UNIQUE NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS cities (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        state_id UUID NOT NULL REFERENCES states(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE(state_id, name)
      );

      CREATE TABLE IF NOT EXISTS activities (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        type activity_type NOT NULL,
        details TEXT,
        latitude DOUBLE PRECISION,
        longitude DOUBLE PRECISION,
        address TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS followups (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        subject TEXT NOT NULL,
        note TEXT,
        datetime TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS tasks (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        org_id UUID REFERENCES orgs(id) ON DELETE SET NULL,
        user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT NOT NULL DEFAULT 'todo',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS locations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        latitude DOUBLE PRECISION NOT NULL,
        longitude DOUBLE PRECISION NOT NULL,
        address TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS backups (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        data JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE OR REPLACE FUNCTION set_updated_at()
      RETURNS TRIGGER AS $$
      BEGIN NEW.updated_at = now(); RETURN NEW; END $$ LANGUAGE plpgsql;

      DO $$ BEGIN
        CREATE TRIGGER trg_users_updated BEFORE UPDATE ON users
        FOR EACH ROW EXECUTE FUNCTION set_updated_at();
      EXCEPTION WHEN duplicate_object THEN null; END $$;

      DO $$ BEGIN
        CREATE TRIGGER trg_tasks_updated BEFORE UPDATE ON tasks
        FOR EACH ROW EXECUTE FUNCTION set_updated_at();
      EXCEPTION WHEN duplicate_object THEN null; END $$;
    `);
    console.log("✅ Migration complete");
  } finally {
    client.release();
  }
}
migrate().catch((e) => console.error("Migration error:", e));

/* ------------------------------ AUTH ------------------------------- */
// Seed: create org + admin (first-time setup). Safe: only when no admin exists.
app.post("/api/auth/seed", asyncRoute(async (req, res) => {
  const { orgName, name, email, mobile, employeeId, password } = req.body;
  const { rows: adminCount } = await pool.query("SELECT count(*)::int AS c FROM users WHERE role='admin'");
  if (adminCount[0].c > 0) return res.status(400).json({ error: "Admin already exists" });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const org = await client.query(
      "INSERT INTO orgs (name) VALUES ($1) RETURNING id, name",
      [orgName || "Default Org"]
    );
    const hash = await bcrypt.hash(password, 10);
    const admin = await client.query(
      `INSERT INTO users (org_id, role, name, email, mobile, employee_id, password_hash)
       VALUES ($1,'admin',$2,$3,$4,$5,$6)
       RETURNING id, role, name, email, mobile, employee_id`,
      [org.rows[0].id, name, email, mobile, employeeId, hash]
    );
    await client.query("COMMIT");
    const user = admin.rows[0];
    const token = signToken(user);
    res.json({ token, user });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error(e);
    res.status(500).json({ error: "Seed failed" });
  } finally {
    client.release();
  }
}));

// Register: if there is an admin already, only admins can create others.
// If no users exist (fresh DB), allow open self-register as admin.
app.post("/api/auth/register", asyncRoute(async (req, res) => {
  const { name, email, mobile, employeeId, password, role = "employee" } = req.body;

  const { rows: cntRows } = await pool.query("SELECT count(*)::int AS c FROM users");
  const isFresh = cntRows[0].c === 0;
  if (!isFresh) {
    // Require auth + admin when not fresh
    const auth = req.headers.authorization || "";
    if (!auth.startsWith("Bearer ")) return res.status(401).json({ error: "Missing token" });
    try {
      const decoded = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
      if (decoded.role !== "admin") return res.status(403).json({ error: "Only admin can register users" });
    } catch {
      return res.status(403).json({ error: "Invalid token" });
    }
  }

  const finalRole = isFresh ? "admin" : role === "admin" ? "admin" : "employee";
  const hash = await bcrypt.hash(password, 10);

  const { rows } = await pool.query(
    `INSERT INTO users (role, name, email, mobile, employee_id, password_hash)
     VALUES ($1,$2,$3,$4,$5,$6)
     RETURNING id, role, name, email, mobile, employee_id`,
    [finalRole, name, email, mobile, employeeId, hash]
  );
  const user = rows[0];
  const token = signToken(user);
  res.json({ token, user });
}));

// Login
app.post("/api/auth/login", asyncRoute(async (req, res) => {
  const { employeeId, mobile, email, password } = req.body;
  if (!password) return res.status(400).json({ error: "Password required" });

  const { rows } = await pool.query(
    `SELECT * FROM users
     WHERE ($1::text IS NOT NULL AND employee_id=$1)
        OR ($2::text IS NOT NULL AND mobile=$2)
        OR ($3::text IS NOT NULL AND email=$3)
     LIMIT 1`,
    [employeeId || null, mobile || null, email || null]
  );
  const user = rows[0];
  if (!user) return res.status(400).json({ error: "User not found" });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(400).json({ error: "Invalid credentials" });

  const token = signToken(user);
  await pool.query("UPDATE users SET last_seen = now() WHERE id=$1", [user.id]);
  res.json({
    token,
    user: {
      id: user.id,
      role: user.role,
      name: user.name,
      email: user.email,
      mobile: user.mobile,
      employeeId: user.employee_id,
      photoUrl: user.photo_url,
    },
  });
}));

/* ------------------------------ USERS ------------------------------ */
app.get("/api/users", authenticate, requireRole("admin"), asyncRoute(async (req, res) => {
  const { rows } = await pool.query(
    "SELECT id, role, name, email, mobile, employee_id AS \"employeeId\", photo_url AS \"photoUrl\", created_at FROM users ORDER BY created_at DESC"
  );
  res.json({ users: rows });
}));

app.post("/api/users", authenticate, requireRole("admin"), asyncRoute(async (req, res) => {
  const { name, email, mobile, employeeId, password, role = "employee" } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const { rows } = await pool.query(
    `INSERT INTO users (role, name, email, mobile, employee_id, password_hash)
     VALUES ($1,$2,$3,$4,$5,$6)
     RETURNING id, role, name, email, mobile, employee_id AS "employeeId"`,
    [role, name, email, mobile, employeeId, hash]
  );
  res.json({ user: rows[0] });
}));

app.patch("/api/users/:id", authenticate, asyncRoute(async (req, res) => {
  const { id } = req.params;
  const { name, email, mobile, password, role, photoUrl } = req.body;

  if (req.user.role !== "admin" && req.user.id !== id) {
    return res.status(403).json({ error: "Forbidden" });
  }

  const fields = [];
  const values = [];
  let idx = 1;

  if (name !== undefined) { fields.push(`name=$${idx++}`); values.push(name); }
  if (email !== undefined) { fields.push(`email=$${idx++}`); values.push(email); }
  if (mobile !== undefined) { fields.push(`mobile=$${idx++}`); values.push(mobile); }
  if (photoUrl !== undefined) { fields.push(`photo_url=$${idx++}`); values.push(photoUrl); }
  if (role !== undefined && req.user.role === "admin") { fields.push(`role=$${idx++}`); values.push(role); }
  if (password) {
    const hash = await bcrypt.hash(password, 10);
    fields.push(`password_hash=$${idx++}`); values.push(hash);
  }
  if (!fields.length) return res.json({ ok: true });

  values.push(id);
  const { rows } = await pool.query(
    `UPDATE users SET ${fields.join(", ")} WHERE id=$${idx} RETURNING id, role, name, email, mobile, employee_id AS "employeeId", photo_url AS "photoUrl"`,
    values
  );
  res.json({ user: rows[0] });
}));

app.delete("/api/users/:id", authenticate, requireRole("admin"), asyncRoute(async (req, res) => {
  const { id } = req.params;
  await pool.query("DELETE FROM users WHERE id=$1", [id]);
  res.json({ ok: true });
}));

app.patch("/api/users/me", authenticate, asyncRoute(async (req, res) => {
  req.params.id = req.user.id;
  return app._router.handle(req, res); // will fall into /api/users/:id via same request
}));

/* ------------------------------ ADMINS ----------------------------- */
app.get("/api/admins", authenticate, requireRole("admin"), asyncRoute(async (_req, res) => {
  const { rows } = await pool.query(
    "SELECT id, name, email, mobile, employee_id AS \"employeeId\" FROM users WHERE role='admin' ORDER BY created_at DESC"
  );
  res.json({ admins: rows });
}));
app.post("/api/admins", authenticate, requireRole("admin"), asyncRoute(async (req, res) => {
  const { name, email, mobile, employeeId, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const { rows } = await pool.query(
    `INSERT INTO users (role, name, email, mobile, employee_id, password_hash)
     VALUES ('admin',$1,$2,$3,$4,$5)
     RETURNING id, name, email, mobile, employee_id AS "employeeId"`,
    [name, email, mobile, employeeId, hash]
  );
  res.json({ admin: rows[0] });
}));
app.delete("/api/admins/:id", authenticate, requireRole("admin"), asyncRoute(async (req, res) => {
  await pool.query("DELETE FROM users WHERE id=$1 AND role='admin'", [req.params.id]);
  res.json({ ok: true });
}));

/* ---------------------------- EMPLOYEES ---------------------------- */
app.get("/api/employees", authenticate, requireRole("admin"), asyncRoute(async (_req, res) => {
  const { rows } = await pool.query(
    "SELECT id, name, email, mobile, employee_id AS \"employeeId\" FROM users WHERE role='employee' ORDER BY created_at DESC"
  );
  res.json({ employees: rows });
}));
app.post("/api/employees", authenticate, requireRole("admin"), asyncRoute(async (req, res) => {
  const { name, email, mobile, employeeId, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const { rows } = await pool.query(
    `INSERT INTO users (role, name, email, mobile, employee_id, password_hash)
     VALUES ('employee',$1,$2,$3,$4,$5)
     RETURNING id, name, email, mobile, employee_id AS "employeeId"`,
    [name, email, mobile, employeeId, hash]
  );
  res.json({ employee: rows[0] });
}));
app.delete("/api/employees/:id", authenticate, requireRole("admin"), asyncRoute(async (req, res) => {
  await pool.query("DELETE FROM users WHERE id=$1 AND role='employee'", [req.params.id]);
  res.json({ ok: true });
}));

/* ----------------------------- STATES ------------------------------ */
app.get("/api/states", authenticate, asyncRoute(async (_req, res) => {
  const { rows } = await pool.query("SELECT id, name FROM states ORDER BY name ASC");
  res.json({ states: rows });
}));
app.post("/api/states", authenticate, requireRole("admin"), asyncRoute(async (req, res) => {
  const { name } = req.body;
  const { rows } = await pool.query(
    "INSERT INTO states (name) VALUES ($1) RETURNING id, name",
    [name]
  );
  res.json({ state: rows[0] });
}));
app.delete("/api/states/:id", authenticate, requireRole("admin"), asyncRoute(async (req, res) => {
  await pool.query("DELETE FROM states WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
}));

/* ------------------------------ CITIES ----------------------------- */
app.get("/api/cities", authenticate, asyncRoute(async (req, res) => {
  const { stateId } = req.query;
  let q = "SELECT id, state_id AS \"stateId\", name FROM cities";
  const vals = [];
  if (stateId) { q += " WHERE state_id=$1"; vals.push(stateId); }
  q += " ORDER BY name ASC";
  const { rows } = await pool.query(q, vals);
  res.json({ cities: rows });
}));
app.post("/api/cities", authenticate, requireRole("admin"), asyncRoute(async (req, res) => {
  const { stateId, name } = req.body;
  const { rows } = await pool.query(
    "INSERT INTO cities (state_id, name) VALUES ($1,$2) RETURNING id, state_id AS \"stateId\", name",
    [stateId, name]
  );
  res.json({ city: rows[0] });
}));
app.delete("/api/cities/:id", authenticate, requireRole("admin"), asyncRoute(async (req, res) => {
  await pool.query("DELETE FROM cities WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
}));

/* ---------------------------- ACTIVITIES --------------------------- */
app.get("/api/activities", authenticate, asyncRoute(async (req, res) => {
  const { userId, type, from, to, limit = 50, offset = 0 } = req.query;

  const conds = [];
  const vals = [];
  let idx = 1;

  if (userId) { conds.push(`user_id=$${idx++}`); vals.push(userId); }
  if (type) { conds.push(`type=$${idx++}::activity_type`); vals.push(type); }
  if (from) { conds.push(`created_at >= $${idx++}`); vals.push(new Date(from)); }
  if (to) { conds.push(`created_at <= $${idx++}`); vals.push(new Date(to)); }

  // Non-admins see only their own
  if (req.user.role !== "admin") {
    conds.push(`user_id=$${idx++}`);
    vals.push(req.user.id);
  }

  const where = conds.length ? `WHERE ${conds.join(" AND ")}` : "";
  const { rows } = await pool.query(
    `SELECT id, user_id AS "userId", type, details, latitude, longitude, address, created_at
     FROM activities ${where}
     ORDER BY created_at DESC
     LIMIT $${idx++} OFFSET $${idx}`,
    [...vals, Number(limit), Number(offset)]
  );
  res.json({ activities: rows });
}));

app.post("/api/activities", authenticate, asyncRoute(async (req, res) => {
  const { type, details, latitude, longitude, address } = req.body;
  const { rows } = await pool.query(
    `INSERT INTO activities (user_id, type, details, latitude, longitude, address)
     VALUES ($1,$2,$3,$4,$5,$6)
     RETURNING id, user_id AS "userId", type, details, latitude, longitude, address, created_at`,
    [req.user.id, type, details || null, latitude ?? null, longitude ?? null, address ?? null]
  );
  const activity = rows[0];
  io.emit("activity:new", activity);
  res.json({ activity });
}));

/* ----------------------------- FOLLOWUPS --------------------------- */
app.get("/api/followups", authenticate, asyncRoute(async (req, res) => {
  const { userId, from, to, limit = 100, offset = 0 } = req.query;

  const conds = [];
  const vals = [];
  let idx = 1;

  if (userId && req.user.role === "admin") { conds.push(`user_id=$${idx++}`); vals.push(userId); }
  if (from) { conds.push(`datetime >= $${idx++}`); vals.push(new Date(from)); }
  if (to) { conds.push(`datetime <= $${idx++}`); vals.push(new Date(to)); }

  if (req.user.role !== "admin") {
    conds.push(`user_id=$${idx++}`); vals.push(req.user.id);
  }

  const where = conds.length ? `WHERE ${conds.join(" AND ")}` : "";
  const { rows } = await pool.query(
    `SELECT id, user_id AS "userId", subject, note, datetime, created_at
     FROM followups ${where}
     ORDER BY datetime DESC
     LIMIT $${idx++} OFFSET $${idx}`,
    [...vals, Number(limit), Number(offset)]
  );
  res.json({ followups: rows });
}));

app.post("/api/followups", authenticate, asyncRoute(async (req, res) => {
  const { subject, note, datetime } = req.body;
  const { rows } = await pool.query(
    `INSERT INTO followups (user_id, subject, note, datetime)
     VALUES ($1,$2,$3,$4)
     RETURNING id, user_id AS "userId", subject, note, datetime, created_at`,
    [req.user.id, subject, note ?? null, new Date(datetime)]
  );
  const followup = rows[0];
  io.emit("followup:new", followup);
  res.json({ followup });
}));

app.patch("/api/followups/:id", authenticate, asyncRoute(async (req, res) => {
  const { id } = req.params;

  // owner or admin only
  const { rows: ownerRows } = await pool.query("SELECT user_id FROM followups WHERE id=$1", [id]);
  if (!ownerRows.length) return res.status(404).json({ error: "Not found" });
  if (req.user.role !== "admin" && ownerRows[0].user_id !== req.user.id) {
    return res.status(403).json({ error: "Forbidden" });
  }

  const { subject, note, datetime } = req.body;
  const fields = [], vals = []; let idx = 1;
  if (subject !== undefined) { fields.push(`subject=$${idx++}`); vals.push(subject); }
  if (note !== undefined) { fields.push(`note=$${idx++}`); vals.push(note); }
  if (datetime !== undefined) { fields.push(`datetime=$${idx++}`); vals.push(new Date(datetime)); }
  if (!fields.length) return res.json({ ok: true });

  vals.push(id);
  const { rows } = await pool.query(
    `UPDATE followups SET ${fields.join(", ")} WHERE id=$${idx}
     RETURNING id, user_id AS "userId", subject, note, datetime, created_at`,
    vals
  );
  res.json({ followup: rows[0] });
}));

app.delete("/api/followups/:id", authenticate, asyncRoute(async (req, res) => {
  const { id } = req.params;
  const { rows: ownerRows } = await pool.query("SELECT user_id FROM followups WHERE id=$1", [id]);
  if (!ownerRows.length) return res.status(404).json({ error: "Not found" });
  if (req.user.role !== "admin" && ownerRows[0].user_id !== req.user.id) {
    return res.status(403).json({ error: "Forbidden" });
  }
  await pool.query("DELETE FROM followups WHERE id=$1", [id]);
  res.json({ ok: true });
}));

/* ------------------------------ TASKS ------------------------------ */
app.get("/api/tasks", authenticate, asyncRoute(async (req, res) => {
  const conds = [], vals = []; let idx = 1;
  if (req.user.role !== "admin") { conds.push(`user_id=$${idx++}`); vals.push(req.user.id); }
  const where = conds.length ? `WHERE ${conds.join(" AND ")}` : "";
  const { rows } = await pool.query(`SELECT * FROM tasks ${where} ORDER BY created_at DESC`, vals);
  res.json({ tasks: rows });
}));

app.post("/api/tasks", authenticate, asyncRoute(async (req, res) => {
  const { title, description, status = "todo", userId } = req.body;
  const targetUser = req.user.role === "admin" && userId ? userId : req.user.id;
  const { rows } = await pool.query(
    `INSERT INTO tasks (user_id, title, description, status)
     VALUES ($1,$2,$3,$4) RETURNING *`,
    [targetUser, title, description ?? null, status]
  );
  res.json({ task: rows[0] });
}));

app.patch("/api/tasks/:id", authenticate, asyncRoute(async (req, res) => {
  const { id } = req.params;

  // owner or admin
  const { rows: tRows } = await pool.query("SELECT user_id FROM tasks WHERE id=$1", [id]);
  if (!tRows.length) return res.status(404).json({ error: "Not found" });
  if (req.user.role !== "admin" && tRows[0].user_id !== req.user.id) {
    return res.status(403).json({ error: "Forbidden" });
  }

  const { title, description, status } = req.body;
  const fields = [], vals = []; let idx = 1;
  if (title !== undefined) { fields.push(`title=$${idx++}`); vals.push(title); }
  if (description !== undefined) { fields.push(`description=$${idx++}`); vals.push(description); }
  if (status !== undefined) { fields.push(`status=$${idx++}`); vals.push(status); }
  if (!fields.length) return res.json({ ok: true });

  vals.push(id);
  const { rows } = await pool.query(
    `UPDATE tasks SET ${fields.join(", ")} WHERE id=$${idx} RETURNING *`,
    vals
  );
  res.json({ task: rows[0] });
}));

app.delete("/api/tasks/:id", authenticate, asyncRoute(async (req, res) => {
  const { id } = req.params;
  const { rows: tRows } = await pool.query("SELECT user_id FROM tasks WHERE id=$1", [id]);
  if (!tRows.length) return res.status(404).json({ error: "Not found" });
  if (req.user.role !== "admin" && tRows[0].user_id !== req.user.id) {
    return res.status(403).json({ error: "Forbidden" });
  }
  await pool.query("DELETE FROM tasks WHERE id=$1", [id]);
  res.json({ ok: true });
}));

/* ----------------------------- LOCATIONS --------------------------- */
app.post("/api/locations", authenticate, asyncRoute(async (req, res) => {
  const { latitude, longitude, address } = req.body;
  const { rows } = await pool.query(
    `INSERT INTO locations (user_id, latitude, longitude, address)
     VALUES ($1,$2,$3,$4) RETURNING *`,
    [req.user.id, latitude, longitude, address ?? null]
  );
  res.json({ location: rows[0] });
}));
app.get("/api/locations/recent", authenticate, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM locations WHERE user_id=$1 ORDER BY created_at DESC LIMIT 10",
    [req.user.id]
  );
  res.json({ locations: rows });
}));

/* ------------------------------ BACKUPS ---------------------------- */
app.post("/api/backups", authenticate, asyncRoute(async (req, res) => {
  const { data } = req.body;
  const { rows } = await pool.query(
    "INSERT INTO backups (user_id, data) VALUES ($1,$2) RETURNING *",
    [req.user.id, data]
  );
  res.json({ backup: rows[0] });
}));
app.get("/api/backups", authenticate, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM backups WHERE user_id=$1 ORDER BY created_at DESC",
    [req.user.id]
  );
  res.json({ backups: rows });
}));

/* ------------------------------ Health ----------------------------- */
app.get("/", (_req, res) => {
  res.json({ ok: true, uptime: process.uptime() });
});

/* ----------------------------- Errors ------------------------------ */
app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal Server Error" });
});

/* ----------------------------- Start ------------------------------- */
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
