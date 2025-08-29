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

/* ================== APP & SOCKET ================== */
const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: process.env.CORS_ORIGINS?.split(",") || ["*"],
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
    credentials: true,
  },
});

app.use(cors({ origin: process.env.CORS_ORIGINS?.split(",") || true, credentials: true }));
app.use(helmet());
app.use(express.json());

/* ================== DATABASE ================== */
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

/* ================== MIGRATIONS ================== */
async function migrate() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE EXTENSION IF NOT EXISTS "pgcrypto";

      CREATE TABLE IF NOT EXISTS orgs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      DO $$ BEGIN
        CREATE TYPE user_role AS ENUM ('admin','employee');
      EXCEPTION WHEN duplicate_object THEN null; END $$;

      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        org_id UUID REFERENCES orgs(id) ON DELETE CASCADE,
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

      CREATE TABLE IF NOT EXISTS activities (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        type TEXT NOT NULL,            -- e.g., checkin | checkout | visit | note
        details TEXT,
        location TEXT,
        latitude DOUBLE PRECISION,
        longitude DOUBLE PRECISION,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS followups (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        subject TEXT NOT NULL,
        note TEXT,
        followup_time TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);
    console.log("✅ Migration complete");
  } catch (e) {
    console.error("Migration error:", e);
  } finally {
    client.release();
  }
}
migrate();

/* ================== SOCKET.IO ================== */
io.on("connection", (socket) => {
  console.log("🔌 Client connected:", socket.id);
  socket.on("disconnect", () => console.log("❌ Client disconnected:", socket.id));
});

/* ================== AUTH HELPERS ================== */
function bearer(req) {
  const h = req.headers["authorization"];
  if (!h) return null;
  const [t, v] = h.split(" ");
  if (!t || t.toLowerCase() !== "bearer") return null;
  return v || null;
}

function authRequired(req, res, next) {
  try {
    const token = bearer(req);
    if (!token) return res.status(401).json({ error: "Missing bearer token" });
    const payload = jwt.verify(token, process.env.JWT_SECRET || "secret");
    req.user = { id: payload.id, role: payload.role };
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  };
}

/* ================== AUTH ROUTES ================== */
// Seed org + admin
app.post("/api/auth/seed", async (req, res) => {
  const client = await pool.connect();
  try {
    const {
      orgName = "Default Org",
      adminName = "Admin",
      adminEmail,
      adminMobile,
      adminPassword = "admin123",
    } = req.body;

    const org = (
      await client.query(`INSERT INTO orgs (name) VALUES ($1) RETURNING *`, [orgName])
    ).rows[0];

    const empId = "ADM-" + Math.floor(1000 + Math.random() * 9000);
    const hash = await bcrypt.hash(adminPassword, 10);

    const admin = (
      await client.query(
        `INSERT INTO users (org_id, role, name, email, employee_id, mobile, password_hash)
         VALUES ($1,'admin',$2,$3,$4,$5,$6)
         RETURNING id, name, email, employee_id, mobile, role`,
        [org.id, adminName, adminEmail, empId, adminMobile, hash]
      )
    ).rows[0];

    res.json({ org, admin });
  } catch (e) {
    console.error("Seed error:", e);
    res.status(500).json({ error: "Failed to seed database" });
  } finally {
    client.release();
  }
});

// Login (employeeId + mobile + password)
app.post("/api/auth/login", async (req, res) => {
  const { employeeId, mobile, password } = req.body;
  if (!employeeId || !mobile || !password) {
    return res.status(400).json({ error: "employeeId, mobile and password required" });
  }
  try {
    const { rows } = await pool.query(
      `SELECT * FROM users WHERE employee_id = $1 AND mobile = $2`,
      [employeeId, mobile]
    );
    const user = rows[0];
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET || "secret",
      { expiresIn: "7d" }
    );

    res.json({
      token,
      user: {
        id: user.id,
        employeeId: user.employee_id,
        name: user.name,
        mobile: user.mobile,
        email: user.email,
        role: user.role,
      },
    });
  } catch (e) {
    console.error("Login error:", e);
    res.status(500).json({ error: "Internal server error" });
  }
});

/* ================== PROFILE ================== */
app.get("/api/users/me", authRequired, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, org_id, role, name, email, employee_id, mobile, photo_url, created_at, updated_at
     FROM users WHERE id = $1`,
    [req.user.id]
  );
  res.json({ user: rows[0] });
});

app.patch("/api/users/me", authRequired, async (req, res) => {
  const { name, email, mobile, password, photoUrl } = req.body;
  try {
    let fields = [];
    let params = [];
    let i = 1;

    if (name) { fields.push(`name=$${i++}`); params.push(name); }
    if (email) { fields.push(`email=$${i++}`); params.push(email); }
    if (mobile) { fields.push(`mobile=$${i++}`); params.push(mobile); }
    if (photoUrl) { fields.push(`photo_url=$${i++}`); params.push(photoUrl); }
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      fields.push(`password_hash=$${i++}`);
      params.push(hash);
    }

    if (!fields.length) return res.json({ ok: true });
    params.push(req.user.id);

    const { rows } = await pool.query(
      `UPDATE users SET ${fields.join(", ")}, updated_at=now()
       WHERE id=$${i}
       RETURNING id, name, email, employee_id, mobile, photo_url, updated_at`,
      params
    );
    res.json({ user: rows[0] });
  } catch (e) {
    console.error("Update profile error:", e);
    res.status(500).json({ error: "Failed to update profile" });
  }
});

/* ================== EMPLOYEE MANAGEMENT (ADMIN) ================== */
app.get("/api/employees", authRequired, requireRole("admin"), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, name, email, employee_id, mobile, role, photo_url, created_at
     FROM users
     WHERE org_id=(SELECT org_id FROM users WHERE id=$1)
     ORDER BY created_at DESC`,
    [req.user.id]
  );
  res.json({ employees: rows });
});

app.post("/api/employees", authRequired, requireRole("admin"), async (req, res) => {
  const { name, email, mobile, password, role = "employee" } = req.body;
  try {
    const orgId = (
      await pool.query(`SELECT org_id FROM users WHERE id=$1`, [req.user.id])
    ).rows[0].org_id;

    const empId = "EMP-" + Math.floor(1000 + Math.random() * 9000);
    const hash = await bcrypt.hash(password, 10);

    const { rows } = await pool.query(
      `INSERT INTO users (org_id, role, name, email, employee_id, mobile, password_hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING id, name, email, employee_id, mobile, role`,
      [orgId, role, name, email, empId, mobile, hash]
    );
    res.json({ employee: rows[0] });
  } catch (e) {
    console.error("Add employee error:", e);
    res.status(500).json({ error: "Failed to add employee" });
  }
});

app.patch("/api/employees/:id", authRequired, requireRole("admin"), async (req, res) => {
  const { id } = req.params;
  const { name, email, mobile, role } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE users SET
         name=COALESCE($1,name),
         email=COALESCE($2,email),
         mobile=COALESCE($3,mobile),
         role=COALESCE($4,role),
         updated_at=now()
       WHERE id=$5
       RETURNING id, name, email, employee_id, mobile, role, updated_at`,
      [name, email, mobile, role, id]
    );
    res.json({ employee: rows[0] });
  } catch (e) {
    console.error("Update employee error:", e);
    res.status(500).json({ error: "Failed to update employee" });
  }
});

app.delete("/api/employees/:id", authRequired, requireRole("admin"), async (req, res) => {
  try {
    await pool.query(`DELETE FROM users WHERE id=$1`, [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    console.error("Delete employee error:", e);
    res.status(500).json({ error: "Failed to delete employee" });
  }
});

/* ================== ACTIVITIES ================== */
app.post("/api/activities", authRequired, async (req, res) => {
  const { type, details, location, latitude, longitude } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO activities (user_id, type, details, location, latitude, longitude)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING *`,
      [req.user.id, type, details, location, latitude, longitude]
    );
    const activity = rows[0];
    io.emit("activity:new", activity); // global broadcast (single-org app)
    res.json({ activity });
  } catch (e) {
    console.error("Add activity error:", e);
    res.status(500).json({ error: "Failed to add activity" });
  }
});

app.get("/api/activities", authRequired, async (req, res) => {
  try {
    let query = `
      SELECT a.*, u.name, u.employee_id
      FROM activities a
      JOIN users u ON a.user_id = u.id
      WHERE u.org_id = (SELECT org_id FROM users WHERE id=$1)
    `;
    const params = [req.user.id];

    if (req.user.role !== "admin") {
      // employee sees only their own
      query += ` AND a.user_id = $1`;
    }

    query += ` ORDER BY a.created_at DESC`;

    const { rows } = await pool.query(query, params);
    res.json({ activities: rows });
  } catch (e) {
    console.error("Fetch activities error:", e);
    res.status(500).json({ error: "Failed to fetch activities" });
  }
});

/* ================== FOLLOWUPS ================== */
app.post("/api/followups", authRequired, async (req, res) => {
  const { subject, note, followupTime } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO followups (user_id, subject, note, followup_time)
       VALUES ($1,$2,$3,$4)
       RETURNING *`,
      [req.user.id, subject, note, followupTime]
    );
    const followup = rows[0];
    io.emit("followup:new", followup); // global broadcast (single-org app)
    res.json({ followup });
  } catch (e) {
    console.error("Add followup error:", e);
    res.status(500).json({ error: "Failed to add followup" });
  }
});

app.get("/api/followups", authRequired, async (req, res) => {
  try {
    let query = `
      SELECT f.*, u.name, u.employee_id
      FROM followups f
      JOIN users u ON f.user_id = u.id
      WHERE u.org_id = (SELECT org_id FROM users WHERE id=$1)
    `;
    const params = [req.user.id];

    if (req.user.role !== "admin") {
      query += ` AND f.user_id = $1`;
    }

    query += ` ORDER BY f.followup_time DESC`;

    const { rows } = await pool.query(query, params);
    res.json({ followups: rows });
  } catch (e) {
    console.error("Fetch followups error:", e);
    res.status(500).json({ error: "Failed to fetch followups" });
  }
});

/* ================== OFFLINE SYNC ================== */
app.post("/api/sync", authRequired, async (req, res) => {
  const { queue } = req.body;
  if (!Array.isArray(queue)) return res.status(400).json({ error: "queue must be array" });
  try {
    for (const item of queue) {
      if (item.type === "activity") {
        const d = item.data || {};
        const { rows } = await pool.query(
          `INSERT INTO activities (user_id, type, details, location, latitude, longitude)
           VALUES ($1,$2,$3,$4,$5,$6)
           RETURNING *`,
          [req.user.id, d.type, d.details, d.location, d.latitude, d.longitude]
        );
        io.emit("activity:new", rows[0]);
      } else if (item.type === "followup") {
        const d = item.data || {};
        const { rows } = await pool.query(
          `INSERT INTO followups (user_id, subject, note, followup_time)
           VALUES ($1,$2,$3,$4)
           RETURNING *`,
          [req.user.id, d.subject, d.note, d.followupTime]
        );
        io.emit("followup:new", rows[0]);
      }
    }
    res.json({ success: true });
  } catch (e) {
    console.error("Sync error:", e);
    res.status(500).json({ error: "Failed to sync data" });
  }
});

/* ================== DASHBOARD ================== */
app.get("/api/dashboard", authRequired, async (req, res) => {
  try {
    const { rows: orgRow } = await pool.query(
      `SELECT org_id FROM users WHERE id=$1`,
      [req.user.id]
    );
    const orgId = orgRow[0].org_id;
    let data = {};

    if (req.user.role === "admin") {
      const activities = await pool.query(
        `SELECT a.type, COUNT(*)::int AS count
         FROM activities a
         JOIN users u ON a.user_id=u.id
         WHERE u.org_id=$1
         GROUP BY a.type`,
        [orgId]
      );

      const followupsDue = await pool.query(
        `SELECT COUNT(*)::int AS count
         FROM followups f
         JOIN users u ON f.user_id=u.id
         WHERE u.org_id=$1 AND f.followup_time >= now()`,
        [orgId]
      );

      const employeeCount = await pool.query(
        `SELECT COUNT(*)::int AS count
         FROM users
         WHERE org_id=$1 AND role='employee'`,
        [orgId]
      );

      data = {
        employees: employeeCount.rows[0].count,
        followupsDue: followupsDue.rows[0].count,
        activityStats: activities.rows, // [{ type, count }]
      };
    } else {
      const activities = await pool.query(
        `SELECT type, COUNT(*)::int AS count
         FROM activities
         WHERE user_id=$1
         GROUP BY type`,
        [req.user.id]
      );
      const followupsDue = await pool.query(
        `SELECT COUNT(*)::int AS count
         FROM followups
         WHERE user_id=$1 AND followup_time >= now()`,
        [req.user.id]
      );
      data = {
        followupsDue: followupsDue.rows[0].count,
        activityStats: activities.rows,
      };
    }

    res.json({ dashboard: data });
  } catch (e) {
    console.error("Dashboard error:", e);
    res.status(500).json({ error: "Failed to fetch dashboard data" });
  }
});

/* ================== HEALTH ================== */
app.get("/", (req, res) => res.json({ ok: true, uptime: process.uptime() }));

/* ================== START ================== */
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
