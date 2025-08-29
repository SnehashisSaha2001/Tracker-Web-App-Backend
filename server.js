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

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: process.env.CORS_ORIGINS?.split(",") || ["*"],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  },
});

app.use(cors());
app.use(helmet());
app.use(express.json());

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ✅ Migration: create schema safely
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
      DO $$ BEGIN
        CREATE TYPE task_status AS ENUM ('todo','in_progress','done','blocked');
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
        employee_id UUID REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(50) NOT NULL,
        location JSONB,
        details TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS followups (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        employee_id UUID REFERENCES users(id) ON DELETE CASCADE,
        subject TEXT NOT NULL,
        datetime TIMESTAMPTZ NOT NULL,
        note TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      -- Trigger function to auto-update updated_at
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
        NEW.updated_at = now();
        RETURN NEW;
      END;
      $$ language 'plpgsql';
      -- Attach triggers
      DROP TRIGGER IF EXISTS set_updated_at ON activities;
      CREATE TRIGGER set_updated_at
      BEFORE UPDATE ON activities
      FOR EACH ROW
      EXECUTE FUNCTION update_updated_at_column();
      DROP TRIGGER IF EXISTS set_updated_at ON users;
      CREATE TRIGGER set_updated_at
      BEFORE UPDATE ON users
      FOR EACH ROW
      EXECUTE FUNCTION update_updated_at_column();
    `);
    console.log("✅ Migration complete");
  } finally {
    client.release();
  }
}

migrate().catch((err) => console.error("Migration error:", err));

// ========== API ROUTES FROM tracker_backend_express_socket 2.js ==========

// ✅ Updated Login Logic
app.post("/api/auth/login", async (req, res) => {
  try {
    const { employeeId, mobile, password } = req.body;

    if (!employeeId || !mobile || !password) {
      return res.status(400).json({ error: "Employee ID, Mobile, and Password are required" });
    }

    const result = await pool.query(
      "SELECT id, name, employee_id, role, password_hash FROM users WHERE employee_id = $1",
      [employeeId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password_hash);

    if (!isValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        employeeId: user.employee_id,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Example: Activities
app.get("/api/activities", async (req, res) => {
  try {
    // Add ordering by creation timestamp
    const result = await pool.query("SELECT * FROM activities ORDER BY created_at DESC");
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/activities", async (req, res) => {
  try {
    const { employeeId, type, location, details } = req.body;
    const timestamp = new Date().toISOString();

    const result = await pool.query(
      "INSERT INTO activities (employee_id, type, location, details, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [employeeId, type, location, details, timestamp]
    );

    // Emit activity event via Socket.IO
    io.emit("activity:new", result.rows[0]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Example: Followups
app.get("/api/followups", async (req, res) => {
  try {
    // Add ordering by creation timestamp
    const result = await pool.query("SELECT * FROM followups ORDER BY created_at DESC");
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/followups", async (req, res) => {
  try {
    const { employeeId, subject, datetime, note } = req.body;
    const timestamp = new Date(datetime).toISOString();

    const result = await pool.query(
      "INSERT INTO followups (employee_id, subject, datetime, note, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [employeeId, subject, timestamp, note, timestamp]
    );

    // Emit followup event via Socket.IO
    io.emit("followup:new", result.rows[0]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Offline Sync Endpoint
app.post("/api/sync", async (req, res) => {
  try {
    const { queue } = req.body;
    
    if (!Array.isArray(queue) || queue.length === 0) {
      return res.status(400).json({ error: "Empty sync queue provided" });
    }

    let results = [];

    for (const item of queue) {
      try {
        switch (item.type) {
          case 'activity':
            const activityResult = await pool.query(
              "INSERT INTO activities (employee_id, type, location, details, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING *",
              [item.data.employeeId, item.data.type, item.data.location, item.data.details, item.data.timestamp]
            );
            results.push({ ...item, result: activityResult.rows[0] });
            break;
          case 'followup':
            const followupResult = await pool.query(
              "INSERT INTO followups (employee_id, subject, datetime, note, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING *",
              [item.data.employeeId, item.data.subject, item.data.datetime, item.data.note, item.data.timestamp]
            );
            results.push({ ...item, result: followupResult.rows[0] });
            break;
          default:
            results.push({ ...item, error: "Unsupported operation type" });
        }
      } catch (error) {
        results.push({ ...item, error: error.message });
      }
    }

    res.status(200).json({ results });
  } catch (error) {
    res.status(500).json({ error: "Internal server error during sync" });
  }
});

// Socket.IO Connection Handler
io.on("connection", (socket) => {
  console.log("A user connected");

  socket.on("disconnect", () => {
    console.log("User disconnected");
  });
});

// ✅ Test route
app.get("/", (req, res) => {
  res.json({ ok: true, uptime: process.uptime() });
});

// 🚀 Start server
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
