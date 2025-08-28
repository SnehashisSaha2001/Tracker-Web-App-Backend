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

      CREATE TABLE IF NOT EXISTS tasks (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        org_id UUID REFERENCES orgs(id) ON DELETE CASCADE,
        user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        title TEXT NOT NULL,
        description TEXT,
        status task_status NOT NULL DEFAULT 'todo',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
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
      DROP TRIGGER IF EXISTS set_updated_at ON tasks;
      CREATE TRIGGER set_updated_at
      BEFORE UPDATE ON tasks
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

// Example: Auth routes
app.post("/api/auth/seed", async (req, res) => {
  // logic to create org + admin
});

app.post("/api/auth/register", async (req, res) => {
  // logic to register new user
});

app.post("/api/auth/login", async (req, res) => {
  // logic to authenticate user
});

// Example: Task routes
app.get("/api/tasks", async (req, res) => {
  // logic to fetch tasks
});

app.post("/api/tasks", async (req, res) => {
  // logic to create task
});

// Example: User routes
app.get("/api/users", async (req, res) => {
  // logic to fetch users
});

app.patch("/api/users/me", async (req, res) => {
  // logic to update user profile
});

// Example: Location routes
app.post("/api/locations", async (req, res) => {
  // logic to save location
});

app.get("/api/locations/recent", async (req, res) => {
  // logic to fetch recent locations
});

// Example: Backup routes
app.post("/api/backups", async (req, res) => {
  // logic to save backup
});

app.get("/api/backups", async (req, res) => {
  // logic to fetch backups
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
