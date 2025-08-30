// tracker_backend_final.js
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
const io = new SocketIOServer(server, { cors: { origin: "*", methods: ["GET","POST","PUT","PATCH","DELETE"] } });
app.use(cors());
app.use(helmet());
app.use(express.json({ limit: "2mb" }));

/* ----------------------------- Postgres ------------------------------ */
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

/* -------------------------- Helpers ------------------------- */
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

/* -------------------------- Migrations ------------------------------- */
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

      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        role user_role NOT NULL,
        name TEXT NOT NULL,
        email TEXT UNIQUE,
        employee_id TEXT UNIQUE,
        mobile TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS backups (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL,
        data JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
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

      CREATE TABLE IF NOT EXISTS tasks (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
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
    `);
    console.log("✅ Migration complete");
  } finally {
    client.release();
  }
}

/* -------------------------- Auto Seed Users -------------------------- */
const seedData = [
  {
    "name": "Shanti Saran Singh",
    "role": "admin",
    "email": "singhss@scube.co.in",
    "mobile": "9831038262",
    "employee_id": "ADM-S.S Singh",
    "password": "scube@1234"
  },
  {
    "name": "Sandeep Sarkar",
    "role": "admin",
    "email": "sandeep@scube.co.in",
    "mobile": "9831036858",
    "employee_id": "ADM-Sandeep",
    "password": "scube@1234"
  },
  {
    "name": "Snehashis Saha",
    "role": "admin",
    "email": "marcom@scube.co.in",
    "mobile": "9330199588",
    "employee_id": "ADM-Snehashis",
    "password": "scube@1234"
  },
  {
    "name": "Komal Gupta",
    "role": "admin",
    "email": "komal@scube.co.in",
    "mobile": "7003045682",
    "employee_id": "ADM-Komal",
    "password": "scube@1234"
  },
  {
    "name": "MD Shoaib Raza",
    "role": "admin",
    "email": "shoaib@scube.co.in",
    "mobile": "9831259095",
    "employee_id": "ADM-Shoaib",
    "password": "scube@1234"
  },
  {
    "name": "Snehasish Paul",
    "role": "employee",
    "email": "snehasish@scube.co.in",
    "mobile": "8017892062",
    "employee_id": "SCS-03318",
    "password": "scube@4321"
  },
  {
    "name": "Zuber Alam",
    "role": "employee",
    "email": "zuber@scube.co.in",
    "mobile": "9891377424",
    "employee_id": "SCS-01102",
    "password": "scube@4321"
  },
  {
    "name": "Bharath Kumar TM",
    "role": "employee",
    "email": "bharath@scube.co.in",
    "mobile": "9844722312",
    "employee_id": "SCS-08017",
    "password": "scube@4321"
  },
  {
    "name": "Shiva Kumarar",
    "role": "employee",
    "email": "shivuramaiah97@gmail.com",
    "mobile": "9611452782",
    "employee_id": "SCS-08016",
    "password": "scube@4321"
  },
  {
    "name": "Tapas Kumar Dinda",
    "role": "employee",
    "email": "tapas@scube.co.in",
    "mobile": "9804443387",
    "employee_id": "SCS-03317",
    "password": "scube@4321"
  },
  {
    "name": "Gopal Chandra Biswas",
    "role": "employee",
    "email": "gopalscube@gmail.com",
    "mobile": "9432095612",
    "employee_id": "SCS-03313",
    "password": "scube@4321"
  },
  {
    "name": "Saugat Majumdar",
    "role": "employee",
    "email": "saugat@scube.co.in",
    "mobile": "9831259094",
    "employee_id": "SCS-03303",
    "password": "scube@4321"
  },
  {
    "name": "Chitrarath Senapati",
    "role": "employee",
    "email": "senapati@scube.co.in",
    "mobile": "9831282190",
    "employee_id": "SCS-03306",
    "password": "scube@4321"
  },
  {
    "name": "Sukhendu Shekhar Mondal",
    "role": "employee",
    "email": "sukhendumondal7278@gmail.com",
    "mobile": "7278942388",
    "employee_id": "SCS-03316",
    "password": "scube@4321"
  },
  {
    "name": "Tarun Kumar Paramanik",
    "role": "employee",
    "email": "tarun@scube.co.in",
    "mobile": "9831650969",
    "employee_id": "SCS-03308",
    "password": "scube@4321"
  },
  {
    "name": "Kartik Ghanta",
    "role": "employee",
    "email": "kartik@scube.co.in",
    "mobile": "7074099074",
    "employee_id": "SCS-03309",
    "password": "scube@4321"
  },
  {
    "name": "Provat Naskar",
    "role": "employee",
    "email": "provatnaskar2324@gmail.com",
    "mobile": "7044486602",
    "employee_id": "SCS-03314",
    "password": "scube@4321"
  },
  {
    "name": "Ravi Kumar",
    "role": "employee",
    "email": "ravik954836@gmail.com",
    "mobile": "95483 62042",
    "employee_id": "SCS-01103",
    "password": "scube@4321"
  },
  {
    "name": "Abhilash Sarangi",
    "role": "employee",
    "email": "abhilash@scube.co.in",
    "mobile": "8763523636",
    "employee_id": "SCS-067403",
    "password": "scube@4321"
  },
  {
    "name": "Kishan Kanodia",
    "role": "employee",
    "email": "kishan@scube.co.in",
    "mobile": "7999610074",
    "employee_id": "SCS-077106",
    "password": "scube@4321"
  },
  {
    "name": "Nitai Charan Bera",
    "role": "employee",
    "email": "pintu@scube.co.in",
    "mobile": "9831650960",
    "employee_id": "SCS- 08002",
    "password": "scube@4321"
  }
] ;

async function seedUsers() {
  const client = await pool.connect();
  try {
    const { rows } = await client.query("SELECT COUNT(*) FROM users");
    if (parseInt(rows[0].count) > 0) {
      console.log("👥 Users already exist, skipping seed");
      return;
    }
    for (const u of seedData) {
      const role = (u.role || "").toLowerCase() === "admin" ? "admin" : "employee";
      const name = (u.name || "").trim();
      const email = (u.email || "").trim() || null;
      const mobile = (u.mobile || "").trim() || null;
      const employee_id = (u.employee_id || "").trim();
      const password = (u.password || "Default@123");
      const hash = await bcrypt.hash(password, 10);
      await client.query(
        `INSERT INTO users (role,name,email,mobile,employee_id,password_hash)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [role, name, email, mobile, employee_id, hash]
      );
    }
    console.log("✅ Users seeded from CSV (" + seedData.length + " users)");
  } finally {
    client.release();
  }
}

/* -------------------------- Auth Routes ------------------------------ */
app.post("/api/auth/login", async (req, res) => {
  const { employeeId, mobile, email, password } = req.body;
  try {
    const { rows } = await pool.query(
      "SELECT * FROM users WHERE employee_id=$1 OR mobile=$2 OR email=$3 LIMIT 1",
      [employeeId, mobile, email]
    );
    const user = rows[0];
    if (!user) return res.status(400).json({ error: "User not found" });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(400).json({ error: "Invalid credentials" });

    const token = signToken(user);
    res.json({ token, user: { id: user.id, name: user.name, role: user.role, employeeId: user.employee_id, email: user.email, mobile: user.mobile } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// Offline fallback login (frontend validates from localStorage backup)
app.post("/api/auth/local-login", (req, res) => {
  const { employeeId } = req.body;
  res.json({ success: true, employeeId, message: "Offline login validated locally" });
});

/* ---------------------------- Users API ------------------------------ */
app.get("/api/users", authenticate, requireRole("admin"), async (req, res) => {
  const { rows } = await pool.query("SELECT id,role,name,email,mobile,employee_id FROM users ORDER BY created_at DESC");
  res.json({ users: rows });
});

/* ---------------------------- Activities ----------------------------- */
app.post("/api/activities", authenticate, async (req, res) => {
  const { type, details, latitude, longitude, address } = req.body;
  const { rows } = await pool.query(
    "INSERT INTO activities (user_id,type,details,latitude,longitude,address) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *",
    [req.user.id, type, details, latitude, longitude, address]
  );
  res.json({ activity: rows[0] });
});

app.get("/api/activities", authenticate, async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM activities ORDER BY created_at DESC");
  res.json({ activities: rows });
});

/* ---------------------------- Followups ----------------------------- */
app.post("/api/followups", authenticate, async (req, res) => {
  const { subject, note, datetime } = req.body;
  const { rows } = await pool.query(
    "INSERT INTO followups (user_id,subject,note,datetime) VALUES ($1,$2,$3,$4) RETURNING *",
    [req.user.id, subject, note, datetime]
  );
  res.json({ followup: rows[0] });
});

app.get("/api/followups", authenticate, async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM followups ORDER BY datetime DESC");
  res.json({ followups: rows });
});

/* ----------------------------- States ------------------------------- */
app.post("/api/states", authenticate, requireRole("admin"), async (req, res) => {
  const { name } = req.body;
  const { rows } = await pool.query("INSERT INTO states (name) VALUES ($1) RETURNING *", [name]);
  res.json({ state: rows[0] });
});

app.get("/api/states", authenticate, async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM states ORDER BY name ASC");
  res.json({ states: rows });
});

/* ----------------------------- Cities ------------------------------- */
app.post("/api/cities", authenticate, requireRole("admin"), async (req, res) => {
  const { stateId, name } = req.body;
  const { rows } = await pool.query("INSERT INTO cities (state_id,name) VALUES ($1,$2) RETURNING *", [stateId, name]);
  res.json({ city: rows[0] });
});

app.get("/api/cities", authenticate, async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM cities ORDER BY name ASC");
  res.json({ cities: rows });
});

/* ----------------------------- Tasks ------------------------------- */
app.post("/api/tasks", authenticate, async (req, res) => {
  const { title, description } = req.body;
  const { rows } = await pool.query("INSERT INTO tasks (user_id,title,description) VALUES ($1,$2,$3) RETURNING *", [req.user.id, title, description]);
  res.json({ task: rows[0] });
});

app.get("/api/tasks", authenticate, async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM tasks ORDER BY created_at DESC");
  res.json({ tasks: rows });
});

/* ----------------------------- Locations ------------------------------- */
app.post("/api/locations", authenticate, async (req, res) => {
  const { latitude, longitude, address } = req.body;
  const { rows } = await pool.query("INSERT INTO locations (user_id,latitude,longitude,address) VALUES ($1,$2,$3,$4) RETURNING *", [req.user.id, latitude, longitude, address]);
  res.json({ location: rows[0] });
});

app.get("/api/locations", authenticate, async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM locations ORDER BY created_at DESC LIMIT 50");
  res.json({ locations: rows });
});

/* ----------------------------- Backups ------------------------------- */
app.post("/api/backups", authenticate, async (req, res) => {
  const { data } = req.body;
  const { rows } = await pool.query("INSERT INTO backups (user_id,data) VALUES ($1,$2) RETURNING *", [req.user.id, data]);
  res.json({ backup: rows[0] });
});

app.get("/api/backups", authenticate, async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM backups WHERE user_id=$1 ORDER BY created_at DESC", [req.user.id]);
  res.json({ backups: rows });
});

/* ----------------------------- Health ------------------------------- */
app.get("/", (req, res) => res.json({ ok: true, uptime: process.uptime() }));

/* ----------------------------- Start ------------------------------- */
migrate().then(seedUsers).catch(console.error);
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => console.log(`🚀 Backend running on port ${PORT}`));
