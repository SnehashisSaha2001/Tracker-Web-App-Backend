import express from "express";
import http from "http";
import { Server as SocketIOServer } from "socket.io";
import cors from "cors";
import helmet from "helmet";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { body, validationResult } from "express-validator";
import dotenv from "dotenv";

dotenv.config();

/* ---------------------------- App & Server ---------------------------- */
const app = express();
const server = http.createServer(app);

// Get frontend URL from environment or use default
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";

const io = new SocketIOServer(server, { 
  cors: { 
    origin: [FRONTEND_URL, "http://localhost:3000"], 
    methods: ["GET","POST","PUT","PATCH","DELETE"],
    credentials: true
  } 
});

// Updated CORS configuration
app.use(cors({
  origin: [FRONTEND_URL, "http://localhost:3000"],
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
  credentials: true
}));

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
        mobile TEXT UNIQUE,
        employee_id TEXT UNIQUE,
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
];

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

/* -------------------------- Socket.IO ------------------------------- */
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  
  // Join room based on user role
  socket.on('join', (data) => {
    if (data.role === 'admin') {
      socket.join('admins');
    } else {
      socket.join(`user_${data.userId}`);
    }
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

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
    res.json({ 
      token, 
      user: { 
        id: user.id, 
        name: user.name, 
        role: user.role, 
        employeeId: user.employee_id, 
        email: user.email, 
        mobile: user.mobile 
      } 
    });
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
  try {
    const { rows } = await pool.query(
      "SELECT id, role, name, email, mobile, employee_id FROM users ORDER BY created_at DESC"
    );
    res.json({ users: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

app.post("/api/users", authenticate, requireRole("admin"), 
  [
    body('role').isIn(['admin', 'employee']).withMessage('Invalid role'),
    body('name').notEmpty().withMessage('Name is required'),
    body('email').optional().isEmail().withMessage('Invalid email'),
    body('mobile').optional().isMobilePhone().withMessage('Invalid mobile number'),
    body('employeeId').notEmpty().withMessage('Employee ID is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { role, name, email, mobile, employeeId, password } = req.body;
    
    try {
      // Check if user already exists
      const { rows } = await pool.query(
        "SELECT * FROM users WHERE employee_id=$1 OR mobile=$2 OR email=$3 LIMIT 1",
        [employeeId, mobile, email]
      );
      
      if (rows.length > 0) {
        return res.status(400).json({ error: "User already exists" });
      }
      
      // Hash password
      const hash = await bcrypt.hash(password, 10);
      
      // Create user
      const { rows: [user] } = await pool.query(
        `INSERT INTO users (role, name, email, mobile, employee_id, password_hash)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, role, name, email, mobile, employee_id`,
        [role, name, email, mobile, employeeId, hash]
      );
      
      res.json({ user });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to create user" });
    }
  }
);

app.put("/api/users/:id", authenticate, requireRole("admin"), 
  [
    body('role').isIn(['admin', 'employee']).withMessage('Invalid role'),
    body('name').notEmpty().withMessage('Name is required'),
    body('email').optional().isEmail().withMessage('Invalid email'),
    body('mobile').optional().isMobilePhone().withMessage('Invalid mobile number'),
    body('employeeId').notEmpty().withMessage('Employee ID is required')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { id } = req.params;
    const { role, name, email, mobile, employeeId, password } = req.body;
    
    try {
      // Check if user exists
      const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [id]);
      
      if (rows.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }
      
      const user = rows[0];
      
      // Update user
      let query = "UPDATE users SET role=$1, name=$2, email=$3, mobile=$4, employee_id=$5";
      let params = [role, name, email, mobile, employeeId];
      
      if (password) {
        const hash = await bcrypt.hash(password, 10);
        query += ", password_hash=$6";
        params.push(hash);
      }
      
      query += " WHERE id=$" + (params.length + 1) + " RETURNING id, role, name, email, mobile, employee_id";
      params.push(id);
      
      const { rows: [updatedUser] } = await pool.query(query, params);
      
      res.json({ user: updatedUser });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to update user" });
    }
  }
);

app.delete("/api/users/:id", authenticate, requireRole("admin"), async (req, res) => {
  const { id } = req.params;
  
  try {
    // Check if user exists
    const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    
    // Delete user
    await pool.query("DELETE FROM users WHERE id=$1", [id]);
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete user" });
  }
});

/* ---------------------------- Activities ----------------------------- */
app.post("/api/activities", authenticate, 
  [
    body('type').isIn(['checkin', 'checkout', 'visit']).withMessage('Invalid activity type'),
    body('details').optional().isString().withMessage('Details must be a string'),
    body('latitude').optional().isFloat().withMessage('Latitude must be a number'),
    body('longitude').optional().isFloat().withMessage('Longitude must be a number'),
    body('address').optional().isString().withMessage('Address must be a string')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { type, details, latitude, longitude, address } = req.body;
    
    try {
      const { rows } = await pool.query(
        `INSERT INTO activities (user_id,type,details,latitude,longitude,address) 
         VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
        [req.user.id, type, details, latitude, longitude, address]
      );
      
      const activity = rows[0];
      
      // Get employee ID for the activity
      const { rows: userRows } = await pool.query(
        "SELECT employee_id FROM users WHERE id=$1",
        [req.user.id]
      );
      
      const employeeId = userRows[0]?.employee_id || req.user.id;
      
      // Transform data to match frontend expectations
      const transformedActivity = {
        id: activity.id,
        employeeId: employeeId,
        timestamp: activity.created_at,
        type: activity.type,
        location: activity.address,
        latitude: activity.latitude,
        longitude: activity.longitude,
        mapLink: activity.latitude && activity.longitude ? 
          `https://www.openstreetmap.org/?mlat=${activity.latitude}&mlon=${activity.longitude}` : null,
        details: activity.details
      };
      
      // Emit real-time update
      io.to('admins').emit('activity_update', {
        action: 'created',
        activity: transformedActivity
      });
      
      res.json({ activity: transformedActivity });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to create activity" });
    }
  }
);

app.get("/api/activities", authenticate, async (req, res) => {
  try {
    let query = `
      SELECT a.*, u.employee_id 
      FROM activities a 
      JOIN users u ON a.user_id = u.id
    `;
    let params = [];
    
    if (req.user.role !== 'admin') {
      query += " WHERE a.user_id = $1";
      params = [req.user.id];
    }
    
    query += " ORDER BY a.created_at DESC";
    
    const { rows } = await pool.query(query, params);
    
    // Transform data to match frontend expectations
    const activities = rows.map(act => ({
      id: act.id,
      employeeId: act.employee_id,
      timestamp: act.created_at,
      type: act.type,
      location: act.address,
      latitude: act.latitude,
      longitude: act.longitude,
      mapLink: act.latitude && act.longitude ? 
        `https://www.openstreetmap.org/?mlat=${act.latitude}&mlon=${act.longitude}` : null,
      details: act.details
    }));
    
    res.json({ activities });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch activities" });
  }
});

/* ---------------------------- Followups ----------------------------- */
app.post("/api/followups", authenticate, 
  [
    body('subject').notEmpty().withMessage('Subject is required'),
    body('note').optional().isString().withMessage('Note must be a string'),
    body('datetime').isISO8601().withMessage('Invalid datetime format')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { subject, note, datetime } = req.body;
    
    try {
      const { rows } = await pool.query(
        "INSERT INTO followups (user_id,subject,note,datetime) VALUES ($1,$2,$3,$4) RETURNING *",
        [req.user.id, subject, note, datetime]
      );
      
      const followup = rows[0];
      
      // Get employee ID for the followup
      const { rows: userRows } = await pool.query(
        "SELECT employee_id FROM users WHERE id=$1",
        [req.user.id]
      );
      
      const employeeId = userRows[0]?.employee_id || req.user.id;
      
      // Transform data to match frontend expectations
      const transformedFollowup = {
        id: followup.id,
        employeeId: employeeId,
        subject: followup.subject,
        datetime: followup.datetime,
        note: followup.note,
        createdAt: followup.created_at
      };
      
      res.json({ followup: transformedFollowup });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to create followup" });
    }
  }
);

app.get("/api/followups", authenticate, async (req, res) => {
  try {
    let query = `
      SELECT f.*, u.employee_id 
      FROM followups f 
      JOIN users u ON f.user_id = u.id
    `;
    let params = [];
    
    if (req.user.role !== 'admin') {
      query += " WHERE f.user_id = $1";
      params = [req.user.id];
    }
    
    query += " ORDER BY f.datetime DESC";
    
    const { rows } = await pool.query(query, params);
    
    // Transform data to match frontend expectations
    const followups = rows.map(f => ({
      id: f.id,
      employeeId: f.employee_id,
      subject: f.subject,
      datetime: f.datetime,
      note: f.note,
      createdAt: f.created_at
    }));
    
    res.json({ followups });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch followups" });
  }
});

/* ----------------------------- States ------------------------------- */
app.post("/api/states", authenticate, requireRole("admin"), 
  [
    body('name').notEmpty().withMessage('State name is required')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { name } = req.body;
    
    try {
      const { rows } = await pool.query("INSERT INTO states (name) VALUES ($1) RETURNING *", [name]);
      
      const state = rows[0];
      
      // Transform data to match frontend expectations
      const transformedState = {
        id: state.id,
        name: state.name,
        createdAt: state.created_at
      };
      
      res.json({ state: transformedState });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to create state" });
    }
  }
);

app.get("/api/states", authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM states ORDER BY name ASC");
    
    // Transform data to match frontend expectations
    const states = rows.map(s => ({
      id: s.id,
      name: s.name,
      createdAt: s.created_at
    }));
    
    res.json({ states });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch states" });
  }
});

/* ----------------------------- Cities ------------------------------- */
app.post("/api/cities", authenticate, requireRole("admin"), 
  [
    body('stateId').isUUID().withMessage('Invalid state ID'),
    body('name').notEmpty().withMessage('City name is required')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { stateId, name } = req.body;
    
    try {
      // Get state name
      const { rows: stateRows } = await pool.query("SELECT name FROM states WHERE id=$1", [stateId]);
      
      if (stateRows.length === 0) {
        return res.status(404).json({ error: "State not found" });
      }
      
      const stateName = stateRows[0].name;
      
      const { rows } = await pool.query(
        "INSERT INTO cities (state_id, name) VALUES ($1, $2) RETURNING *",
        [stateId, name]
      );
      
      const city = rows[0];
      
      // Transform data to match frontend expectations
      const transformedCity = {
        id: city.id,
        stateId: city.state_id,
        stateName: stateName,
        name: city.name,
        createdAt: city.created_at
      };
      
      res.json({ city: transformedCity });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to create city" });
    }
  }
);

app.get("/api/cities", authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.*, s.name as state_name 
      FROM cities c 
      JOIN states s ON c.state_id = s.id 
      ORDER BY s.name ASC, c.name ASC
    `);
    
    // Transform data to match frontend expectations
    const cities = rows.map(c => ({
      id: c.id,
      stateId: c.state_id,
      stateName: c.state_name,
      name: c.name,
      createdAt: c.created_at
    }));
    
    res.json({ cities });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch cities" });
  }
});

/* ----------------------------- Tasks ------------------------------- */
app.post("/api/tasks", authenticate, 
  [
    body('title').notEmpty().withMessage('Title is required'),
    body('description').optional().isString().withMessage('Description must be a string')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { title, description } = req.body;
    
    try {
      const { rows } = await pool.query(
        "INSERT INTO tasks (user_id, title, description) VALUES ($1, $2, $3) RETURNING *",
        [req.user.id, title, description]
      );
      
      res.json({ task: rows[0] });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to create task" });
    }
  }
);

app.get("/api/tasks", authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM tasks ORDER BY created_at DESC");
    res.json({ tasks: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch tasks" });
  }
});

/* ----------------------------- Locations ------------------------------- */
app.post("/api/locations", authenticate, 
  [
    body('latitude').isFloat().withMessage('Latitude must be a number'),
    body('longitude').isFloat().withMessage('Longitude must be a number'),
    body('address').optional().isString().withMessage('Address must be a string')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { latitude, longitude, address } = req.body;
    
    try {
      const { rows } = await pool.query(
        "INSERT INTO locations (user_id, latitude, longitude, address) VALUES ($1, $2, $3, $4) RETURNING *",
        [req.user.id, latitude, longitude, address]
      );
      
      res.json({ location: rows[0] });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to create location" });
    }
  }
);

app.get("/api/locations", authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM locations ORDER BY created_at DESC LIMIT 50");
    res.json({ locations: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch locations" });
  }
});

/* ----------------------------- Backups ------------------------------- */
app.post("/api/backups", authenticate, async (req, res) => {
  const { data } = req.body;
  
  try {
    const { rows } = await pool.query(
      "INSERT INTO backups (user_id, data) VALUES ($1, $2) RETURNING *",
      [req.user.id, data]
    );
    
    res.json({ backup: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create backup" });
  }
});

app.get("/api/backups", authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT * FROM backups WHERE user_id=$1 ORDER BY created_at DESC",
      [req.user.id]
    );
    
    res.json({ backups: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch backups" });
  }
});

/* ----------------------------- Health ------------------------------- */
app.get("/", (req, res) => res.json({ 
  ok: true, 
  uptime: process.uptime(),
  frontend: FRONTEND_URL
}));

/* ----------------------------- Start ------------------------------- */
migrate().then(seedUsers).catch(console.error);
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => console.log(`🚀 Backend running on port ${PORT}`));
