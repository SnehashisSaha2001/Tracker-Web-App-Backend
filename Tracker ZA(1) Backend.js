/**
 * Tracker Backend – Full Code with All Improvements
 */
import express from "express";
import http from "http";
import { Server as SocketIOServer } from "socket.io";
import cors from "cors";
import helmet from "helmet";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { body, validationResult } from "express-validator";
import { v4 as uuidv4 } from "uuid";
import dotenv from "dotenv";
import fetch from "node-fetch";
import rateLimit from "express-rate-limit";
import morgan from "morgan";
dotenv.config();

/* ---------------------------- App & Server ---------------------------- */
const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, { 
  cors: { 
    origin: [
      "https://snehashissaha2001.github.io",
      "http://localhost:3000",
      "http://127.0.0.1:3000",
      "http://localhost:8080",
      "http://127.0.0.1:8080"
    ],
    methods: ["GET","POST","PUT","PATCH","DELETE"],
    credentials: true
  } 
});

app.use(cors({
  origin: [
    "https://snehashissaha2001.github.io",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8080",
    "http://127.0.0.1:8080"
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(helmet());
app.use(express.json({ limit: "2mb" }));
app.use(morgan('combined'));

/* ----------------------------- Rate Limiting --------------------------- */
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  message: "Too many requests, please try again later"
});
app.use("/api/", apiLimiter);

const geocodeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30, // Limit each IP to 30 geocoding requests per window
  message: "Too many geocoding requests, please try again later"
});

/* ----------------------------- Postgres ------------------------------ */
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

/* -------------------------- Helpers ------------------------- */
function signToken(user) {
  return jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1d" });
}

function authenticate(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ success: false, error: "Missing token" });
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ success: false, error: "Invalid token" });
    req.user = decoded;
    next();
  });
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ success: false, error: "Forbidden" });
    }
    next();
  };
}

// Enhanced error handling middleware
app.use((err, req, res, next) => {
  console.error(`${new Date().toISOString()} - ERROR:`, err.stack);
  
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: err.message,
      timestamp: new Date().toISOString()
    });
  }
  
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({
      success: false,
      error: 'Unauthorized',
      timestamp: new Date().toISOString()
    });
  }
  
  res.status(500).json({
    success: false,
    error: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message,
    timestamp: new Date().toISOString()
  });
});

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
        password_changed BOOLEAN DEFAULT FALSE,
        offline_login_allowed BOOLEAN DEFAULT FALSE,
        force_password_reset BOOLEAN DEFAULT TRUE,
        last_login TIMESTAMPTZ,
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
        sync_id UUID UNIQUE,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        type activity_type NOT NULL,
        details TEXT,
        latitude DOUBLE PRECISION,
        longitude DOUBLE PRECISION,
        address TEXT,
        version INTEGER DEFAULT 1,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS followups (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        sync_id UUID UNIQUE,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        subject TEXT NOT NULL,
        note TEXT,
        datetime TIMESTAMPTZ NOT NULL,
        version INTEGER DEFAULT 1,
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
      CREATE TABLE IF NOT EXISTS tasks (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        sync_id UUID UNIQUE,
        user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT NOT NULL DEFAULT 'todo',
        version INTEGER DEFAULT 1,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS locations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        sync_id UUID UNIQUE,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        latitude DOUBLE PRECISION NOT NULL,
        longitude DOUBLE PRECISION NOT NULL,
        address TEXT,
        version INTEGER DEFAULT 1,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);
    console.log("✅ Migration complete");
  } finally {
    client.release();
  }
}

/* -------------------------- Auto Seed Users -------------------------- */
const seedData = [
  { "name": "Shanti Saran Singh", "role": "admin", "email": "singhss@scube.co.in", "mobile": "9831038262", "employee_id": "ADM-S.S Singh" },
  { "name": "Sandeep Sarkar", "role": "admin", "email": "sandeep@scube.co.in", "mobile": "9831036858", "employee_id": "ADM-Sandeep" },
  { "name": "Snehashis Saha", "role": "admin", "email": "marcom@scube.co.in", "mobile": "9330199588", "employee_id": "ADM-Snehashis" },
  { "name": "Komal Gupta", "role": "admin", "email": "komal@scube.co.in", "mobile": "7003045682", "employee_id": "ADM-Komal" },
  { "name": "MD Shoaib Raza", "role": "admin", "email": "shoaib@scube.co.in", "mobile": "9831259095", "employee_id": "ADM-Shoaib" },
  { "name": "Snehasish Paul", "role": "employee", "email": "snehasish@scube.co.in", "mobile": "8017892062", "employee_id": "SCS-03318" },
  { "name": "Zuber Alam", "role": "employee", "email": "zuber@scube.co.in", "mobile": "9891377424", "employee_id": "SCS-01102" },
  { "name": "Bharath Kumar TM", "role": "employee", "email": "bharath@scube.co.in", "mobile": "9844722312", "employee_id": "SCS-08017" },
  { "name": "Shiva Kumarar", "role": "employee", "email": "shivuramaiah97@gmail.com", "mobile": "9611452782", "employee_id": "SCS-08016" },
  { "name": "Tapas Kumar Dinda", "role": "employee", "email": "tapas@scube.co.in", "mobile": "9804443387", "employee_id": "SCS-03317" },
  { "name": "Gopal Chandra Biswas", "role": "employee", "email": "gopalscube@gmail.com", "mobile": "9432095612", "employee_id": "SCS-03313" },
  { "name": "Saugat Majumdar", "role": "employee", "email": "saugat@scube.co.in", "mobile": "9831259094", "employee_id": "SCS-03303" },
  { "name": "Chitrarath Senapati", "role": "employee", "email": "senapati@scube.co.in", "mobile": "9831282190", "employee_id": "SCS-03306" },
  { "name": "Sukhendu Shekhar Mondal", "role": "employee", "email": "sukhendumondal7278@gmail.com", "mobile": "7278942388", "employee_id": "SCS-03316" },
  { "name": "Tarun Kumar Paramanik", "role": "employee", "email": "tarun@scube.co.in", "mobile": "9831650969", "employee_id": "SCS-03308" },
  { "name": "Kartik Ghanta", "role": "employee", "email": "kartik@scube.co.in", "mobile": "7074099074", "employee_id": "SCS-03309" },
  { "name": "Provat Naskar", "role": "employee", "email": "provatnaskar2324@gmail.com", "mobile": "7044486602", "employee_id": "SCS-03314" },
  { "name": "Ravi Kumar", "role": "employee", "email": "ravik954836@gmail.com", "mobile": "95483 62042", "employee_id": "SCS-01103" },
  { "name": "Abhilash Sarangi", "role": "employee", "email": "abhilash@scube.co.in", "mobile": "8763523636", "employee_id": "SCS-067403" },
  { "name": "Kishan Kanodia", "role": "employee", "email": "kishan@scube.co.in", "mobile": "7999610074", "employee_id": "SCS-077106" },
  { "name": "Nitai Charan Bera", "role": "employee", "email": "pintu@scube.co.in", "mobile": "9831650960", "employee_id": "SCS- 08002" }
];

async function seedUsers() {
  // Only seed in development or when explicitly enabled
  if (process.env.NODE_ENV === 'production' && process.env.SEED_DATA !== 'true') {
    console.log("🚫 Seeding skipped in production (set SEED_DATA=true to enable)");
    return;
  }

  const client = await pool.connect();
  try {
    const { rows } = await client.query("SELECT COUNT(*) FROM users");
    if (parseInt(rows[0].count) > 0) {
      console.log("👥 Users already exist, skipping seed");
      return;
    }
    
    // Function to generate a strong random password
    const generatePassword = () => {
      const length = 12;
      const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
      let password = "";
      for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * charset.length);
        password += charset[randomIndex];
      }
      return password;
    };
    
    for (const u of seedData) {
      const role = (u.role || "").toLowerCase() === "admin" ? "admin" : "employee";
      const name = (u.name || "").trim();
      const email = (u.email || "").trim() || null;
      const mobile = (u.mobile || "").trim() || null;
      const employee_id = (u.employee_id || "").trim();
      
      // Generate a unique strong password for each user
      const password = generatePassword();
      const hash = await bcrypt.hash(password, 10);
      
      await client.query(
        `INSERT INTO users (role, name, email, mobile, employee_id, password_hash, offline_login_allowed, force_password_reset) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [role, name, email, mobile, employee_id, hash, true, true] // Enable offline login and force password reset
      );
      
      // Log the generated password for development (remove in production)
      if (process.env.NODE_ENV !== 'production') {
        console.log(`Generated password for ${employee_id}: ${password}`);
      }
    }
    console.log("✅ Users seeded with unique passwords (" + seedData.length + " users)");
  } finally {
    client.release();
  }
}

/* -------------------------- Socket.IO ------------------------------- */
io.on('connection', (socket) => {
  console.log(`Client connected: ${socket.id}`);
  
  // Join room based on user role
  socket.on('join', (data) => {
    if (data.role === 'admin') {
      socket.join('admins');
      console.log(`Admin ${data.userId} joined admin room`);
    } else {
      socket.join(`user_${data.userId}`);
      console.log(`User ${data.userId} joined user room`);
    }
  });
  
  socket.on('disconnect', () => {
    console.log(`Client disconnected: ${socket.id}`);
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
    if (!user) return res.status(400).json({ success: false, error: "User not found" });
    
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(400).json({ success: false, error: "Invalid credentials" });
    
    // Update last login time
    await pool.query("UPDATE users SET last_login=NOW() WHERE id=$1", [user.id]);
    
    const token = signToken(user);
    
    res.json({ 
      success: true,
      token, 
      user: { 
        id: user.id, 
        name: user.name, 
        role: user.role, 
        employeeId: user.employee_id, 
        email: user.email, 
        mobile: user.mobile,
        offlineLoginAllowed: user.offline_login_allowed
      },
      forcePasswordReset: user.force_password_reset
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, error: "Login failed" });
  }
});

app.post("/api/auth/change-password", authenticate, 
  [
    body('currentPassword').notEmpty().withMessage('Current password is required'),
    body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('Password must contain uppercase, lowercase, and number')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { currentPassword, newPassword } = req.body;

    try {
      const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
      const user = rows[0];

      if (!user) {
        return res.status(404).json({ success: false, error: "User not found" });
      }

      const valid = await bcrypt.compare(currentPassword, user.password_hash);
      if (!valid) {
        return res.status(401).json({ success: false, error: "Current password is incorrect" });
      }

      const hash = await bcrypt.hash(newPassword, 10);
      await pool.query(
        "UPDATE users SET password_hash=$1, password_changed=TRUE, force_password_reset=FALSE WHERE id=$2",
        [hash, req.user.id]
      );

      res.json({ success: true, message: "Password changed successfully" });
    } catch (err) {
      console.error("Password change error:", err);
      res.status(500).json({ success: false, error: "Failed to change password" });
    }
  }
);

app.post("/api/sync-offline", authenticate, async (req, res) => {
  const { offlineData } = req.body;
  
  try {
    if (!offlineData || !Array.isArray(offlineData)) {
      return res.status(400).json({ 
        success: false, 
        error: "Offline data must be an array" 
      });
    }

    const syncResults = await processOfflineData(req.user.id, offlineData);
    
    res.json({ 
      success: true,
      syncResults
    });
  } catch (err) {
    console.error("Sync offline error:", err);
    res.status(500).json({ 
      success: false, 
      error: "Sync failed. Please try again later." 
    });
  }
});

app.post("/api/auth/validate-offline-login", authenticate, async (req, res) => {
  try {
    await pool.query("UPDATE users SET last_login=NOW() WHERE id=$1", [req.user.id]);
    res.json({ success: true, message: "Offline login validated" });
  } catch (err) {
    console.error("Validate offline login error:", err);
    res.status(500).json({ success: false, error: "Validation failed" });
  }
});

/* -------------------------- Geocode API ------------------------------ */
app.get("/api/geocode", authenticate, geocodeLimiter, async (req, res) => {
  const { address, lat, lon } = req.query;
  try {
    let url, response;
    
    if (address) {
      // Forward geocoding
      url = `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(address)}&limit=5&addressdetails=1`;
      response = await fetch(url, { headers: { "User-Agent": "TrackerApp/1.0" } });
      const data = await response.json();
      
      const results = data.map(item => ({
        display_name: item.display_name,
        lat: parseFloat(item.lat),
        lon: parseFloat(item.lon),
        address: {
          house_number: item.address?.house_number || '',
          road: item.address?.road || '',
          suburb: item.address?.suburb || '',
          city: item.address?.city || item.address?.town || item.address?.village || '',
          state: item.address?.state || '',
          postcode: item.address?.postcode || '',
          country: item.address?.country || ''
        }
      }));
      
      return res.json({ success: true, results });
    } else if (lat && lon) {
      // Reverse geocoding
      url = `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}&zoom=18&addressdetails=1`;
      response = await fetch(url, { headers: { "User-Agent": "TrackerApp/1.0" } });
      const data = await response.json();
      
      if (data.error) {
        return res.status(404).json({ success: false, error: data.error });
      }
      
      const address = {
        display_name: data.display_name,
        house_number: data.address?.house_number || '',
        road: data.address?.road || '',
        suburb: data.address?.suburb || '',
        city: data.address?.city || data.address?.town || data.address?.village || '',
        state: data.address?.state || '',
        postcode: data.address?.postcode || '',
        country: data.address?.country || ''
      };
      
      return res.json({ success: true, address });
    } else {
      return res.status(400).json({ success: false, error: "Provide either ?address=... or ?lat=...&lon=..." });
    }
  } catch (err) {
    console.error("Geocode error:", err);
    res.status(500).json({ success: false, error: "Geocoding failed" });
  }
});

/* -------------------------- Users API ------------------------------ */
app.get("/api/users", authenticate, requireRole("admin"), async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT id, role, name, email, mobile, employee_id, password_changed, offline_login_allowed, force_password_reset, last_login FROM users ORDER BY created_at DESC"
    );
    res.json({ success: true, users: rows });
  } catch (err) {
    console.error("Fetch users error:", err);
    res.status(500).json({ success: false, error: "Failed to fetch users" });
  }
});

app.post("/api/users", authenticate, requireRole("admin"), 
  [
    body('role').isIn(['admin', 'employee']).withMessage('Invalid role'),
    body('name').notEmpty().withMessage('Name is required'),
    body('email').optional().isEmail().withMessage('Invalid email'),
    body('mobile').optional().isMobilePhone().withMessage('Invalid mobile number'),
    body('employeeId').notEmpty().withMessage('Employee ID is required'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('Password must contain uppercase, lowercase, and number')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const { role, name, email, mobile, employeeId, password, offlineLoginAllowed } = req.body;
    
    try {
      const { rows } = await pool.query(
        "SELECT * FROM users WHERE employee_id=$1 OR mobile=$2 OR email=$3 LIMIT 1",
        [employeeId, mobile, email]
      );
      
      if (rows.length > 0) {
        return res.status(400).json({ success: false, error: "User already exists" });
      }
      
      const hash = await bcrypt.hash(password, 10);
      const { rows: [user] } = await pool.query(
        `INSERT INTO users (role, name, email, mobile, employee_id, password_hash, password_changed, offline_login_allowed, force_password_reset) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id, role, name, email, mobile, employee_id, password_changed, offline_login_allowed, force_password_reset`,
        [role, name, email, mobile, employeeId, hash, true, offlineLoginAllowed || false, false]
      );
      
      res.json({ success: true, user });
    } catch (err) {
      console.error("Create user error:", err);
      res.status(500).json({ success: false, error: "Failed to create user" });
    }
  }
);

/* -------------------------- Activities API --------------------------- */
app.post("/api/activities/batch", authenticate, async (req, res) => {
  try {
    const { activities } = req.body;
    
    if (!Array.isArray(activities) || activities.length === 0) {
      return res.status(400).json({ 
        success: false, 
        error: "Activities must be an array" 
      });
    }
    
    const results = [];
    
    for (const activity of activities) {
      const { type, details, latitude, longitude, address } = activity;
      
      try {
        const { rows } = await pool.query(
          `INSERT INTO activities (user_id, type, details, latitude, longitude, address) 
           VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
          [req.user.id, type, details, latitude, longitude, address]
        );
        
        const result = rows[0];
        const { rows: userRows } = await pool.query(
          "SELECT employee_id FROM users WHERE id=$1",
          [req.user.id]
        );
        
        const employeeId = userRows[0]?.employee_id || req.user.id;
        const transformedActivity = {
          id: result.id,
          employeeId: employeeId,
          timestamp: result.created_at,
          type: result.type,
          location: result.address,
          latitude: result.latitude,
          longitude: result.longitude,
          mapLink: result.latitude && result.longitude ? 
            `https://www.openstreetmap.org/?mlat=${result.latitude}&mlon=${result.longitude}` : null,
          details: result.details
        };
        
        results.push(transformedActivity);
        io.to('admins').emit('activity_update', {
          action: 'created',
          activity: transformedActivity
        });
      } catch (error) {
        console.error('Error creating activity:', error);
        results.push({ error: error.message, activity });
      }
    }
    
    res.json({ 
      success: true, 
      activities: results,
      processed: activities.length,
      successful: results.filter(r => !r.error).length
    });
  } catch (err) {
    console.error("Batch activities error:", err);
    res.status(500).json({ success: false, error: "Failed to create activities" });
  }
});

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
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const { type, details, latitude, longitude, address } = req.body;
    
    try {
      const { rows } = await pool.query(
        `INSERT INTO activities (user_id,type,details,latitude,longitude,address) 
         VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
        [req.user.id, type, details, latitude, longitude, address]
      );
      
      const activity = rows[0];
      const { rows: userRows } = await pool.query(
        "SELECT employee_id FROM users WHERE id=$1",
        [req.user.id]
      );
      
      const employeeId = userRows[0]?.employee_id || req.user.id;
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
      
      io.to('admins').emit('activity_update', {
        action: 'created',
        activity: transformedActivity
      });
      
      res.json({ success: true, activity: transformedActivity });
    } catch (err) {
      console.error("Create activity error:", err);
      res.status(500).json({ success: false, error: "Failed to create activity" });
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
    
    if (req.query.employeeId && req.user.role === 'admin') {
      query += params.length > 0 ? " AND u.employee_id = $" + (params.length + 1) : " WHERE u.employee_id = $1";
      params.push(req.query.employeeId);
    }
    
    if (req.query.date) {
      query += params.length > 0 ? " AND DATE(a.created_at) = $" + (params.length + 1) : " WHERE DATE(a.created_at) = $1";
      params.push(req.query.date);
    }
    
    query += " ORDER BY a.created_at DESC";
    
    const { rows } = await pool.query(query, params);
    
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
    
    res.json({ success: true, activities });
  } catch (err) {
    console.error("Fetch activities error:", err);
    res.status(500).json({ success: false, error: "Failed to fetch activities" });
  }
});

/* -------------------------- Followups API ---------------------------- */
app.post("/api/followups/batch", authenticate, async (req, res) => {
  try {
    const { followups } = req.body;
    
    if (!Array.isArray(followups) || followups.length === 0) {
      return res.status(400).json({ 
        success: false, 
        error: "Followups must be an array" 
      });
    }
    
    const results = [];
    
    for (const followup of followups) {
      const { subject, note, datetime } = followup;
      
      try {
        const { rows } = await pool.query(
          "INSERT INTO followups (user_id, subject, note, datetime) VALUES ($1, $2, $3, $4) RETURNING *",
          [req.user.id, subject, note, datetime]
        );
        
        const result = rows[0];
        const { rows: userRows } = await pool.query(
          "SELECT employee_id FROM users WHERE id=$1",
          [req.user.id]
        );
        
        const employeeId = userRows[0]?.employee_id || req.user.id;
        const transformedFollowup = {
          id: result.id,
          employeeId: employeeId,
          subject: result.subject,
          datetime: result.datetime,
          note: result.note,
          createdAt: result.created_at
        };
        
        results.push(transformedFollowup);
        io.to('admins').emit('followup_update', {
          action: 'created',
          followup: transformedFollowup
        });
      } catch (error) {
        console.error('Error creating followup:', error);
        results.push({ error: error.message, followup });
      }
    }
    
    res.json({ 
      success: true, 
      followups: results,
      processed: followups.length,
      successful: results.filter(r => !r.error).length
    });
  } catch (err) {
    console.error("Batch followups error:", err);
    res.status(500).json({ success: false, error: "Failed to create followups" });
  }
});

app.post("/api/followups", authenticate, 
  [
    body('subject').notEmpty().withMessage('Subject is required'),
    body('note').optional().isString().withMessage('Note must be a string'),
    body('datetime').isISO8601().withMessage('Invalid datetime format')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const { subject, note, datetime } = req.body;
    
    try {
      const { rows } = await pool.query(
        "INSERT INTO followups (user_id,subject,note,datetime) VALUES ($1,$2,$3,$4) RETURNING *",
        [req.user.id, subject, note, datetime]
      );
      
      const followup = rows[0];
      const { rows: userRows } = await pool.query(
        "SELECT employee_id FROM users WHERE id=$1",
        [req.user.id]
      );
      
      const employeeId = userRows[0]?.employee_id || req.user.id;
      const transformedFollowup = {
        id: followup.id,
        employeeId: employeeId,
        subject: followup.subject,
        datetime: followup.datetime,
        note: followup.note,
        createdAt: followup.created_at
      };
      
      io.to('admins').emit('followup_update', {
        action: 'created',
        followup: transformedFollowup
      });
      
      res.json({ success: true, followup: transformedFollowup });
    } catch (err) {
      console.error("Create followup error:", err);
      res.status(500).json({ success: false, error: "Failed to create followup" });
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
    
    if (req.query.employeeId && req.user.role === 'admin') {
      query += params.length > 0 ? " AND u.employee_id = $" + (params.length + 1) : " WHERE u.employee_id = $1";
      params.push(req.query.employeeId);
    }
    
    query += " ORDER BY f.datetime DESC";
    
    const { rows } = await pool.query(query, params);
    
    const followups = rows.map(f => ({
      id: f.id,
      employeeId: f.employee_id,
      subject: f.subject,
      datetime: f.datetime,
      note: f.note,
      createdAt: f.created_at
    }));
    
    res.json({ success: true, followups });
  } catch (err) {
    console.error("Fetch followups error:", err);
    res.status(500).json({ success: false, error: "Failed to fetch followups" });
  }
});

/* -------------------------- Tasks API -------------------------------- */
app.post("/api/tasks", authenticate, 
  [
    body('title').notEmpty().withMessage('Title is required'),
    body('description').optional().isString().withMessage('Description must be a string')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const { title, description, status } = req.body;
    
    try {
      const { rows } = await pool.query(
        "INSERT INTO tasks (user_id, title, description, status) VALUES ($1, $2, $3, $4) RETURNING *",
        [req.user.id, title, description, status || 'todo']
      );
      
      const task = rows[0];
      io.to('admins').emit('task_update', {
        action: 'created',
        task
      });
      
      res.json({ success: true, task });
    } catch (err) {
      console.error("Create task error:", err);
      res.status(500).json({ success: false, error: "Failed to create task" });
    }
  }
);

app.get("/api/tasks", authenticate, async (req, res) => {
  try {
    let query = "SELECT t.*, u.employee_id FROM tasks t LEFT JOIN users u ON t.user_id = u.id";
    let params = [];
    
    if (req.user.role !== 'admin') {
      query += " WHERE t.user_id = $1";
      params = [req.user.id];
    }
    
    query += " ORDER BY t.created_at DESC";
    
    const { rows } = await pool.query(query, params);
    
    const tasks = rows.map(t => ({
      id: t.id,
      employeeId: t.employee_id,
      title: t.title,
      description: t.description,
      status: t.status,
      createdAt: t.created_at,
      updatedAt: t.updated_at
    }));
    
    res.json({ success: true, tasks });
  } catch (err) {
    console.error("Fetch tasks error:", err);
    res.status(500).json({ success: false, error: "Failed to fetch tasks" });
  }
});

app.put("/api/tasks/:id", authenticate, 
  [
    body('title').notEmpty().withMessage('Title is required'),
    body('status').isIn(['todo', 'in-progress', 'completed']).withMessage('Invalid status')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const { id } = req.params;
    const { title, description, status } = req.body;
    
    try {
      const { rows } = await pool.query(
        "UPDATE tasks SET title=$1, description=$2, status=$3, updated_at=NOW() WHERE id=$4 RETURNING *",
        [title, description, status, id]
      );
      
      const task = rows[0];
      io.to('admins').emit('task_update', {
        action: 'updated',
        task
      });
      
      res.json({ success: true, task });
    } catch (err) {
      console.error("Update task error:", err);
      res.status(500).json({ success: false, error: "Failed to update task" });
    }
  }
);

app.delete("/api/tasks/:id", authenticate, async (req, res) => {
  const { id } = req.params;
  
  try {
    await pool.query("DELETE FROM tasks WHERE id=$1", [id]);
    
    io.to('admins').emit('task_update', {
      action: 'deleted',
      taskId: id
    });
    
    res.json({ success: true });
  } catch (err) {
    console.error("Delete task error:", err);
    res.status(500).json({ success: false, error: "Failed to delete task" });
  }
});

/* -------------------------- States API ------------------------------- */
app.post("/api/states", authenticate, requireRole("admin"), 
  [
    body('name').notEmpty().withMessage('State name is required')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const { name } = req.body;
    
    try {
      const { rows } = await pool.query("INSERT INTO states (name) VALUES ($1) RETURNING *", [name]);
      const state = rows[0];
      
      res.json({ success: true, state: {
        id: state.id,
        name: state.name,
        createdAt: state.created_at
      }});
    } catch (err) {
      console.error("Create state error:", err);
      res.status(500).json({ success: false, error: "Failed to create state" });
    }
  }
);

app.get("/api/states", authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM states ORDER BY name ASC");
    const states = rows.map(s => ({
      id: s.id,
      name: s.name,
      createdAt: s.created_at
    }));
    
    res.json({ success: true, states });
  } catch (err) {
    console.error("Fetch states error:", err);
    res.status(500).json({ success: false, error: "Failed to fetch states" });
  }
});

/* -------------------------- Cities API ------------------------------- */
app.post("/api/cities", authenticate, requireRole("admin"), 
  [
    body('stateId').isUUID().withMessage('Invalid state ID'),
    body('name').notEmpty().withMessage('City name is required')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const { stateId, name } = req.body;
    
    try {
      const { rows: stateRows } = await pool.query("SELECT name FROM states WHERE id=$1", [stateId]);
      
      if (stateRows.length === 0) {
        return res.status(404).json({ success: false, error: "State not found" });
      }
      
      const stateName = stateRows[0].name;
      const { rows } = await pool.query(
        "INSERT INTO cities (state_id, name) VALUES ($1, $2) RETURNING *",
        [stateId, name]
      );
      
      const city = rows[0];
      res.json({ success: true, city: {
        id: city.id,
        stateId: city.state_id,
        stateName: stateName,
        name: city.name,
        createdAt: city.created_at
      }});
    } catch (err) {
      console.error("Create city error:", err);
      res.status(500).json({ success: false, error: "Failed to create city" });
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
    
    const cities = rows.map(c => ({
      id: c.id,
      stateId: c.state_id,
      stateName: c.state_name,
      name: c.name,
      createdAt: c.created_at
    }));
    
    res.json({ success: true, cities });
  } catch (err) {
    console.error("Fetch cities error:", err);
    res.status(500).json({ success: false, error: "Failed to fetch cities" });
  }
});

/* -------------------------- Locations API ---------------------------- */
app.post("/api/locations", authenticate, 
  [
    body('latitude').isFloat().withMessage('Latitude must be a number'),
    body('longitude').isFloat().withMessage('Longitude must be a number'),
    body('address').optional().isString().withMessage('Address must be a string')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    let { latitude, longitude, address } = req.body;
    
    try {
      // Auto-fetch address if not provided
      if (!address || address.trim() === "") {
        try {
          const geoRes = await fetch(
            `https://nominatim.openstreetmap.org/reverse?format=json&lat=${latitude}&lon=${longitude}`,
            { headers: { "User-Agent": "TrackerApp/1.0" } }
          );
          const geoData = await geoRes.json();
          address = geoData.display_name || null;
        } catch (geoError) {
          console.error("Geocoding error in locations endpoint:", geoError);
          address = null;
        }
      }
      
      const { rows } = await pool.query(
        "INSERT INTO locations (user_id, latitude, longitude, address) VALUES ($1, $2, $3, $4) RETURNING *",
        [req.user.id, latitude, longitude, address]
      );
      
      const location = rows[0];
      io.to('admins').emit('location_update', {
        action: 'created',
        location
      });
      
      res.json({ success: true, location });
    } catch (err) {
      console.error("Create location error:", err);
      res.status(500).json({ success: false, error: "Failed to create location" });
    }
  }
);

app.get("/api/locations", authenticate, async (req, res) => {
  try {
    let query = "SELECT l.*, u.employee_id FROM locations l JOIN users u ON l.user_id = u.id";
    let params = [];
    
    if (req.user.role !== 'admin') {
      query += " WHERE l.user_id = $1";
      params = [req.user.id];
    }
    
    query += " ORDER BY l.created_at DESC LIMIT 50";
    
    const { rows } = await pool.query(query, params);
    
    const locations = rows.map(l => ({
      id: l.id,
      employeeId: l.employee_id,
      latitude: l.latitude,
      longitude: l.longitude,
      address: l.address,
      createdAt: l.created_at
    }));
    
    res.json({ success: true, locations });
  } catch (err) {
    console.error("Fetch locations error:", err);
    res.status(500).json({ success: false, error: "Failed to fetch locations" });
  }
});

/* -------------------------- Backups API ----------------------------- */
app.post("/api/backups", authenticate, async (req, res) => {
  const { data } = req.body;
  
  try {
    const { rows } = await pool.query(
      "INSERT INTO backups (user_id, data) VALUES ($1, $2) RETURNING *",
      [req.user.id, data]
    );
    
    res.json({ success: true, backup: rows[0] });
  } catch (err) {
    console.error("Create backup error:", err);
    res.status(500).json({ success: false, error: "Failed to create backup" });
  }
});

app.get("/api/backups", authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT * FROM backups WHERE user_id=$1 ORDER BY created_at DESC",
      [req.user.id]
    );
    
    res.json({ success: true, backups: rows });
  } catch (err) {
    console.error("Fetch backups error:", err);
    res.status(500).json({ success: false, error: "Failed to fetch backups" });
  }
});

app.post("/api/backups/restore/:id", authenticate, async (req, res) => {
  const { id } = req.params;
  
  try {
    const { rows } = await pool.query(
      "SELECT * FROM backups WHERE id=$1 AND user_id=$2",
      [id, req.user.id]
    );
    
    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: "Backup not found" });
    }
    
    const backup = rows[0];
    const restoreResults = await processOfflineData(req.user.id, backup.data);
    
    res.json({ 
      success: true,
      message: "Backup restored successfully",
      restoreResults
    });
  } catch (err) {
    console.error("Restore backup error:", err);
    res.status(500).json({ 
      success: false, 
      error: "Restore failed. Please try again later." 
    });
  }
});

/* -------------------------- Sync API -------------------------------- */
app.post("/api/sync", authenticate, async (req, res) => {
  try {
    const [activities, followups, states, cities, users, tasks] = await Promise.all([
      pool.query(`
        SELECT a.*, u.employee_id 
        FROM activities a 
        JOIN users u ON a.user_id = u.id
        ORDER BY a.created_at DESC
      `),
      pool.query(`
        SELECT f.*, u.employee_id 
        FROM followups f 
        JOIN users u ON f.user_id = u.id
        ORDER BY f.datetime DESC
      `),
      pool.query("SELECT * FROM states ORDER BY name ASC"),
      pool.query(`
        SELECT c.*, s.name as state_name 
        FROM cities c 
        JOIN states s ON c.state_id = s.id 
        ORDER BY s.name ASC, c.name ASC
      `),
      pool.query("SELECT id, role, name, email, mobile, employee_id FROM users ORDER BY created_at DESC"),
      pool.query("SELECT t.*, u.employee_id FROM tasks t LEFT JOIN users u ON t.user_id = u.id ORDER BY t.created_at DESC")
    ]);
    
    const transformedActivities = activities[0].rows.map(act => ({
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
    
    const transformedFollowups = followups[0].rows.map(f => ({
      id: f.id,
      employeeId: f.employee_id,
      subject: f.subject,
      datetime: f.datetime,
      note: f.note,
      createdAt: f.created_at
    }));
    
    const transformedStates = states[0].rows.map(s => ({
      id: s.id,
      name: s.name,
      createdAt: s.created_at
    }));
    
    const transformedCities = cities[0].rows.map(c => ({
      id: c.id,
      stateId: c.state_id,
      stateName: c.state_name,
      name: c.name,
      createdAt: c.created_at
    }));
    
    const transformedUsers = users[0].rows.map(u => ({
      employeeId: u.employee_id,
      name: u.name,
      mobileNo: u.mobile,
      emailId: u.email,
      role: u.role,
      id: u.id
    }));
    
    const transformedTasks = tasks[0].rows.map(t => ({
      id: t.id,
      employeeId: t.employee_id,
      title: t.title,
      description: t.description,
      status: t.status,
      createdAt: t.created_at,
      updatedAt: t.updated_at
    }));
    
    res.json({
      success: true,
      data: {
        activities: transformedActivities,
        followups: transformedFollowups,
        states: transformedStates,
        cities: transformedCities,
        users: transformedUsers,
        tasks: transformedTasks
      }
    });
  } catch (err) {
    console.error("Sync error:", err);
    res.status(500).json({ success: false, error: "Failed to sync data" });
  }
});

/* -------------------------- Helper Functions ------------------------- */
async function processOfflineData(userId, offlineData) {
  const results = {
    activities: { success: 0, failed: 0, conflicts: 0 },
    followups: { success: 0, failed: 0, conflicts: 0 },
    locations: { success: 0, failed: 0, conflicts: 0 },
    tasks: { success: 0, failed: 0, conflicts: 0 }
  };
  
  for (const item of offlineData) {
    try {
      const syncId = item.syncId || uuidv4();
      
      switch (item.type) {
        case 'activity':
          const existingActivity = await pool.query(
            "SELECT * FROM activities WHERE sync_id=$1",
            [syncId]
          );
          
          if (existingActivity.rows.length > 0) {
            if (item.version > existingActivity.rows[0].version) {
              await pool.query(
                `UPDATE activities SET details=$1, latitude=$2, longitude=$3, address=$4, version=$5, updated_at=NOW() 
                 WHERE id=$6`,
                [item.data.details, item.data.latitude, item.data.longitude, item.data.address, item.version, existingActivity.rows[0].id]
              );
              results.activities.success++;
              
              io.to('admins').emit('activity_update', {
                action: 'updated',
                activity: { ...existingActivity.rows[0], ...item.data }
              });
            } else {
              results.activities.conflicts++;
            }
          } else {
            const { rows } = await pool.query(
              `INSERT INTO activities (user_id, type, details, latitude, longitude, address, sync_id, created_at, version) 
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
              [userId, item.data.type, item.data.details, item.data.latitude, 
               item.data.longitude, item.data.address, syncId, item.timestamp, item.version]
            );
            results.activities.success++;
            
            io.to('admins').emit('activity_update', {
              action: 'created',
              activity: rows[0]
            });
          }
          break;
          
        case 'followup':
          const existingFollowup = await pool.query(
            "SELECT * FROM followups WHERE sync_id=$1",
            [syncId]
          );
          
          if (existingFollowup.rows.length > 0) {
            if (item.version > existingFollowup.rows[0].version) {
              await pool.query(
                `UPDATE followups SET subject=$1, note=$2, datetime=$3, version=$4, updated_at=NOW() WHERE id=$5`,
                [item.data.subject, item.data.note, item.data.datetime, item.version, existingFollowup.rows[0].id]
              );
              results.followups.success++;
              
              io.to('admins').emit('followup_update', {
                action: 'updated',
                followup: { ...existingFollowup.rows[0], ...item.data }
              });
            } else {
              results.followups.conflicts++;
            }
          } else {
            const { rows } = await pool.query(
              `INSERT INTO followups (user_id, subject, note, datetime, sync_id, created_at, version) 
               VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
              [userId, item.data.subject, item.data.note, item.data.datetime, syncId, item.timestamp, item.version]
            );
            results.followups.success++;
            
            io.to('admins').emit('followup_update', {
              action: 'created',
              followup: rows[0]
            });
          }
          break;
          
        case 'location':
          const existingLocation = await pool.query(
            "SELECT * FROM locations WHERE sync_id=$1",
            [syncId]
          );
          
          if (existingLocation.rows.length > 0) {
            if (item.version > existingLocation.rows[0].version) {
              await pool.query(
                `UPDATE locations SET latitude=$1, longitude=$2, address=$3, version=$4, updated_at=NOW() WHERE id=$5`,
                [item.data.latitude, item.data.longitude, item.data.address, item.version, existingLocation.rows[0].id]
              );
              results.locations.success++;
              
              io.to('admins').emit('location_update', {
                action: 'updated',
                location: { ...existingLocation.rows[0], ...item.data }
              });
            } else {
              results.locations.conflicts++;
            }
          } else {
            const { rows } = await pool.query(
              `INSERT INTO locations (user_id, latitude, longitude, address, sync_id, created_at, version) 
               VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
              [userId, item.data.latitude, item.data.longitude, item.data.address, syncId, item.timestamp, item.version]
            );
            results.locations.success++;
            
            io.to('admins').emit('location_update', {
              action: 'created',
              location: rows[0]
            });
          }
          break;
          
        case 'task':
          const existingTask = await pool.query(
            "SELECT * FROM tasks WHERE sync_id=$1",
            [syncId]
          );
          
          if (existingTask.rows.length > 0) {
            if (item.version > existingTask.rows[0].version) {
              await pool.query(
                `UPDATE tasks SET title=$1, description=$2, status=$3, version=$4, updated_at=NOW() WHERE id=$5`,
                [item.data.title, item.data.description, item.data.status, item.version, existingTask.rows[0].id]
              );
              results.tasks.success++;
              
              io.to('admins').emit('task_update', {
                action: 'updated',
                task: { ...existingTask.rows[0], ...item.data }
              });
            } else {
              results.tasks.conflicts++;
            }
          } else {
            const { rows } = await pool.query(
              `INSERT INTO tasks (user_id, title, description, status, sync_id, created_at, version) 
               VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
              [userId, item.data.title, item.data.description, item.data.status, syncId, item.timestamp, item.version]
            );
            results.tasks.success++;
            
            io.to('admins').emit('task_update', {
              action: 'created',
              task: rows[0]
            });
          }
          break;
      }
    } catch (error) {
      console.error(`Error processing offline ${item.type}:`, error);
      switch (item.type) {
        case 'activity': results.activities.failed++; break;
        case 'followup': results.followups.failed++; break;
        case 'location': results.locations.failed++; break;
        case 'task': results.tasks.failed++; break;
      }
    }
  }
  
  return results;
}

/* -------------------------- Health Check ---------------------------- */
app.get("/", (req, res) => {
  res.json({ 
    ok: true, 
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

/* -------------------------- Start Server ---------------------------- */
migrate().then(seedUsers).catch(console.error);
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`✅ Tracker backend running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Database: ${process.env.DATABASE_URL ? 'Connected' : 'Not configured'}`);
});
