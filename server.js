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
    origin: "*", // Allow all origins for development
    methods: ["GET", "POST"],
  },
});

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ---------- Middleware ----------
app.use(helmet());
app.use(cors());
app.use(express.json());

// ---------- Authentication Middleware ----------
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: "Authentication required" });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid token" });
    }
    req.user = user;
    next();
  });
}

// ---------- Geocoding Endpoint ----------
app.get("/api/geocode", authenticateToken, async (req, res) => {
  try {
    const { lat, lon, address } = req.query;
    
    if (!lat && !lon && !address) {
      return res.status(400).json({ 
        success: false, 
        error: "Provide either coordinates (lat, lon) or an address" 
      });
    }
    
    let url;
    if (address) {
      // Forward geocoding (address to coordinates)
      url = `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(address)}`;
    } else {
      // Reverse geocoding (coordinates to address)
      url = `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}`;
    }
    
    // Make request to Nominatim API
    const response = await fetch(url);
    
    if (!response.ok) {
      throw new Error(`Nominatim API error: ${response.status}`);
    }
    
    const data = await response.json();
    
    // Format response based on request type
    if (address) {
      // Forward geocoding response
      return res.json({
        success: true,
        results: data
      });
    } else {
      // Reverse geocoding response
      return res.json({
        success: true,
        address: data
      });
    }
  } catch (error) {
    console.error("Geocoding error:", error);
    res.status(500).json({
      success: false,
      error: error.message || "Geocoding failed"
    });
  }
});

// ---------- DB Migration ----------
async function migrate() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        role TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        mobile TEXT,
        employee_id TEXT,
        password TEXT NOT NULL
      );
    `);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS checkins (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id),
        latitude FLOAT,
        longitude FLOAT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    
    // Add activities table if it doesn't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS activities (
        id SERIAL PRIMARY KEY,
        employee_id TEXT NOT NULL,
        type TEXT NOT NULL,
        details TEXT,
        latitude FLOAT,
        longitude FLOAT,
        address TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    
    // Add followups table if it doesn't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS followups (
        id SERIAL PRIMARY KEY,
        employee_id TEXT NOT NULL,
        subject TEXT NOT NULL,
        note TEXT,
        datetime TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    
    // Add states table if it doesn't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS states (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    
    // Add cities table if it doesn't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS cities (
        id SERIAL PRIMARY KEY,
        state_id INTEGER REFERENCES states(id),
        name TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(state_id, name)
      );
    `);
    
    console.log("✅ Migration complete");
  } catch (error) {
    console.error("Migration error:", error);
  }
}

// ---------- Seeding ----------
async function seedData() {
  if (process.env.SEED_DATA !== "true") {
    console.log("🚫 Seeding skipped (SEED_DATA not true)");
    return;
  }
  
  try {
    console.log("🌱 Starting database seeding...");
    const admins = [
      { name: "Shanti Saran Singh", role: "admin", email: "singhss@scube.co.in", mobile: "9831038262", employee_id: "ADM-S.S Singh" },
      { name: "Sandeep Sarkar", role: "admin", email: "sandeep@scube.co.in", mobile: "9831036858", employee_id: "ADM-Sandeep" },
      { name: "Snehashis Saha", role: "admin", email: "marcom@scube.co.in", mobile: "9330199588", employee_id: "ADM-Snehashis" },
      { name: "Komal Gupta", role: "admin", email: "komal@scube.co.in", mobile: "7003045682", employee_id: "ADM-Komal" },
      { name: "MD Shoaib Raza", role: "admin", email: "shoaib@scube.co.in", mobile: "9831259095", employee_id: "ADM-Shoaib" },
    ];
    const employees = [
      { name: "Snehasish Paul", role: "employee", email: "snehasish@scube.co.in", mobile: "8017892062", employee_id: "SCS-03318" },
      { name: "Zuber Alam", role: "employee", email: "zuber@scube.co.in", mobile: "9891377424", employee_id: "SCS-01102" },
      { name: "Bharath Kumar TM", role: "employee", email: "bharath@scube.co.in", mobile: "9844722312", employee_id: "SCS-08017" },
      { name: "Shiva Kumarar", role: "employee", email: "shivuramaiah97@gmail.com", mobile: "9611452782", employee_id: "SCS-08016" },
      { name: "Tapas Kumar Dinda", role: "employee", email: "tapas@scube.co.in", mobile: "9804443387", employee_id: "SCS-03317" },
      { name: "Gopal Chandra Biswas", role: "employee", email: "gopalscube@gmail.com", mobile: "9432095612", employee_id: "SCS-03313" },
      { name: "Saugat Majumdar", role: "employee", email: "saugat@scube.co.in", mobile: "9831259094", employee_id: "SCS-03303" },
      { name: "Chitrarath Senapati", role: "employee", email: "senapati@scube.co.in", mobile: "9831282190", employee_id: "SCS-03306" },
      { name: "Sukhendu Shekhar Mondal", role: "employee", email: "sukhendumondal7278@gmail.com", mobile: "7278942388", employee_id: "SCS-03316" },
      { name: "Tarun Kumar Paramanik", role: "employee", email: "tarun@scube.co.in", mobile: "9831650969", employee_id: "SCS-03308" },
      { name: "Kartik Ghanta", role: "employee", email: "kartik@scube.co.in", mobile: "7074099074", employee_id: "SCS-03309" },
      { name: "Provat Naskar", role: "employee", email: "provatnaskar2324@gmail.com", mobile: "7044486602", employee_id: "SCS-03314" },
      { name: "Ravi Kumar", role: "employee", email: "ravik954836@gmail.com", mobile: "9548362042", employee_id: "SCS-01103" },
      { name: "Abhilash Sarangi", role: "employee", email: "abhilash@scube.co.in", mobile: "8763523636", employee_id: "SCS-067403" },
      { name: "Kishan Kanodia", role: "employee", email: "kishan@scube.co.in", mobile: "7999610074", employee_id: "SCS-077106" },
      { name: "Nitai Charan Bera", role: "employee", email: "pintu@scube.co.in", mobile: "9831650960", employee_id: "SCS-08002" },
    ];
    
    const adminPassword = await bcrypt.hash("scube@1234", 10);
    const employeePassword = await bcrypt.hash("scube@4321", 10);
    
    for (const u of [...admins, ...employees]) {
      const hashed = u.role === "admin" ? adminPassword : employeePassword;
      await pool.query(
        `INSERT INTO users (name, role, email, mobile, employee_id, password)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (email) DO NOTHING`,
        [u.name, u.role, u.email, u.mobile, u.employee_id, hashed]
      );
    }
    
    console.log("✅ Users seeded with fixed passwords");
    console.log("🔑 Admin password: scube@1234");
    console.log("🔑 Employee password: scube@4321");
  } catch (error) {
    console.error("Seeding error:", error);
  }
}

// ---------- Routes ----------
app.get("/", (req, res) => {
  res.json({ status: "Backend running" });
});

// Authentication endpoint
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Check if email or employee_id is provided
    const identifier = email;
    
    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1 OR employee_id=$1",
      [identifier]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid email/employee ID or password" });
    }
    
    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid email/employee ID or password" });
    }
    
    const token = jwt.sign(
      { id: user.id, role: user.role, email: user.email, employee_id: user.employee_id },
      JWT_SECRET,
      { expiresIn: "7d" }
    );
    
    res.json({ 
      token, 
      user: {
        id: user.id,
        name: user.name,
        role: user.role,
        email: user.email,
        employee_id: user.employee_id,
        mobile: user.mobile
      }
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Login failed" });
  }
});

// Activities endpoints
app.get("/api/activities", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM activities ORDER BY timestamp DESC"
    );
    res.json({ activities: result.rows });
  } catch (error) {
    console.error("Error fetching activities:", error);
    res.status(500).json({ error: "Failed to fetch activities" });
  }
});

app.post("/api/activities", authenticateToken, async (req, res) => {
  try {
    const { type, details, latitude, longitude, address } = req.body;
    const user = req.user;
    
    // Get employee_id from users table
    const userResult = await pool.query(
      "SELECT employee_id FROM users WHERE id = $1",
      [user.id]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    
    const employeeId = userResult.rows[0].employee_id;
    
    const result = await pool.query(
      `INSERT INTO activities (employee_id, type, details, latitude, longitude, address)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [employeeId, type, details, latitude, longitude, address]
    );
    
    // Emit socket event for real-time updates
    io.emit("activity_update", {
      action: "created",
      activity: result.rows[0]
    });
    
    res.json({ success: true, activity: result.rows[0] });
  } catch (error) {
    console.error("Error creating activity:", error);
    res.status(500).json({ error: "Failed to create activity" });
  }
});

// Followups endpoints
app.get("/api/followups", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM followups ORDER BY created_at DESC"
    );
    res.json({ followups: result.rows });
  } catch (error) {
    console.error("Error fetching followups:", error);
    res.status(500).json({ error: "Failed to fetch followups" });
  }
});

app.post("/api/followups", authenticateToken, async (req, res) => {
  try {
    const { subject, note, datetime } = req.body;
    const user = req.user;
    
    // Get employee_id from users table
    const userResult = await pool.query(
      "SELECT employee_id FROM users WHERE id = $1",
      [user.id]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    
    const employeeId = userResult.rows[0].employee_id;
    
    const result = await pool.query(
      `INSERT INTO followups (employee_id, subject, note, datetime)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [employeeId, subject, note, datetime]
    );
    
    // Emit socket event for real-time updates
    io.emit("followup_update", {
      action: "created",
      followup: result.rows[0]
    });
    
    res.json({ success: true, followup: result.rows[0] });
  } catch (error) {
    console.error("Error creating followup:", error);
    res.status(500).json({ error: "Failed to create followup" });
  }
});

// States endpoints
app.get("/api/states", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM states ORDER BY name"
    );
    res.json({ states: result.rows });
  } catch (error) {
    console.error("Error fetching states:", error);
    res.status(500).json({ error: "Failed to fetch states" });
  }
});

app.post("/api/states", authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;
    const result = await pool.query(
      "INSERT INTO states (name) VALUES ($1) RETURNING *",
      [name]
    );
    res.json({ success: true, state: result.rows[0] });
  } catch (error) {
    console.error("Error creating state:", error);
    res.status(500).json({ error: "Failed to create state" });
  }
});

// Cities endpoints
app.get("/api/cities", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT cities.*, states.name as state_name 
       FROM cities 
       JOIN states ON cities.state_id = states.id 
       ORDER BY states.name, cities.name`
    );
    res.json({ cities: result.rows });
  } catch (error) {
    console.error("Error fetching cities:", error);
    res.status(500).json({ error: "Failed to fetch cities" });
  }
});

app.post("/api/cities", authenticateToken, async (req, res) => {
  try {
    const { stateId, name } = req.body;
    const result = await pool.query(
      "INSERT INTO cities (state_id, name) VALUES ($1, $2) RETURNING *",
      [stateId, name]
    );
    res.json({ success: true, city: result.rows[0] });
  } catch (error) {
    console.error("Error creating city:", error);
    res.status(500).json({ error: "Failed to create city" });
  }
});

// Users endpoints
app.get("/api/users", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, role, email, mobile, employee_id FROM users ORDER BY name"
    );
    res.json({ users: result.rows });
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

app.post("/api/users", authenticateToken, async (req, res) => {
  try {
    const { role, name, email, mobile, employeeId, password } = req.body;
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      `INSERT INTO users (role, name, email, mobile, employee_id, password)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, name, role, email, mobile, employee_id`,
      [role, name, email, mobile, employeeId, hashedPassword]
    );
    
    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ error: "Failed to create user" });
  }
});

// Legacy checkin endpoints (for compatibility)
app.post("/api/checkin", async (req, res) => {
  try {
    const { user_id, latitude, longitude } = req.body;
    await pool.query(
      "INSERT INTO checkins (user_id, latitude, longitude) VALUES ($1,$2,$3)",
      [user_id, latitude, longitude]
    );
    io.emit("new-checkin", { user_id, latitude, longitude });
    res.json({ success: true });
  } catch (error) {
    console.error("Checkin error:", error);
    res.status(500).json({ error: "Failed to record checkin" });
  }
});

app.get("/api/checkins", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM checkins ORDER BY timestamp DESC LIMIT 50"
    );
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching checkins:", error);
    res.status(500).json({ error: "Failed to fetch checkins" });
  }
});

// ---------- Socket.IO Connection Handling ----------
io.on("connection", (socket) => {
  console.log("A user connected:", socket.id);
  
  // Handle joining rooms based on user role
  socket.on("join", (data) => {
    if (data.role && data.userId) {
      socket.join(data.role);
      console.log(`User ${data.userId} joined ${data.role} room`);
    }
  });
  
  socket.on("disconnect", () => {
    console.log("A user disconnected:", socket.id);
  });
});

// ---------- Start Server ----------
async function startServer() {
  try {
    console.log("📊 Database: Connected");
    await migrate();
    await seedData();
    server.listen(PORT, () => {
      console.log(`✅ Tracker backend running on port ${PORT}`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV}`);
    });
  } catch (err) {
    console.error("❌ Failed to start server:", err);
    process.exit(1);
  }
}

startServer();
