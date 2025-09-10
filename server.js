import express from "express";
import http from "http";
import { Server as SocketIOServer } from "socket.io";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import { Pool } from "pg";
import axios from "axios";

dotenv.config();
const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(helmet());
app.use(express.json());

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ================== DATABASE MIGRATION ==================
async function migrate() {
  try {
    await pool.query("DROP TABLE IF EXISTS activities CASCADE;");
    await pool.query("DROP TABLE IF EXISTS users CASCADE;");
    
    await pool.query(`
      CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100),
        role VARCHAR(20),
        email VARCHAR(100) UNIQUE,
        mobile VARCHAR(20),
        employee_id VARCHAR(50),
        password VARCHAR(200)
      );
    `);
    
    await pool.query(`
      CREATE TABLE activities (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        activity TEXT,
        location TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    
    console.log("✅ Migration complete");
  } catch (err) {
    console.error("Migration error:", err);
    throw err;
  }
}

// ================== SEEDING ==================
async function seedData() {
  if (process.env.NODE_ENV === "production" && process.env.SEED_DATA !== "true") {
    console.log("🚫 Seeding skipped in production (set SEED_DATA=true to enable)");
    return;
  }
  
  console.log("🌱 Starting database seeding...");
  
  try {
    await pool.query("TRUNCATE TABLE users RESTART IDENTITY CASCADE;");
    
    const adminPassword = await bcrypt.hash("scube@1234", 10);
    const employeePassword = await bcrypt.hash("scube@4321", 10);
    
    const users = [
      { name: "Shanti Saran Singh", role: "admin", email: "singhss@scube.co.in", mobile: "9831038262", employee_id: "ADM-S.S Singh", password: adminPassword },
      { name: "Sandeep Sarkar", role: "admin", email: "sandeep@scube.co.in", mobile: "9831036858", employee_id: "ADM-Sandeep", password: adminPassword },
      { name: "Snehashis Saha", role: "admin", email: "marcom@scube.co.in", mobile: "9330199588", employee_id: "ADM-Snehashis", password: adminPassword },
      { name: "Komal Gupta", role: "admin", email: "komal@scube.co.in", mobile: "7003045682", employee_id: "ADM-Komal", password: adminPassword },
      { name: "MD Shoaib Raza", role: "admin", email: "shoaib@scube.co.in", mobile: "9831259095", employee_id: "ADM-Shoaib", password: adminPassword },
      { name: "Snehasish Paul", role: "employee", email: "snehasish@scube.co.in", mobile: "8017892062", employee_id: "SCS-03318", password: employeePassword },
      { name: "Zuber Alam", role: "employee", email: "zuber@scube.co.in", mobile: "9891377424", employee_id: "SCS-01102", password: employeePassword },
      { name: "Bharath Kumar TM", role: "employee", email: "bharath@scube.co.in", mobile: "9844722312", employee_id: "SCS-08017", password: employeePassword },
      { name: "Shiva Kumarar", role: "employee", email: "shivuramaiah97@gmail.com", mobile: "9611452782", employee_id: "SCS-08016", password: employeePassword },
      { name: "Tapas Kumar Dinda", role: "employee", email: "tapas@scube.co.in", mobile: "9804443387", employee_id: "SCS-03317", password: employeePassword },
      { name: "Gopal Chandra Biswas", role: "employee", email: "gopalscube@gmail.com", mobile: "9432095612", employee_id: "SCS-03313", password: employeePassword },
      { name: "Saugat Majumdar", role: "employee", email: "saugat@scube.co.in", mobile: "9831259094", employee_id: "SCS-03303", password: employeePassword },
      { name: "Chitrarath Senapati", role: "employee", email: "senapati@scube.co.in", mobile: "9831282190", employee_id: "SCS-03306", password: employeePassword },
      { name: "Sukhendu Shekhar Mondal", role: "employee", email: "sukhendumondal7278@gmail.com", mobile: "7278942388", employee_id: "SCS-03316", password: employeePassword },
      { name: "Tarun Kumar Paramanik", role: "employee", email: "tarun@scube.co.in", mobile: "9831650969", employee_id: "SCS-03308", password: employeePassword },
      { name: "Kartik Ghanta", role: "employee", email: "kartik@scube.co.in", mobile: "7074099074", employee_id: "SCS-03309", password: employeePassword },
      { name: "Provat Naskar", role: "employee", email: "provatnaskar2324@gmail.com", mobile: "7044486602", employee_id: "SCS-03314", password: employeePassword },
      { name: "Ravi Kumar", role: "employee", email: "ravik954836@gmail.com", mobile: "9548362042", employee_id: "SCS-01103", password: employeePassword },
      { name: "Abhilash Sarangi", role: "employee", email: "abhilash@scube.co.in", mobile: "8763523636", employee_id: "SCS-067403", password: employeePassword },
      { name: "Kishan Kanodia", role: "employee", email: "kishan@scube.co.in", mobile: "7999610074", employee_id: "SCS-077106", password: employeePassword },
      { name: "Nitai Charan Bera", role: "employee", email: "pintu@scube.co.in", mobile: "9831650960", employee_id: "SCS-08002", password: employeePassword },
    ];
    
    for (const u of users) {
      await pool.query(
        "INSERT INTO users (name, role, email, mobile, employee_id, password) VALUES ($1,$2,$3,$4,$5,$6)",
        [u.name, u.role, u.email, u.mobile, u.employee_id, u.password]
      );
    }
    
    console.log("✅ Users seeded with fixed passwords");
    console.log(`🔑 Admin password: scube@1234`);
    console.log(`🔑 Employee password: scube@4321`);
  } catch (err) {
    console.error("Seeding error:", err);
    throw err;
  }
}

// ================== AUTH ENDPOINT ==================
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (result.rows.length === 0) return res.status(400).json({ error: "User not found" });
    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid password" });
    res.json({ 
      message: "Login successful", 
      user: { 
        id: user.id, 
        name: user.name, 
        role: user.role, 
        email: user.email,
        employee_id: user.employee_id
      } 
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// ================== GEOCODING ENDPOINT ==================
app.get('/api/geocode', async (req, res) => {
  const { lat, lon, address } = req.query;

  try {
    if (address) {
      // Forward geocoding
      const response = await axios.get("https://nominatim.openstreetmap.org/search", {
        params: { q: address, format: "json", limit: 1 },
        headers: { "User-Agent": "TrackerApp/1.0" }
      });
      if (response.data && response.data.length > 0) {
        const loc = response.data[0];
        return res.json({ lat: parseFloat(loc.lat), lng: parseFloat(loc.lon) });
      } else {
        return res.status(404).json({ error: "No results found" });
      }
    } else if (lat && lon) {
      // Reverse geocoding
      const response = await axios.get("https://nominatim.openstreetmap.org/reverse", {
        params: { lat, lon, format: "json" },
        headers: { "User-Agent": "TrackerApp/1.0" }
      });
      if (response.data && response.data.display_name) {
        return res.json({ address: response.data.display_name });
      } else {
        return res.status(404).json({ error: "No address found" });
      }
    }
    return res.status(400).json({ error: "Either address or lat/lon required" });
  } catch (err) {
    console.error("Geocoding error:", err.message);
    res.status(500).json({ error: "Failed to geocode" });
  }
});

// ================== ACTIVITY ENDPOINTS ==================

// Create a new activity
app.post("/api/activities", async (req, res) => {
  const { user_id, activity, location } = req.body;
  if (!user_id || !activity) {
    return res.status(400).json({ error: "user_id and activity required" });
  }
  try {
    const result = await pool.query(
      "INSERT INTO activities (user_id, activity, location) VALUES ($1,$2,$3) RETURNING *",
      [user_id, activity, location || null]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Activity insert error:", err);
    res.status(500).json({ error: "Failed to create activity" });
  }
});

// Get all activities for a user
app.get("/api/activities/:user_id", async (req, res) => {
  const { user_id } = req.params;
  try {
    const result = await pool.query(
      "SELECT * FROM activities WHERE user_id=$1 ORDER BY created_at DESC",
      [user_id]
    );
    res.json(result.rows); // Always an array
  } catch (err) {
    console.error("Activities fetch error:", err);
    res.status(500).json({ error: "Failed to fetch activities" });
  }
});

// Checkout (mark checkout activity)
app.post("/api/checkout", async (req, res) => {
  const { user_id, location } = req.body;
  if (!user_id) return res.status(400).json({ error: "user_id required" });
  try {
    const result = await pool.query(
      "INSERT INTO activities (user_id, activity, location) VALUES ($1,$2,$3) RETURNING *",
      [user_id, "checkout", location || null]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Checkout error:", err);
    res.status(500).json({ error: "Failed to checkout" });
  }
});

// ================== START SERVER ==================
const PORT = process.env.PORT || 10000;

async function startServer() {
  try {
    await pool.query("SELECT NOW()");
    console.log("📊 Database: Connected");
    
    await migrate();
    
    if (process.env.SEED_DATA === "true") {
      console.log("🌱 Starting database seeding...");
      await seedData();
    } else {
      console.log("🚫 Seeding skipped (set SEED_DATA=true to enable)");
    }
    
    server.listen(PORT, () => {
      console.log(`✅ Tracker backend running on port ${PORT}`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || "development"}`);
    });
  } catch (err) {
    console.error("❌ Failed to start server:", err);
    process.exit(1);
  }
}

startServer();
