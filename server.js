import express from "express";
import http from "http";
import { Server as SocketIOServer } from "socket.io";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Pool } from "pg";
import axios from "axios";

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"]
  }
});

app.use(express.json({ limit: "10mb" }));
app.use(cors());
app.use(helmet());

// ====================== DATABASE ======================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

// ====================== AUTH MIDDLEWARE ======================
function verifyToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.status(403).json({ error: "No token provided" });

  jwt.verify(token.split(" ")[1], process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Unauthorized" });
    req.user = decoded;
    next();
  });
}

// ====================== AUTH ROUTES ======================
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });

    const user = rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "12h" }
    );

    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ====================== PROFILE ROUTES ======================

// Get logged-in user profile
app.get("/api/users/profile", verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT id, username, email, role FROM users WHERE id = $1",
      [req.user.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json(rows[0]);
  } catch (err) {
    console.error("Profile fetch error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Update logged-in user profile
app.put("/api/users/profile", verifyToken, async (req, res) => {
  try {
    const { username, email } = req.body;
    await pool.query(
      "UPDATE users SET username = $1, email = $2 WHERE id = $3",
      [username, email, req.user.id]
    );
    res.json({ message: "Profile updated successfully" });
  } catch (err) {
    console.error("Profile update error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Change password
app.put("/api/users/change-password", verifyToken, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    const { rows } = await pool.query("SELECT password FROM users WHERE id = $1", [req.user.id]);
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });

    const validPassword = await bcrypt.compare(oldPassword, rows[0].password);
    if (!validPassword) return res.status(400).json({ error: "Old password is incorrect" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query("UPDATE users SET password = $1 WHERE id = $2", [hashedPassword, req.user.id]);

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Password update error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ====================== ROLE ROUTES ======================

// Get available roles
app.get("/api/roles", verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT DISTINCT role FROM users");
    res.json(rows.map(r => r.role));
  } catch (err) {
    console.error("Roles fetch error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Assign role to a user
app.post("/api/users/:id/roles", verifyToken, async (req, res) => {
  try {
    const { role } = req.body;
    const userId = req.params.id;

    await pool.query("UPDATE users SET role = $1 WHERE id = $2", [role, userId]);
    res.json({ message: "Role updated successfully" });
  } catch (err) {
    console.error("Role update error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ====================== GEOCODING ======================
app.get("/api/geocode", verifyToken, async (req, res) => {
  try {
    const { lat, lon } = req.query;
    if (!lat || !lon) return res.status(400).json({ error: "Missing lat/lon" });

    // Check cache first
    const cacheCheck = await pool.query(
      "SELECT address FROM geocache WHERE lat = $1 AND lon = $2",
      [lat, lon]
    );

    if (cacheCheck.rows.length > 0) {
      return res.json({ address: cacheCheck.rows[0].address });
    }

    const response = await axios.get("https://nominatim.openstreetmap.org/reverse", {
      params: { lat, lon, format: "json" },
      headers: { "User-Agent": "Employee-Tracker/1.0" }
    });

    const address = response.data.display_name || "Unknown location";

    // Store in cache
    await pool.query("INSERT INTO geocache (lat, lon, address) VALUES ($1, $2, $3)", [
      lat,
      lon,
      address
    ]);

    res.json({ address });
  } catch (err) {
    console.error("Geocode error:", err);
    res.status(500).json({ error: "Geocoding failed" });
  }
});

// ====================== SOCKET.IO ======================
io.on("connection", (socket) => {
  console.log("Client connected:", socket.id);
  socket.on("disconnect", () => console.log("Client disconnected:", socket.id));
});

// ====================== SERVER START ======================
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
