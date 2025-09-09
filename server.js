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
    origin: "*", // allow frontend
    methods: ["GET", "POST"],
  },
});

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ---------- DB Migration ----------
async function migrate() {
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
  console.log("✅ Migration complete");
}

// ---------- Seeding ----------
async function seedData() {
  if (process.env.SEED_DATA !== "true") {
    console.log("🚫 Seeding skipped (SEED_DATA not true)");
    return;
  }

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
}

// ---------- Middleware ----------
app.use(helmet());
app.use(cors());
app.use(express.json());

// ---------- Routes ----------
app.get("/", (req, res) => {
  res.json({ status: "Backend running" });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);

  if (result.rows.length === 0) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  const user = result.rows[0];
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  const token = jwt.sign(
    { id: user.id, role: user.role, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({ token, user });
});

app.post("/api/checkin", async (req, res) => {
  const { user_id, latitude, longitude } = req.body;
  await pool.query(
    "INSERT INTO checkins (user_id, latitude, longitude) VALUES ($1,$2,$3)",
    [user_id, latitude, longitude]
  );

  io.emit("new-checkin", { user_id, latitude, longitude });
  res.json({ success: true });
});

app.get("/api/checkins", async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM checkins ORDER BY timestamp DESC LIMIT 50"
  );
  res.json(result.rows);
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
