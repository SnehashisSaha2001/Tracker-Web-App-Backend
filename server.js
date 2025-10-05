// server.js - Final Tracker Backend (matched to frontend)
// Required env vars: DATABASE_URL, JWT_SECRET, LOCATIONIQ_API_KEY, FRONTEND_ORIGIN (optional), PORT (optional)

require('dotenv').config();
const express = require('express');
const http = require('http');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);

// ---- Socket.IO for realtime updates ----
const { Server } = require('socket.io');
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_ORIGIN || '*',
    methods: ['GET', 'POST']
  }
});
io.on('connection', socket => {
  console.log('🔌 Socket connected:', socket.id);
  socket.on('disconnect', () => console.log('🔌 Socket disconnected:', socket.id));
});
app.set('io', io);

// ---- Basic middleware ----
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const corsOptions = {
  origin: process.env.FRONTEND_ORIGIN || '*'
};
app.use(cors(corsOptions));
app.set('trust proxy', 1);

// rate limiter
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 400 }));

// ---- Postgres pool (Render-friendly SSL) ----
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ---- Helpers ----
function signToken(user) {
  return jwt.sign({
    id: user.id,
    employeeId: user.employee_id,
    name: user.name,
    role: user.role
  }, process.env.JWT_SECRET, { expiresIn: '24h' });
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Authorization header missing' });
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid auth format' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

async function getAddressFromCoords(lat, lon) {
  const key = process.env.LOCATIONIQ_API_KEY;
  if (!key || lat == null || lon == null) return `(${lat}, ${lon})`;
  // use us1 endpoint — works globally
  const url = `https://us1.locationiq.com/v1/reverse.php?key=${key}&lat=${lat}&lon=${lon}&format=json`;
  try {
    const r = await fetch(url);
    if (!r.ok) {
      console.error('LocationIQ status:', r.status);
      return `(${lat}, ${lon})`;
    }
    const data = await r.json();
    return data.display_name || `(${lat}, ${lon})`;
  } catch (err) {
    console.error('LocationIQ error:', err.message || err);
    return `(${lat}, ${lon})`;
  }
}

// Utility to map DB row -> frontend activity shape
function mapActivityRowToFrontend(row) {
  return {
    id: row.id,
    employeeId: row.employee_id,
    timestamp: row.timestamp,
    type: row.type,
    location: row.location,
    latitude: row.latitude === null ? null : parseFloat(row.latitude),
    longitude: row.longitude === null ? null : parseFloat(row.longitude),
    mapLink: (row.latitude && row.longitude) ? `https://www.google.com/maps?q=${row.latitude},${row.longitude}` : null,
    details: row.details
  };
}

// ---- Routes ----
// Root
app.get('/', (req, res) => res.json({ status: 'ok', message: 'Tracker backend running' }));

// AUTH: /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { employeeId, mobile, password } = req.body;
    if (!employeeId || !password) return res.status(400).json({ error: 'employeeId and password required' });

    const q = 'SELECT * FROM users WHERE employee_id = $1 LIMIT 1';
    const { rows } = await pool.query(q, [employeeId]);
    if (!rows || rows.length === 0) {
      if (mobile) {
        const { rows: r2 } = await pool.query('SELECT * FROM users WHERE mobile = $1 LIMIT 1', [mobile]);
        if (r2 && r2.length) rows.push(r2[0]);
      }
    }

    if (!rows || rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = rows[0];

    if (user.mobile && mobile && user.mobile !== mobile) {
      return res.status(401).json({ error: 'Mobile mismatch' });
    }

    if (user.password !== password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = signToken(user);
    return res.json({
      token,
      user: {
        id: user.id,
        employeeId: user.employee_id,
        name: user.name,
        role: user.role,
        mobile: user.mobile,
        email: user.email
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Login failed' });
  }
});

// USERS
app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, employee_id, name, mobile, email, role FROM users ORDER BY name');
    const users = rows.map(r => ({
      id: r.id,
      employee_id: r.employee_id,
      name: r.name,
      mobile: r.mobile,
      email: r.email,
      role: r.role
    }));
    res.json({ users });
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.post('/api/users', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
    const { role, name, email, mobile, employeeId, password } = req.body;
    if (!employeeId || !name || !role) return res.status(400).json({ error: 'Missing required fields' });

    const q = `INSERT INTO users (employee_id, name, mobile, email, role, password)
               VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, employee_id, name, mobile, email, role`;
    const vals = [employeeId, name, mobile || 'N/A', email || 'N/A', role, password || 'scube@4321'];
    const { rows } = await pool.query(q, vals);
    return res.json({ user: rows[0] });
  } catch (err) {
    console.error('Create user error:', err);
    return res.status(500).json({ error: 'Failed to create user' });
  }
});

// ACTIVITIES GET
app.get('/api/activities', authMiddleware, async (req, res) => {
  try {
    const { employeeId, date } = req.query;
    let q = 'SELECT * FROM activities';
    const vals = [];
    if (employeeId && date) {
      q += ' WHERE employee_id=$1 AND DATE(timestamp) = $2';
      vals.push(employeeId, date);
    } else if (employeeId) {
      q += ' WHERE employee_id=$1';
      vals.push(employeeId);
    } else if (date) {
      q += ' WHERE DATE(timestamp) = $1';
      vals.push(date);
    }
    q += ' ORDER BY timestamp DESC';
    const { rows } = await pool.query(q, vals);
    const activities = rows.map(mapActivityRowToFrontend);
    res.json({ activities });
  } catch (err) {
    console.error('Get activities error:', err);
    res.status(500).json({ error: 'Failed to fetch activities' });
  }
});

// ACTIVITIES POST
app.post('/api/activities', authMiddleware, async (req, res) => {
  try {
    const { type, details, latitude, longitude, address } = req.body;
    const lat = (latitude != null) ? Number(latitude) : null;
    const lon = (longitude != null) ? Number(longitude) : null;
    let location = address || null;
    if (!location && lat != null && lon != null) {
      location = await getAddressFromCoords(lat, lon);
    } else if (!location) {
      location = 'Unknown';
    }

    const q = `INSERT INTO activities (employee_id, type, details, latitude, longitude, location, timestamp)
               VALUES ($1,$2,$3,$4,$5,$6,NOW()) RETURNING *`;
    const vals = [req.user.employeeId || req.user.employee_id, type || 'Check-In', details || '', lat, lon, location];
    const { rows } = await pool.query(q, vals);
    const activity = mapActivityRowToFrontend(rows[0]);

    const ioInstance = app.get('io') || io;
    ioInstance.emit('new-activity', activity);

    return res.json({ success: true, activity });
  } catch (err) {
    console.error('Create activity error:', err);
    return res.status(500).json({ error: 'Failed to save activity' });
  }
});

// ACTIVITIES SYNC (batch)
app.post('/api/activities/sync', authMiddleware, async (req, res) => {
  try {
    const payload = req.body;
    if (!payload || !Array.isArray(payload.activities)) return res.status(400).json({ error: 'Invalid payload' });
    const saved = [];
    for (const rec of payload.activities) {
      const type = rec.type || 'Check-In';
      const details = rec.details || '';
      const lat = (rec.latitude != null) ? Number(rec.latitude) : null;
      const lon = (rec.longitude != null) ? Number(rec.longitude) : null;
      let location = rec.address || null;
      if (!location && lat != null && lon != null) {
        location = await getAddressFromCoords(lat, lon);
      } else if (!location) {
        location = 'Unknown';
      }

      const q = `INSERT INTO activities (employee_id, type, details, latitude, longitude, location, timestamp)
                 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`;
      const ts = rec.timestamp ? new Date(rec.timestamp).toISOString() : new Date().toISOString();
      const vals = [req.user.employeeId || req.user.employee_id, type, details, lat, lon, location, ts];
      const { rows } = await pool.query(q, vals);
      const activity = mapActivityRowToFrontend(rows[0]);
      saved.push(activity);

      const ioInstance = app.get('io') || io;
      ioInstance.emit('new-activity', activity);
    }
    return res.json({ success: true, activities: saved });
  } catch (err) {
    console.error('Batch sync error:', err);
    return res.status(500).json({ error: 'Failed to sync activities' });
  }
});

// FOLLOWUPS
app.get('/api/followups', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM followups ORDER BY datetime DESC');
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
    console.error('Get followups error:', err);
    res.status(500).json({ error: 'Failed to fetch followups' });
  }
});

app.post('/api/followups', authMiddleware, async (req, res) => {
  try {
    const { subject, datetime, note } = req.body;
    if (!subject || !datetime) return res.status(400).json({ error: 'subject and datetime required' });
    const q = `INSERT INTO followups (employee_id, subject, datetime, note, created_at)
               VALUES ($1,$2,$3,$4,NOW()) RETURNING *`;
    const vals = [req.user.employeeId || req.user.employee_id, subject, datetime, note || ''];
    const { rows } = await pool.query(q, vals);
    return res.json({ success: true, followup: rows[0] });
  } catch (err) {
    console.error('Create followup error:', err);
    res.status(500).json({ error: 'Failed to save followup' });
  }
});

// STATES
app.get('/api/states', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM states ORDER BY name');
    res.json({ states: rows });
  } catch (err) {
    console.error('Get states error:', err);
    res.status(500).json({ error: 'Failed to fetch states' });
  }
});

app.post('/api/states', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'State name required' });
    const { rows } = await pool.query('INSERT INTO states (name) VALUES ($1) RETURNING *', [name]);
    return res.json({ state: rows[0] });
  } catch (err) {
    console.error('Create state error:', err);
    res.status(500).json({ error: 'Failed to create state' });
  }
});

// CITIES
app.get('/api/cities', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT cities.id, cities.name, cities.state_id, states.name AS state_name, cities.created_at
      FROM cities LEFT JOIN states ON cities.state_id = states.id
      ORDER BY states.name, cities.name
    `);
    const cities = rows.map(r => ({
      id: r.id,
      stateId: r.state_id,
      stateName: r.state_name,
      name: r.name,
      createdAt: r.created_at
    }));
    res.json({ cities });
  } catch (err) {
    console.error('Get cities error:', err);
    res.status(500).json({ error: 'Failed to fetch cities' });
  }
});

app.post('/api/cities', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
    const { stateId, name } = req.body;
    if (!stateId || !name) return res.status(400).json({ error: 'stateId and name required' });
    const { rows } = await pool.query('INSERT INTO cities (state_id, name) VALUES ($1,$2) RETURNING *', [stateId, name]);
    return res.json({ city: rows[0] });
  } catch (err) {
    console.error('Create city error:', err);
    res.status(500).json({ error: 'Failed to create city' });
  }
});

// ---- Start server ----
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`✅ Tracker backend listening on port ${PORT}`));
