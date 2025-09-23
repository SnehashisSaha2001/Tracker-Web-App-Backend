// server.js (Final backend with filters, realtime, and full frontend alignment)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const fetch = require('node-fetch');
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: "*" } });

app.use(express.json());
app.use(cors());
app.use(helmet());

const limiter = rateLimit({ windowMs: 60 * 1000, max: 100 });
app.use(limiter);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

function generateToken(user) {
  return jwt.sign(
    { employeeId: user.employee_id, role: user.role },
    process.env.JWT_SECRET || 'secret',
    { expiresIn: '8h' }
  );
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET || 'secret', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

async function getAddress(lat, lon) {
  const url = `https://us1.locationiq.com/v1/reverse.php?key=${process.env.LOCATIONIQ_KEY}&lat=${lat}&lon=${lon}&format=json`;
  try {
    const resp = await fetch(url, { timeout: 4000 });
    if (!resp.ok) throw new Error('LocationIQ failed');
    const data = await resp.json();
    return { address: data.display_name, city: data.address?.city || data.address?.town || data.address?.village || null };
  } catch (err) {
    console.error('Reverse geocoding failed:', err.message);
    return { address: `Lat:${lat}, Lon:${lon}`, city: null };
  }
}

// Routes
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

app.post('/api/auth/login', async (req, res) => {
  const { employeeId, mobile, password } = req.body;
  if (!employeeId || !mobile || !password) return res.status(400).json({ error: 'Employee ID, mobile, and password required' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE employee_id = $1 AND mobile = $2', [employeeId, mobile]);
    if (rows.length === 0) return res.status(401).json({ error: 'User not found or mobile mismatch' });
    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid password' });
    const token = generateToken(user);
    res.json({ token, user: { employeeId: user.employee_id, role: user.role, name: user.name, mobile: user.mobile } });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/activities', authenticateToken, async (req, res) => {
  const { type, details, latitude, longitude } = req.body;
  const employeeId = req.user.employeeId;
  if (!type || !latitude || !longitude) return res.status(400).json({ error: 'type, latitude, and longitude required' });
  try {
    const { address, city } = await getAddress(latitude, longitude);
    const query = `INSERT INTO activities (employee_id, type, details, latitude, longitude, address, city, timestamp)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,now()) RETURNING *;`;
    const values = [employeeId, type, details || null, latitude, longitude, address, city];
    const { rows } = await pool.query(query, values);
    const activity = { id: rows[0].id, employeeId: rows[0].employee_id, type: rows[0].type, details: rows[0].details,
                       latitude: rows[0].latitude, longitude: rows[0].longitude, location: rows[0].address, city: rows[0].city,
                       timestamp: rows[0].timestamp, mapLink: `https://maps.google.com/?q=${rows[0].latitude},${rows[0].longitude}` };
    io.emit('activity:new', activity);
    res.json({ success: true, activity });
  } catch (err) {
    console.error('Log activity error:', err.message);
    res.status(500).json({ error: 'Failed to log activity' });
  }
});

app.get('/api/activities', authenticateToken, async (req, res) => {
  try {
    let query = 'SELECT * FROM activities';
    const values = [];
    const conditions = [];
    if (req.query.employeeId && req.user.role === 'admin') {
      conditions.push(`employee_id = $${values.length + 1}`); values.push(req.query.employeeId);
    } else if (req.user.role !== 'admin') {
      conditions.push(`employee_id = $${values.length + 1}`); values.push(req.user.employeeId);
    }
    if (req.query.startDate) { conditions.push(`timestamp >= $${values.length + 1}`); values.push(new Date(req.query.startDate)); }
    if (req.query.endDate) { conditions.push(`timestamp <= $${values.length + 1}`); values.push(new Date(req.query.endDate)); }
    if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
    query += ' ORDER BY timestamp DESC LIMIT 500';
    const { rows } = await pool.query(query, values);
    const activities = rows.map(r => ({ id: r.id, employeeId: r.employee_id, type: r.type, details: r.details,
      latitude: r.latitude, longitude: r.longitude, location: r.address, city: r.city, timestamp: r.timestamp,
      mapLink: `https://maps.google.com/?q=${r.latitude},${r.longitude}` }));
    res.json({ activities });
  } catch (err) {
    console.error('Fetch activities error:', err.message);
    res.status(500).json({ error: 'Failed to fetch activities' });
  }
});

app.post('/api/followups', authenticateToken, async (req, res) => {
  const { subject, note, latitude, longitude, datetime } = req.body;
  const employeeId = req.user.employeeId;
  if (!subject || !latitude || !longitude) return res.status(400).json({ error: 'subject, latitude, and longitude required' });
  try {
    const { address, city } = await getAddress(latitude, longitude);
    const query = `INSERT INTO followups (employee_id, subject, note, address, city, datetime)
                   VALUES ($1,$2,$3,$4,$5,$6) RETURNING *;`;
    const values = [employeeId, subject, note || null, address, city, datetime || null];
    const { rows } = await pool.query(query, values);
    const followup = { id: rows[0].id, employeeId: rows[0].employee_id, subject: rows[0].subject, note: rows[0].note,
                       datetime: rows[0].datetime, createdAt: rows[0].created_at };
    io.emit('followup:new', followup);
    res.json({ success: true, followup });
  } catch (err) {
    console.error('Save followup error:', err.message);
    res.status(500).json({ error: 'Failed to save followup' });
  }
});

app.get('/api/followups', authenticateToken, async (req, res) => {
  try {
    let rows;
    if (req.user.role === 'admin') {
      ({ rows } = await pool.query('SELECT * FROM followups ORDER BY datetime DESC NULLS LAST LIMIT 100'));
    } else {
      ({ rows } = await pool.query('SELECT * FROM followups WHERE employee_id = $1 ORDER BY datetime DESC NULLS LAST LIMIT 100', [req.user.employeeId]));
    }
    const followups = rows.map(f => ({ id: f.id, employeeId: f.employee_id, subject: f.subject, note: f.note,
      datetime: f.datetime, createdAt: f.created_at }));
    res.json({ followups });
  } catch (err) {
    console.error('Fetch followups error:', err.message);
    res.status(500).json({ error: 'Failed to fetch followups' });
  }
});

const employeeRouter = express.Router();
employeeRouter.get('/', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, employee_id, name, email, mobile, role, created_at FROM users ORDER BY created_at DESC');
    const employees = rows.map(u => ({ id: u.id, employeeId: u.employee_id, name: u.name, email: u.email,
      mobile: u.mobile, role: u.role, createdAt: u.created_at }));
    res.json({ employees });
  } catch (err) {
    console.error('Fetch employees error:', err.message);
    res.status(500).json({ error: 'Failed to fetch employees' });
  }
});
employeeRouter.post('/', authenticateToken, requireAdmin, async (req, res) => {
  const { employeeId, name, email, mobile, role, password } = req.body;
  if (!employeeId || !name || !mobile || !role || !password) return res.status(400).json({ error: 'Missing required fields' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const query = `INSERT INTO users (employee_id, name, email, mobile, role, password_hash)
                   VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, employee_id, name, email, mobile, role, created_at;`;
    const values = [employeeId, name, email || null, mobile, role, hash];
    const { rows } = await pool.query(query, values);
    res.json({ success: true, employee: { id: rows[0].id, employeeId: rows[0].employee_id, name: rows[0].name,
      email: rows[0].email, mobile: rows[0].mobile, role: rows[0].role, createdAt: rows[0].created_at } });
  } catch (err) {
    console.error('Add employee error:', err.message);
    res.status(500).json({ error: 'Failed to add employee' });
  }
});
employeeRouter.put('/:id', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params; const { name, email, mobile, role, password } = req.body;
  try {
    let query, values;
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      query = `UPDATE users SET name=$1, email=$2, mobile=$3, role=$4, password_hash=$5 WHERE id=$6 RETURNING id, employee_id, name, email, mobile, role, created_at;`;
      values = [name, email || null, mobile, role, hash, id];
    } else {
      query = `UPDATE users SET name=$1, email=$2, mobile=$3, role=$4 WHERE id=$5 RETURNING id, employee_id, name, email, mobile, role, created_at;`;
      values = [name, email || null, mobile, role, id];
    }
    const { rows } = await pool.query(query, values);
    res.json({ success: true, employee: { id: rows[0].id, employeeId: rows[0].employee_id, name: rows[0].name,
      email: rows[0].email, mobile: rows[0].mobile, role: rows[0].role, createdAt: rows[0].created_at } });
  } catch (err) {
    console.error('Update employee error:', err.message);
    res.status(500).json({ error: 'Failed to update employee' });
  }
});
employeeRouter.delete('/:id', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  try { await pool.query('DELETE FROM users WHERE id=$1', [id]); res.json({ success: true }); }
  catch (err) { console.error('Delete employee error:', err.message); res.status(500).json({ error: 'Failed to delete employee' }); }
});
app.use('/api/employees', employeeRouter);
app.use('/api/users', employeeRouter);

io.on('connection', (socket) => { console.log('Client connected:', socket.id); socket.on('disconnect', () => console.log('Client disconnected:', socket.id)); });

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
