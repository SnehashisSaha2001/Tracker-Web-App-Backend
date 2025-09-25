// server.js (Final backend ready for Render)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const fetch = require('node-fetch'); // Works with node-fetch@2.6.7
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: "*" } });

app.use(express.json());
app.use(cors());
app.use(helmet());

// Rate limiting
const limiter = rateLimit({ windowMs: 60 * 1000, max: 100 });
app.use(limiter);

// Database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Helpers
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

// Auth
app.post('/api/auth/login', async (req, res) => {
  const { employeeId, mobile, password } = req.body;
  if (!employeeId || !mobile || !password) return res.status(400).json({ error: 'Employee ID, mobile, and password required' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE employee_id=$1 AND mobile=$2', [employeeId, mobile]);
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

// Activities
app.post('/api/activities', authenticateToken, async (req, res) => {
  const { type, details, latitude, longitude } = req.body;
  const employeeId = req.user.employeeId;
  if (!type || !latitude || !longitude) return res.status(400).json({ error: 'type, latitude, and longitude required' });
  try {
    const { address, city } = await getAddress(latitude, longitude);
    const { rows } = await pool.query(
      `INSERT INTO activities (employee_id, type, details, latitude, longitude, address, city, timestamp)
       VALUES ($1,$2,$3,$4,$5,$6,$7,now()) RETURNING *;`,
      [employeeId, type, details || null, latitude, longitude, address, city]
    );
    const a = rows[0];
    const activity = { id: a.id, employeeId: a.employee_id, type: a.type, details: a.details, latitude: a.latitude, longitude: a.longitude,
      location: a.address, city: a.city, timestamp: a.timestamp, mapLink: `https://maps.google.com/?q=${a.latitude},${a.longitude}` };
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
    const values = [], conditions = [];
    if (req.query.employeeId && req.user.role === 'admin') { conditions.push(`employee_id=$${values.length+1}`); values.push(req.query.employeeId); }
    else if (req.user.role !== 'admin') { conditions.push(`employee_id=$${values.length+1}`); values.push(req.user.employeeId); }
    if (req.query.startDate) { conditions.push(`timestamp >= $${values.length+1}`); values.push(new Date(req.query.startDate)); }
    if (req.query.endDate) { conditions.push(`timestamp <= $${values.length+1}`); values.push(new Date(req.query.endDate)); }
    if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
    query += ' ORDER BY timestamp DESC LIMIT 500';
    const { rows } = await pool.query(query, values);
    res.json({ activities: rows.map(r => ({ id: r.id, employeeId: r.employee_id, type: r.type, details: r.details,
      latitude: r.latitude, longitude: r.longitude, location: r.address, city: r.city, timestamp: r.timestamp,
      mapLink: `https://maps.google.com/?q=${r.latitude},${r.longitude}` })) });
  } catch (err) {
    console.error('Fetch activities error:', err.message);
    res.status(500).json({ error: 'Failed to fetch activities' });
  }
});

// Followups
app.post('/api/followups', authenticateToken, async (req, res) => {
  const { subject, note, latitude, longitude, datetime } = req.body;
  const employeeId = req.user.employeeId;
  if (!subject || !latitude || !longitude) return res.status(400).json({ error: 'subject, latitude, and longitude required' });
  try {
    const { address, city } = await getAddress(latitude, longitude);
    const { rows } = await pool.query(
      `INSERT INTO followups (employee_id, subject, note, address, city, datetime)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *;`,
      [employeeId, subject, note || null, address, city, datetime || null]
    );
    const f = rows[0];
    const followup = { id: f.id, employeeId: f.employee_id, subject: f.subject, note: f.note, datetime: f.datetime, createdAt: f.created_at };
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
    if (req.user.role === 'admin')
      ({ rows } = await pool.query('SELECT * FROM followups ORDER BY datetime DESC NULLS LAST LIMIT 100'));
    else
      ({ rows } = await pool.query('SELECT * FROM followups WHERE employee_id=$1 ORDER BY datetime DESC NULLS LAST LIMIT 100', [req.user.employeeId]));
    res.json({ followups: rows.map(f => ({ id: f.id, employeeId: f.employee_id, subject: f.subject, note: f.note, datetime: f.datetime, createdAt: f.created_at })) });
  } catch (err) {
    console.error('Fetch followups error:', err.message);
    res.status(500).json({ error: 'Failed to fetch followups' });
  }
});

// Employees
const employeeRouter = express.Router();
employeeRouter.get('/', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, employee_id, name, email, mobile, role, created_at FROM users ORDER BY created_at DESC');
    res.json({ employees: rows.map(u => ({ id: u.id, employeeId: u.employee_id, name: u.name, email: u.email, mobile: u.mobile, role: u.role, createdAt: u.created_at })) });
  } catch (err) { res.status(500).json({ error: 'Failed to fetch employees' }); }
});
employeeRouter.post('/', authenticateToken, requireAdmin, async (req, res) => {
  const { employeeId, name, email, mobile, role, password } = req.body;
  if (!employeeId || !name || !mobile || !role || !password) return res.status(400).json({ error: 'Missing required fields' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO users (employee_id, name, email, mobile, role, password_hash)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, employee_id, name, email, mobile, role, created_at;`,
      [employeeId, name, email || null, mobile, role, hash]
    );
    const u = rows[0];
    res.json({ success: true, employee: { id: u.id, employeeId: u.employee_id, name: u.name, email: u.email, mobile: u.mobile, role: u.role, createdAt: u.created_at } });
  } catch (err) { res.status(500).json({ error: 'Failed to add employee' }); }
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
    const u = rows[0];
    res.json({ success: true, employee: { id: u.id, employeeId: u.employee_id, name: u.name, email: u.email, mobile: u.mobile, role: u.role, createdAt: u.created_at } });
  } catch (err) { res.status(500).json({ error: 'Failed to update employee' }); }
});
employeeRouter.delete('/:id', authenticateToken, requireAdmin, async (req, res) => {
  try { await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: 'Failed to delete employee' }); }
});
app.use('/api/employees', employeeRouter);
app.use('/api/users', employeeRouter);

// Socket.IO
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  socket.on('disconnect', () => console.log('Client disconnected:', socket.id));
});

// Start server
const PORT = process.env.PORT || 4000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
