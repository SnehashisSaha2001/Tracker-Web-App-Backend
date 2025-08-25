// backend.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const { Sequelize } = require('sequelize');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// -------------------------
// Check required environment variables
const requiredEnv = ['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST', 'DB_PORT', 'JWT_SECRET'];
requiredEnv.forEach((key) => {
  if (!process.env[key]) {
    console.warn(`⚠️  Warning: Environment variable ${key} is not set!`);
  }
});

// Database Configuration
const sequelize = new Sequelize(
  process.env.DB_NAME || 'trackerdb',
  process.env.DB_USER || 'postgres',
  process.env.DB_PASSWORD || 'password',
  {
    host: process.env.DB_HOST || 'localhost',
    dialect: 'postgres',
    port: process.env.DB_PORT || 5432,
    logging: false,
  }
);

// Models Definition
const Employee = sequelize.define('Employee', {
  name: { type: Sequelize.STRING, allowNull: false },
  employeeId: { type: Sequelize.STRING, unique: true, allowNull: false },
  mobileNo: { type: Sequelize.STRING, allowNull: false },
  email: { type: Sequelize.STRING, allowNull: false },
  password: { type: Sequelize.STRING, allowNull: false },
  role: { type: Sequelize.ENUM('employee', 'admin'), defaultValue: 'employee' },
}, { timestamps: true });

const Activity = sequelize.define('Activity', {
  employeeId: { type: Sequelize.INTEGER, references: { model: 'Employee', key: 'id' } },
  type: { type: Sequelize.ENUM('check-in', 'check-out', 'visit'), allowNull: false },
  details: { type: Sequelize.TEXT },
  location: { type: Sequelize.STRING },
  timestamp: { type: Sequelize.DATE, defaultValue: Sequelize.NOW },
}, { timestamps: true });

const State = sequelize.define('State', { name: { type: Sequelize.STRING, allowNull: false } }, { timestamps: true });
const City = sequelize.define('City', {
  stateId: { type: Sequelize.INTEGER, references: { model: 'State', key: 'id' } },
  stateName: { type: Sequelize.STRING },
  name: { type: Sequelize.STRING, allowNull: false },
}, { timestamps: true });

const FollowUp = sequelize.define('FollowUp', {
  employeeId: { type: Sequelize.INTEGER, references: { model: 'Employee', key: 'id' } },
  subject: { type: Sequelize.STRING, allowNull: false },
  datetime: { type: Sequelize.DATE, allowNull: false },
  note: { type: Sequelize.TEXT },
}, { timestamps: true });

// Authentication Configuration
const authConfig = { secret: process.env.JWT_SECRET || 'defaultSecret', expiresIn: '1h' };

// Controllers
const authController = {
  register: async (req, res) => {
    try {
      const { name, employeeId, mobileNo, email, password, role } = req.body;
      const hashedPassword = await bcrypt.hash(password, 10);
      const employee = await Employee.create({ name, employeeId, mobileNo, email, password: hashedPassword, role: role || 'employee' });
      const token = jwt.sign({ id: employee.id }, authConfig.secret, { expiresIn: authConfig.expiresIn });
      res.status(201).json({ status: 'success', token, data: { employee } });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Server error' });
    }
  },
  login: async (req, res) => {
    try {
      const { employeeId, password } = req.body;
      const employee = await Employee.findOne({ where: { employeeId } });
      if (!employee) return res.status(401).json({ message: 'Invalid credentials' });
      const isMatch = await bcrypt.compare(password, employee.password);
      if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });
      const token = jwt.sign({ id: employee.id }, authConfig.secret, { expiresIn: authConfig.expiresIn });
      res.status(200).json({ status: 'success', token, data: { employee } });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Server error' });
    }
  },
};

const employeeController = {
  getAllEmployees: async (req, res) => {
    try {
      const employees = await Employee.findAll();
      res.json(employees);
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Server error' });
    }
  },
  createEmployee: async (req, res) => {
    try {
      const { name, employeeId, mobileNo, email, password, role } = req.body;
      const hashedPassword = await bcrypt.hash(password, 10);
      const employee = await Employee.create({ name, employeeId, mobileNo, email, password: hashedPassword, role });
      res.status(201).json(employee);
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Server error' });
    }
  },
};

// Routes
const authRoutes = express.Router();
authRoutes.post('/register', authController.register);
authRoutes.post('/login', authController.login);

const employeeRoutes = express.Router();
employeeRoutes.get('/', employeeController.getAllEmployees);
employeeRoutes.post('/', employeeController.createEmployee);

// Main Application
const app = express();

// Middleware
app.use(cors()); // Allow all origins; restrict later if needed
app.use(helmet());
app.use(morgan('dev'));
app.use(express.json());

// Route Registration
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/employees', employeeRoutes);

// Database Connection and Server Start
(async () => {
  try {
    await sequelize.authenticate();
    console.log('✅ Database connected successfully');
    await sequelize.sync();
    console.log('✅ Tables synchronized');

    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
  } catch (error) {
    console.error('❌ Unable to connect to database:', error);
  }
})();
