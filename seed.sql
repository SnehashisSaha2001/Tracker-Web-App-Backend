CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    employee_id VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100),
    mobile VARCHAR(20) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin','employee')),
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS activities (
    id SERIAL PRIMARY KEY,
    employee_id VARCHAR(50) REFERENCES users(employee_id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    details TEXT,
    latitude DOUBLE PRECISION NOT NULL,
    longitude DOUBLE PRECISION NOT NULL,
    address TEXT,
    city VARCHAR(100),
    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS followups (
    id SERIAL PRIMARY KEY,
    employee_id VARCHAR(50) REFERENCES users(employee_id) ON DELETE CASCADE,
    subject VARCHAR(200) NOT NULL,
    note TEXT,
    address TEXT,
    city VARCHAR(100),
    datetime TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

-- bcrypt hash for "admin123"
INSERT INTO users (employee_id, name, email, mobile, role, password_hash)
VALUES ('ADM001', 'Super Admin', 'admin@example.com', '9876543210', 'admin',
        '$2b$10$Pv8db9bdU0m36LKkwY6uZeo4xXWc8kEMqDSp/9jtz9DmvzxVWX4nO')
ON CONFLICT (employee_id) DO NOTHING;

-- bcrypt hash for "emp123"
INSERT INTO users (employee_id, name, email, mobile, role, password_hash)
VALUES ('EMP001', 'John Employee', 'employee@example.com', '9123456780', 'employee',
        '$2b$10$lh1t..8rTPjF.7Yz0UV.2uWRKpbo6OblTXKNYdQQIB8r7V0FPM9Gu')
ON CONFLICT (employee_id) DO NOTHING;
