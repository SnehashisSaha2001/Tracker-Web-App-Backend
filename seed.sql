-- seed.sql - Tracker DB schema + full initial user data
-- Run once in your Postgres DB (Render DB console or psql)

DROP TABLE IF EXISTS activities, followups, cities, states, users;

-- users
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  employee_id VARCHAR(64) UNIQUE NOT NULL,
  name VARCHAR(255),
  mobile VARCHAR(32),
  email VARCHAR(255),
  role VARCHAR(32),
  password VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW()
);

-- activities
CREATE TABLE activities (
  id SERIAL PRIMARY KEY,
  employee_id VARCHAR(64) NOT NULL,
  type VARCHAR(64),
  details TEXT,
  latitude DOUBLE PRECISION,
  longitude DOUBLE PRECISION,
  location TEXT,
  timestamp TIMESTAMP DEFAULT NOW()
);

-- followups
CREATE TABLE followups (
  id SERIAL PRIMARY KEY,
  employee_id VARCHAR(64) NOT NULL,
  subject VARCHAR(255),
  datetime TIMESTAMP,
  note TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

-- states
CREATE TABLE states (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW()
);

-- cities
CREATE TABLE cities (
  id SERIAL PRIMARY KEY,
  state_id INTEGER REFERENCES states(id),
  name VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW()
);

-- ================================
-- Admin accounts (common password scube@1234)
-- ================================
INSERT INTO users (employee_id, name, mobile, email, role, password) VALUES
('ADM-S.S Singh','Shanti Saran Singh','9831038262','s.s.singh@example.com','admin','scube@1234'),
('ADM-Sandeep','Sandeep Sarkar','9831036858','sandeep.sarkar@example.com','admin','scube@1234'),
('ADM-Snehashis','Snehashis Saha','9330199588','snehashis@example.com','admin','scube@1234'),
('ADM-Komal','Komal Gupta','7003045682','komal@example.com','admin','scube@1234'),
('ADM-Shoaib','MD Shoaib Raza','9831259095','shoaib@example.com','admin','scube@1234');

-- ================================
-- Employees (password scube@4321)
-- (Complete set parsed from your uploaded frontend)
-- ================================
INSERT INTO users (employee_id, name, mobile, email, role, password) VALUES
('SCS-03318','Snehasish Paul','8017892062','N/A','employee','scube@4321'),
('SCS-01102','Zuber Alam','9891377424','N/A','employee','scube@4321'),
('SCS-08017','Bharath Kumar TM','9844722312','N/A','employee','scube@4321'),
('SCS-08016','Shiva Kumarar','9611452782','N/A','employee','scube@4321'),
('SCS-03317','Tapas Kumar Dinda','9804443387','N/A','employee','scube@4321'),
('SCS-03313','Gopal Chandra Biswas','9432095612','N/A','employee','scube@4321'),
('SCS-03303','Saugat Majumdar','9831259094','N/A','employee','scube@4321'),
('SCS-03306','Chitrarath Senapati','9831282190','N/A','employee','scube@4321'),
('SCS-03316','Sukhendu Shekhar Mondal','7278942388','N/A','employee','scube@4321'),
('SCS-03308','Tarun Kumar Paramanik','9831650969','N/A','employee','scube@4321'),
('SCS-03309','Kartik Ghanta','7074099074','N/A','employee','scube@4321'),
('SCS-03314','Provat Naskar','7044486602','N/A','employee','scube@4321'),
('SCS-01103','Ravi','9548362042','N/A','employee','scube@4321'),
('SCS-067403','Abhilash Sarangi','8763523636','N/A','employee','scube@4321'),
('SCS-067404','Shubhadarshani Nath','7978143152','N/A','employee','scube@4321');
