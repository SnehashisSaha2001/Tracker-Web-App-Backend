Tracker Backend - Ready to Deploy
===============================

Files:
- server.js         (Express + Socket.IO backend)
- seed.sql          (Postgres schema + initial data)
- package.json      (npm dependencies)
- .env.example      (environment variable examples)

Quick start (local):
1. Install dependencies:
   npm install

2. Create a Postgres database and set DATABASE_URL in a .env file:
   DATABASE_URL=postgresql://user:password@host:5432/dbname
   JWT_SECRET=your_jwt_secret
   LOCATIONIQ_API_KEY=your_locationiq_key

3. Run SQL in seed.sql to create tables and seed users.

4. Start server:
   npm start

Deploy to Render:
- Create a new Web Service, connect your repo, set environment variables on Render:
  DATABASE_URL, JWT_SECRET, LOCATIONIQ_API_KEY, FRONTEND_ORIGIN
- Build command: npm install
- Start command: npm start
