# Tracker Backend

Backend for the Tracker Web App using Node.js, Express, PostgreSQL, and Socket.IO.

## 🚀 Deployment on Render

### Environment Variables
Add these in Render Dashboard → Web Service → Environment Variables:

- `DATABASE_URL` = Your Render PostgreSQL connection string  
- `JWT_SECRET` = my_super_secret_jwt_key_12345  
- `LOCATIONIQ_KEY` = pk.3e417b8c69164fade95ea92d7b869046  
- `NODE_ENV` = production  

### Build & Start Commands
- **Build Command**: `npm install`  
- **Start Command**: `node server.js`  

### Database Setup
1. Open your PostgreSQL service in Render.  
2. Go to **Shell**.  
3. Copy and paste contents of `seed.sql`.  
4. Verify with:
   ```sql
   SELECT * FROM users;
