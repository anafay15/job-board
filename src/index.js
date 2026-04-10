require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: 5432,
});

// Initialize database tables
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS jobs (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      company TEXT NOT NULL,
      location TEXT NOT NULL,
      description TEXT NOT NULL,
      posted_by INTEGER REFERENCES users(id),
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS applications (
      id SERIAL PRIMARY KEY,
      job_id INTEGER REFERENCES jobs(id),
      user_id INTEGER REFERENCES users(id),
      cover_letter TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('Database initialized');
}

// Middleware to verify JWT token
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Register
app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const result = await pool.query(
    'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email',
    [email, hashed]
  );
  res.json(result.rows[0]);
});

// Login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET);
  res.json({ token });
});

// Post a job (requires login)
app.post('/jobs', authMiddleware, async (req, res) => {
  const { title, company, location, description } = req.body;
  const result = await pool.query(
    'INSERT INTO jobs (title, company, location, description, posted_by) VALUES ($1, $2, $3, $4, $5) RETURNING *',
    [title, company, location, description, req.user.id]
  );
  res.json(result.rows[0]);
});

// Get all jobs
app.get('/jobs', async (req, res) => {
  const result = await pool.query('SELECT * FROM jobs ORDER BY created_at DESC');
  res.json(result.rows);
});

// Apply for a job (requires login)
app.post('/jobs/:id/apply', authMiddleware, async (req, res) => {
  const { cover_letter } = req.body;
  const result = await pool.query(
    'INSERT INTO applications (job_id, user_id, cover_letter) VALUES ($1, $2, $3) RETURNING *',
    [req.params.id, req.user.id, cover_letter]
  );
  res.json(result.rows[0]);
});

// Get applications for a job (requires login)
app.get('/jobs/:id/applications', authMiddleware, async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM applications WHERE job_id = $1',
    [req.params.id]
  );
  res.json(result.rows);
});

app.listen(3000, async () => {
  await initDB();
  console.log('Job Board API running on port 3000');
});