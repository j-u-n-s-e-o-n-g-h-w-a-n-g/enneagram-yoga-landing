const { Pool } = require('pg');

let pool = null;
let dbReady = false;

// Try multiple possible env var names for the database URL
const DB_URL = process.env.DATABASE_URL
  || process.env.DATABASE_PUBLIC_URL
  || process.env.DATABASE_PRIVATE_URL
  || process.env.POSTGRES_URL
  || process.env.POSTGRES_PUBLIC_URL
  || process.env.POSTGRES_PRIVATE_URL
  || process.env.PGDATABASE_URL
  || null;

if (DB_URL) {
  console.log('🔗 Found database URL, connecting...');
  pool = new Pool({
    connectionString: DB_URL,
    ssl: { rejectUnauthorized: false }
  });

  pool.on('error', (err) => {
    console.error('Unexpected pool error:', err);
  });
} else {
  console.warn('⚠️  No database URL found. Checked: DATABASE_URL, DATABASE_PUBLIC_URL, DATABASE_PRIVATE_URL, POSTGRES_URL, POSTGRES_PUBLIC_URL, POSTGRES_PRIVATE_URL');
  console.warn('⚠️  Running without database (landing page only).');
}

async function initDB() {
  if (!pool) {
    console.log('⚠️  Skipping DB init — no database URL configured.');
    return;
  }

  let client;
  try {
    client = await pool.connect();
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(20) NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'member',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS class_passes (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        total_classes INTEGER NOT NULL DEFAULT 12,
        remaining_classes INTEGER NOT NULL DEFAULT 12,
        purchased_at TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP,
        status VARCHAR(20) DEFAULT 'active'
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        class_pass_id INTEGER REFERENCES class_passes(id) ON DELETE SET NULL,
        amount INTEGER NOT NULL,
        method VARCHAR(50) DEFAULT 'bank_transfer',
        status VARCHAR(20) DEFAULT 'pending',
        depositor_name VARCHAR(100),
        confirmed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS attendance (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        class_pass_id INTEGER REFERENCES class_passes(id) ON DELETE SET NULL,
        attended_at TIMESTAMP DEFAULT NOW(),
        note VARCHAR(255)
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS session (
        sid VARCHAR NOT NULL COLLATE "default",
        sess JSON NOT NULL,
        expire TIMESTAMP(6) NOT NULL,
        CONSTRAINT session_pkey PRIMARY KEY (sid)
      );
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_session_expire ON session (expire);
    `);
    dbReady = true;
    console.log('✅ Database tables initialized successfully');
  } catch (err) {
    console.error('❌ Database initialization error:', err.message);
    console.log('⚠️  Server will run without database features.');
  } finally {
    if (client) client.release();
  }
}

function isDBReady() {
  return dbReady && pool !== null;
}

function getDbUrl() {
  return DB_URL;
}

module.exports = { pool, initDB, isDBReady, getDbUrl };
