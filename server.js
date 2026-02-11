const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { pool, initDB, isDBReady, getDbUrl } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session setup — use PG store if DB is available, otherwise memory
function setupSession() {
  const sessionConfig = {
    secret: process.env.SESSION_SECRET || 'enneagram-yoga-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000, secure: false }
  };

  if (pool) {
    try {
      const pgSession = require('connect-pg-simple')(session);
      sessionConfig.store = new pgSession({ pool, tableName: 'session' });
      console.log('✅ Session store: PostgreSQL');
    } catch (err) {
      console.warn('⚠️  PG session store failed, using memory store:', err.message);
    }
  } else {
    console.log('⚠️  Session store: Memory (no database URL)');
  }

  app.use(session(sessionConfig));
}

// DB check middleware
function requireDB(req, res, next) {
  if (!isDBReady()) return res.status(503).json({ error: '데이터베이스가 연결되지 않았습니다. 관리자에게 문의하세요.' });
  next();
}
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: '로그인이 필요합니다' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: '로그인이 필요합니다' });
  if (req.session.userRole !== 'admin') return res.status(403).json({ error: '관리자 권한이 필요합니다' });
  next();
}

// ===================== AUTH API =====================

app.post('/api/register', requireDB, async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;
    if (!name || !email || !phone || !password) return res.status(400).json({ error: '모든 필드를 입력해주세요' });
    if (password.length < 6) return res.status(400).json({ error: '비밀번호는 6자 이상이어야 합니다' });
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) return res.status(400).json({ error: '이미 가입된 이메일입니다' });
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, phone, password) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role',
      [name, email, phone, hashed]
    );
    const user = result.rows[0];
    req.session.userId = user.id;
    req.session.userName = user.name;
    req.session.userRole = user.role;
    res.json({ success: true, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: '서버 오류가 발생했습니다' });
  }
});

app.post('/api/login', requireDB, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: '이메일과 비밀번호를 입력해주세요' });
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: '이메일 또는 비밀번호가 올바르지 않습니다' });
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: '이메일 또는 비밀번호가 올바르지 않습니다' });
    req.session.userId = user.id;
    req.session.userName = user.name;
    req.session.userRole = user.role;
    res.json({ success: true, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: '서버 오류가 발생했습니다' });
  }
});

app.post('/api/logout', (req, res) => {
  if (!req.session) return res.json({ success: true });
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: '로그아웃 실패' });
    res.json({ success: true });
  });
});

app.get('/api/me', (req, res) => {
  if (!req.session || !req.session.userId) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, user: { id: req.session.userId, name: req.session.userName, role: req.session.userRole } });
});

// ===================== MEMBER API =====================

app.get('/api/mypage', requireDB, requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const userResult = await pool.query('SELECT id, name, email, phone, created_at FROM users WHERE id = $1', [userId]);
    const passResult = await pool.query(
      'SELECT * FROM class_passes WHERE user_id = $1 ORDER BY purchased_at DESC', [userId]
    );
    const paymentResult = await pool.query(
      'SELECT * FROM payments WHERE user_id = $1 ORDER BY created_at DESC', [userId]
    );
    const attendanceResult = await pool.query(
      'SELECT * FROM attendance WHERE user_id = $1 ORDER BY attended_at DESC LIMIT 20', [userId]
    );
    res.json({
      user: userResult.rows[0],
      passes: passResult.rows,
      payments: paymentResult.rows,
      attendance: attendanceResult.rows
    });
  } catch (err) {
    console.error('Mypage error:', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

app.post('/api/passes/request', requireDB, requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const depositorName = req.body.depositor_name || req.session.userName;
    const paymentResult = await pool.query(
      'INSERT INTO payments (user_id, amount, depositor_name, status) VALUES ($1, $2, $3, $4) RETURNING *',
      [userId, 99000, depositorName, 'pending']
    );
    res.json({ success: true, payment: paymentResult.rows[0] });
  } catch (err) {
    console.error('Pass request error:', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

// ===================== ADMIN API =====================

app.get('/api/admin/members', requireDB, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.name, u.email, u.phone, u.created_at,
        (SELECT COALESCE(SUM(cp.remaining_classes), 0) FROM class_passes cp WHERE cp.user_id = u.id AND cp.status = 'active') as remaining_classes,
        (SELECT COUNT(*) FROM attendance a WHERE a.user_id = u.id) as total_attended
      FROM users u WHERE u.role = 'member' ORDER BY u.created_at DESC
    `);
    res.json({ members: result.rows });
  } catch (err) {
    console.error('Admin members error:', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

app.get('/api/admin/payments', requireDB, requireAdmin, async (req, res) => {
  try {
    const status = req.query.status || 'all';
    let query = `
      SELECT p.*, u.name as user_name, u.email as user_email, u.phone as user_phone
      FROM payments p JOIN users u ON p.user_id = u.id
    `;
    const params = [];
    if (status !== 'all') {
      query += ' WHERE p.status = $1';
      params.push(status);
    }
    query += ' ORDER BY p.created_at DESC';
    const result = await pool.query(query, params);
    res.json({ payments: result.rows });
  } catch (err) {
    console.error('Admin payments error:', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

app.post('/api/admin/payments/:id/confirm', requireDB, requireAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const paymentId = req.params.id;
    const payment = await client.query('SELECT * FROM payments WHERE id = $1', [paymentId]);
    if (payment.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: '결제를 찾을 수 없습니다' }); }
    if (payment.rows[0].status === 'confirmed') { await client.query('ROLLBACK'); return res.status(400).json({ error: '이미 확인된 결제입니다' }); }
    const passResult = await client.query(
      'INSERT INTO class_passes (user_id, total_classes, remaining_classes, status) VALUES ($1, 12, 12, $2) RETURNING *',
      [payment.rows[0].user_id, 'active']
    );
    await client.query(
      'UPDATE payments SET status = $1, confirmed_at = NOW(), class_pass_id = $2 WHERE id = $3',
      ['confirmed', passResult.rows[0].id, paymentId]
    );
    await client.query('COMMIT');
    res.json({ success: true, pass: passResult.rows[0] });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Confirm payment error:', err);
    res.status(500).json({ error: '서버 오류' });
  } finally {
    client.release();
  }
});

app.post('/api/admin/members/:id/attend', requireDB, requireAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const userId = req.params.id;
    const passResult = await client.query(
      "SELECT * FROM class_passes WHERE user_id = $1 AND status = 'active' AND remaining_classes > 0 ORDER BY purchased_at ASC LIMIT 1",
      [userId]
    );
    if (passResult.rows.length === 0) { await client.query('ROLLBACK'); return res.status(400).json({ error: '사용 가능한 이용권이 없습니다' }); }
    const pass = passResult.rows[0];
    await client.query('UPDATE class_passes SET remaining_classes = remaining_classes - 1 WHERE id = $1', [pass.id]);
    if (pass.remaining_classes - 1 <= 0) {
      await client.query("UPDATE class_passes SET status = 'used' WHERE id = $1", [pass.id]);
    }
    await client.query(
      'INSERT INTO attendance (user_id, class_pass_id, note) VALUES ($1, $2, $3)',
      [userId, pass.id, req.body.note || '']
    );
    await client.query('COMMIT');
    res.json({ success: true, remaining: pass.remaining_classes - 1 });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Attend error:', err);
    res.status(500).json({ error: '서버 오류' });
  } finally {
    client.release();
  }
});

app.get('/api/admin/stats', requireDB, requireAdmin, async (req, res) => {
  try {
    const totalMembers = await pool.query("SELECT COUNT(*) FROM users WHERE role = 'member'");
    const pendingPayments = await pool.query("SELECT COUNT(*) FROM payments WHERE status = 'pending'");
    const activePasses = await pool.query("SELECT COUNT(*) FROM class_passes WHERE status = 'active' AND remaining_classes > 0");
    const todayAttendance = await pool.query("SELECT COUNT(*) FROM attendance WHERE attended_at::date = CURRENT_DATE");
    res.json({
      totalMembers: parseInt(totalMembers.rows[0].count),
      pendingPayments: parseInt(pendingPayments.rows[0].count),
      activePasses: parseInt(activePasses.rows[0].count),
      todayAttendance: parseInt(todayAttendance.rows[0].count)
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

// ===================== PAGE ROUTES =====================

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/mypage', (req, res) => res.sendFile(path.join(__dirname, 'public', 'mypage.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// Health check
app.get('/api/health', (req, res) => {
  const dbUrl = getDbUrl();
  res.json({
    status: 'ok',
    db: isDBReady(),
    hasDbUrl: !!dbUrl,
    dbUrlPrefix: dbUrl ? dbUrl.substring(0, 20) + '...' : 'not set',
    poolExists: pool !== null,
    dbRelatedEnvKeys: Object.keys(process.env).filter(k =>
      k.includes('DATABASE') || k.includes('PG') || k.includes('POSTGRES') || k.includes('DB')
    ),
    timestamp: new Date().toISOString()
  });
});

// ===================== START =====================

async function start() {
  try {
    await initDB();
  } catch (err) {
    console.error('DB init failed, continuing without DB:', err.message);
  }
  setupSession();
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`   Database: ${isDBReady() ? 'Connected' : 'Not connected'}`);
    console.log(`   DB URL: ${getDbUrl() ? 'found' : 'NOT SET'}`);
  });
}
start();
