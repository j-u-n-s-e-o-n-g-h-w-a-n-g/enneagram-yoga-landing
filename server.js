const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { pool, initDB } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Session store
const pgSession = require('connect-pg-simple')(session);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  store: new pgSession({ pool, tableName: 'session' }),
  secret: process.env.SESSION_SECRET || 'enneagram-yoga-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000, secure: false }
}));

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: '로그인이 필요합니다' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: '로그인이 필요합니다' });
  if (req.session.userRole !== 'admin') return res.status(403).json({ error: '관리자 권한이 필요합니다' });
  next();
}

// ===================== AUTH API =====================

app.post('/api/register', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;
    if (!name || !email || !phone || !password) return res.status(400).json({ error: '모든 필드를 입력해주세요' });
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

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
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
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: '로그아웃 실패' });
    res.json({ success: true });
  });
});

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, user: { id: req.session.userId, name: req.session.userName, role: req.session.userRole } });
});

// ===================== MEMBER API =====================

app.get('/api/mypage', requireAuth, async (req, res) => {
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

// Request a new class pass (deposit pending)
app.post('/api/passes/request', requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const depositorName = req.body.depositor_name || req.session.userName;
    // Create a pending payment
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

app.get('/api/admin/members', requireAdmin, async (req, res) => {
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

app.get('/api/admin/payments', requireAdmin, async (req, res) => {
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

// Confirm payment & activate class pass
app.post('/api/admin/payments/:id/confirm', requireAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const paymentId = req.params.id;
    const payment = await client.query('SELECT * FROM payments WHERE id = $1', [paymentId]);
    if (payment.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: '결제를 찾을 수 없습니다' }); }
    if (payment.rows[0].status === 'confirmed') { await client.query('ROLLBACK'); return res.status(400).json({ error: '이미 확인된 결제입니다' }); }
    // Create class pass
    const passResult = await client.query(
      'INSERT INTO class_passes (user_id, total_classes, remaining_classes, status) VALUES ($1, 12, 12, $2) RETURNING *',
      [payment.rows[0].user_id, 'active']
    );
    // Update payment
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

// Use a class (deduct 1)
app.post('/api/admin/members/:id/attend', requireAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const userId = req.params.id;
    // Find active pass with remaining classes
    const passResult = await client.query(
      "SELECT * FROM class_passes WHERE user_id = $1 AND status = 'active' AND remaining_classes > 0 ORDER BY purchased_at ASC LIMIT 1",
      [userId]
    );
    if (passResult.rows.length === 0) { await client.query('ROLLBACK'); return res.status(400).json({ error: '사용 가능한 이용권이 없습니다' }); }
    const pass = passResult.rows[0];
    await client.query('UPDATE class_passes SET remaining_classes = remaining_classes - 1 WHERE id = $1', [pass.id]);
    // If remaining becomes 0, mark as used
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

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
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

// ===================== START =====================

async function start() {
  await initDB();
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}
start();
