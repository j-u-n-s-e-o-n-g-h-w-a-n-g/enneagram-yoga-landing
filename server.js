require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { getPool, initDB, isDBReady, getDbUrl } = require('./db');
const { generateTempPassword } = require('./words');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ===================== SESSION (before routes!) =====================
const sessionConfig = {
  secret: process.env.SESSION_SECRET || 'enneagram-yoga-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000, secure: false }
};

const initPool = getPool();
if (initPool) {
  try {
    const pgSession = require('connect-pg-simple')(session);
    sessionConfig.store = new pgSession({ pool: initPool, tableName: 'session' });
    console.log('✅ Session store: PostgreSQL');
  } catch (err) {
    console.warn('⚠️  PG session store failed, using memory store:', err.message);
  }
} else {
  console.log('⚠️  Session store: Memory (no database URL)');
}
app.use(session(sessionConfig));

// ===================== MIDDLEWARE =====================
function requireDB(req, res, next) {
  if (!isDBReady()) return res.status(503).json({ error: '데이터베이스가 연결되지 않았습니다.' });
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
function requireApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  const validKey = process.env.N8N_API_KEY;
  if (!validKey) return res.status(503).json({ error: 'API key not configured on server' });
  if (apiKey !== validKey) return res.status(401).json({ error: 'Invalid API key' });
  next();
}

// ===================== APPLICATION API (공개) =====================

app.post('/api/applications', requireDB, async (req, res) => {
  const pool = getPool();
  try {
    const { name, email, phone } = req.body;
    if (!name || !email || !phone) return res.status(400).json({ error: '이름, 이메일, 전화번호를 모두 입력해주세요' });
    // 동일 이메일+pending이면 업데이트
    const existing = await pool.query(
      "SELECT id FROM applications WHERE email = $1 AND status = 'pending'",
      [email]
    );
    let application;
    if (existing.rows.length > 0) {
      const result = await pool.query(
        'UPDATE applications SET name = $1, phone = $2, created_at = NOW() WHERE id = $3 RETURNING *',
        [name, phone, existing.rows[0].id]
      );
      application = result.rows[0];
    } else {
      const result = await pool.query(
        'INSERT INTO applications (name, email, phone) VALUES ($1, $2, $3) RETURNING *',
        [name, email, phone]
      );
      application = result.rows[0];
    }
    res.json({ success: true, application });
  } catch (err) {
    console.error('Application error:', err);
    res.status(500).json({ error: '서버 오류가 발생했습니다' });
  }
});

// ===================== WEBHOOK API (n8n 전용) =====================

app.post('/api/webhook/payment-confirm', requireDB, requireApiKey, async (req, res) => {
  const pool = getPool();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { depositor_name, amount, phone, email } = req.body;
    if (!depositor_name && !phone && !email) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: '입금자명, 전화번호, 이메일 중 하나 이상 필요합니다' });
    }

    const paidAmount = parseInt(amount) || 0;
    const expectedAmount = 99000;

    // 1. Find matching application
    let appResult;
    const normalizedPhone = phone ? phone.replace(/[-\s]/g, '') : null;
    if (normalizedPhone) {
      appResult = await client.query(
        "SELECT * FROM applications WHERE REPLACE(REPLACE(phone, '-', ''), ' ', '') = $1 AND status = 'pending' ORDER BY created_at DESC LIMIT 1",
        [normalizedPhone]
      );
    }
    if ((!appResult || appResult.rows.length === 0) && email) {
      appResult = await client.query(
        "SELECT * FROM applications WHERE email = $1 AND status = 'pending' ORDER BY created_at DESC LIMIT 1",
        [email]
      );
    }
    if ((!appResult || appResult.rows.length === 0) && depositor_name) {
      appResult = await client.query(
        "SELECT * FROM applications WHERE name = $1 AND status = 'pending' ORDER BY created_at DESC LIMIT 1",
        [depositor_name]
      );
    }
    if (!appResult || appResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: '매칭되는 신청 내역을 찾을 수 없습니다', depositor_name, phone, email });
    }

    const application = appResult.rows[0];

    // 2. Check amount - underpaid
    if (paidAmount > 0 && paidAmount < expectedAmount) {
      const shortage = expectedAmount - paidAmount;
      // Record partial payment but don't activate pass
      await client.query(
        "INSERT INTO payments (user_id, amount, depositor_name, status, confirmed_at) VALUES ((SELECT id FROM users WHERE email = $1 LIMIT 1), $2, $3, 'underpaid', NOW())",
        [application.email, paidAmount, depositor_name || application.name]
      );
      await client.query('COMMIT');
      return res.json({
        success: false,
        status: 'underpaid',
        paid_amount: paidAmount,
        expected_amount: expectedAmount,
        shortage: shortage,
        user_name: application.name,
        user_phone: application.phone,
        message: paidAmount.toLocaleString() + '원이 입금되어 ' + shortage.toLocaleString() + '원이 부족합니다. 농협 312-0025-5524-11 (황준성) 계좌로 차액을 추가 입금해주세요.'
      });
    }

    // 3. Check for existing user
    let userId;
    let isNewUser = false;
    let tempPassword = null;
    const existingUser = await client.query('SELECT id, email FROM users WHERE email = $1', [application.email]);

    if (existingUser.rows.length > 0) {
      userId = existingUser.rows[0].id;
      isNewUser = false;
    } else {
      // Create new user with temp password
      tempPassword = generateTempPassword();
      const hashed = await bcrypt.hash(tempPassword, 10);
      const newUser = await client.query(
        'INSERT INTO users (name, email, phone, password, password_is_temp) VALUES ($1, $2, $3, $4, TRUE) RETURNING id',
        [application.name, application.email, application.phone, hashed]
      );
      userId = newUser.rows[0].id;
      isNewUser = true;
    }

    // 4. Create class pass (with 3-month expiry)
    const passResult = await client.query(
      "INSERT INTO class_passes (user_id, total_classes, remaining_classes, status, expires_at) VALUES ($1, 12, 12, 'active', NOW() + INTERVAL '3 months') RETURNING *",
      [userId]
    );

    // 5. Create payment record
    await client.query(
      "INSERT INTO payments (user_id, amount, depositor_name, status, confirmed_at, class_pass_id) VALUES ($1, $2, $3, 'confirmed', NOW(), $4)",
      [userId, paidAmount || expectedAmount, depositor_name || application.name, passResult.rows[0].id]
    );

    // 6. Update application
    await client.query(
      "UPDATE applications SET status = 'paid', user_id = $1, paid_at = NOW() WHERE id = $2",
      [userId, application.id]
    );

    await client.query('COMMIT');

    // 7. Check overpaid
    let overpaidInfo = null;
    if (paidAmount > expectedAmount) {
      const excess = paidAmount - expectedAmount;
      overpaidInfo = {
        status: 'overpaid',
        excess: excess,
        message: paidAmount.toLocaleString() + '원이 입금되어 ' + excess.toLocaleString() + '원이 초과 입금되었습니다. 차액은 입금하신 계좌로 반환될 예정입니다.'
      };
    }

    res.json({
      success: true,
      user_id: userId,
      temp_password: tempPassword,
      user_name: application.name,
      user_email: application.email,
      user_phone: application.phone,
      is_new_user: isNewUser,
      pass_id: passResult.rows[0].id,
      expires_at: passResult.rows[0].expires_at,
      paid_amount: paidAmount || expectedAmount,
      overpaid: overpaidInfo
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Payment confirm webhook error:', err);
    res.status(500).json({ error: '서버 오류가 발생했습니다' });
  } finally {
    client.release();
  }
});

// ===================== BACKUP API (n8n 전용) =====================

app.get('/api/webhook/backup', requireDB, requireApiKey, async (req, res) => {
  const pool = getPool();
  try {
    const users = await pool.query('SELECT id, name, email, phone, role, password_is_temp, created_at FROM users ORDER BY id');
    const applications = await pool.query('SELECT * FROM applications ORDER BY id');
    const classPasses = await pool.query('SELECT * FROM class_passes ORDER BY id');
    const payments = await pool.query('SELECT * FROM payments ORDER BY id');
    const attendance = await pool.query('SELECT * FROM attendance ORDER BY id');

    res.json({
      success: true,
      backup_date: new Date().toISOString(),
      data: {
        users: users.rows,
        applications: applications.rows,
        class_passes: classPasses.rows,
        payments: payments.rows,
        attendance: attendance.rows
      },
      counts: {
        users: users.rows.length,
        applications: applications.rows.length,
        class_passes: classPasses.rows.length,
        payments: payments.rows.length,
        attendance: attendance.rows.length
      }
    });
  } catch (err) {
    console.error('Backup API error:', err);
    res.status(500).json({ error: '백업 데이터 조회 중 오류가 발생했습니다' });
  }
});

// ===================== AUTH API =====================

app.post('/api/register', requireDB, async (req, res) => {
  const pool = getPool();
  try {
    const { name, email, phone, password } = req.body;
    if (!name || !email || !phone || !password) return res.status(400).json({ error: '모든 필드를 입력해주세요' });
    if (password.length < 6) return res.status(400).json({ error: '비밀번호는 6자 이상이어야 합니다' });
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) return res.status(400).json({ error: '이미 가입된 이메일입니다' });
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role',
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
  const pool = getPool();
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

// ===================== PASSWORD CHANGE =====================

app.post('/api/change-password', requireDB, requireAuth, async (req, res) => {
  const pool = getPool();
  try {
    const { current_password, new_password } = req.body;
    if (!current_password || !new_password) return res.status(400).json({ error: '현재 비밀번호와 새 비밀번호를 입력해주세요' });
    if (new_password.length < 6) return res.status(400).json({ error: '새 비밀번호는 6자 이상이어야 합니다' });
    const userResult = await pool.query('SELECT password FROM users WHERE id = $1', [req.session.userId]);
    if (userResult.rows.length === 0) return res.status(404).json({ error: '사용자를 찾을 수 없습니다' });
    const valid = await bcrypt.compare(current_password, userResult.rows[0].password);
    if (!valid) return res.status(401).json({ error: '현재 비밀번호가 올바르지 않습니다' });
    const hashed = await bcrypt.hash(new_password, 10);
    await pool.query('UPDATE users SET password = $1, password_is_temp = FALSE WHERE id = $2', [hashed, req.session.userId]);
    res.json({ success: true });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ error: '서버 오류가 발생했습니다' });
  }
});

// ===================== MEMBER API =====================

app.get('/api/mypage', requireDB, requireAuth, async (req, res) => {
  const pool = getPool();
  try {
    const userId = req.session.userId;
    const userResult = await pool.query('SELECT id, name, email, phone, password_is_temp, created_at FROM users WHERE id = $1', [userId]);
    const passResult = await pool.query('SELECT * FROM class_passes WHERE user_id = $1 ORDER BY purchased_at DESC', [userId]);
    const paymentResult = await pool.query('SELECT * FROM payments WHERE user_id = $1 ORDER BY created_at DESC', [userId]);
    const attendanceResult = await pool.query('SELECT * FROM attendance WHERE user_id = $1 ORDER BY attended_at DESC LIMIT 20', [userId]);
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
  const pool = getPool();
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
  const pool = getPool();
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
  const pool = getPool();
  try {
    const status = req.query.status || 'all';
    let query = `SELECT p.*, u.name as user_name, u.email as user_email, u.phone as user_phone FROM payments p JOIN users u ON p.user_id = u.id`;
    const params = [];
    if (status !== 'all') { query += ' WHERE p.status = $1'; params.push(status); }
    query += ' ORDER BY p.created_at DESC';
    const result = await pool.query(query, params);
    res.json({ payments: result.rows });
  } catch (err) {
    console.error('Admin payments error:', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

app.post('/api/admin/payments/:id/confirm', requireDB, requireAdmin, async (req, res) => {
  const pool = getPool();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const paymentId = req.params.id;
    const payment = await client.query('SELECT * FROM payments WHERE id = $1', [paymentId]);
    if (payment.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: '결제를 찾을 수 없습니다' }); }
    if (payment.rows[0].status === 'confirmed') { await client.query('ROLLBACK'); return res.status(400).json({ error: '이미 확인된 결제입니다' }); }
    const passResult = await client.query(
      "INSERT INTO class_passes (user_id, total_classes, remaining_classes, status, expires_at) VALUES ($1, 12, 12, $2, NOW() + INTERVAL '3 months') RETURNING *",
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
  const pool = getPool();
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
  const pool = getPool();
  try {
    const totalMembers = await pool.query("SELECT COUNT(*) FROM users WHERE role = 'member'");
    const pendingPayments = await pool.query("SELECT COUNT(*) FROM payments WHERE status = 'pending'");
    const activePasses = await pool.query("SELECT COUNT(*) FROM class_passes WHERE status = 'active' AND remaining_classes > 0");
    const todayAttendance = await pool.query("SELECT COUNT(*) FROM attendance WHERE attended_at::date = CURRENT_DATE");
    const pendingApps = await pool.query("SELECT COUNT(*) FROM applications WHERE status = 'pending'");
    res.json({
      totalMembers: parseInt(totalMembers.rows[0].count),
      pendingPayments: parseInt(pendingPayments.rows[0].count),
      activePasses: parseInt(activePasses.rows[0].count),
      todayAttendance: parseInt(todayAttendance.rows[0].count),
      pendingApplications: parseInt(pendingApps.rows[0].count)
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

app.get('/api/admin/applications', requireDB, requireAdmin, async (req, res) => {
  const pool = getPool();
  try {
    const status = req.query.status || 'all';
    let query = 'SELECT * FROM applications';
    const params = [];
    if (status !== 'all') { query += ' WHERE status = $1'; params.push(status); }
    query += ' ORDER BY created_at DESC';
    const result = await pool.query(query, params);
    res.json({ applications: result.rows });
  } catch (err) {
    console.error('Admin applications error:', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

// ===================== API: 잔여횟수 있는 회원 조회 (n8n용) =====================

app.get('/api/webhook/active-members', requireDB, requireApiKey, async (req, res) => {
  const pool = getPool();
  try {
    const result = await pool.query(`
      SELECT u.id, u.name, u.phone, u.email,
        COALESCE(SUM(cp.remaining_classes), 0) as remaining_classes
      FROM users u
      JOIN class_passes cp ON cp.user_id = u.id AND cp.status = 'active' AND cp.remaining_classes > 0
      WHERE u.role = 'member'
      GROUP BY u.id, u.name, u.phone, u.email
      HAVING COALESCE(SUM(cp.remaining_classes), 0) > 0
    `);
    res.json({ success: true, members: result.rows });
  } catch (err) {
    console.error('Active members API error:', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

// ===================== API: 첫 출석 회원 조회 (n8n 저널링 안내용) =====================

app.get('/api/webhook/first-attendance-yesterday', requireDB, requireApiKey, async (req, res) => {
  const pool = getPool();
  try {
    const result = await pool.query(`
      SELECT u.id, u.name, u.phone, u.email
      FROM users u
      JOIN attendance a ON a.user_id = u.id
      WHERE u.role = 'member'
      GROUP BY u.id, u.name, u.phone, u.email
      HAVING COUNT(a.id) = 1
        AND MIN(a.attended_at)::date = (CURRENT_DATE - INTERVAL '1 day')::date
    `);
    res.json({ success: true, members: result.rows });
  } catch (err) {
    console.error('First attendance API error:', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

// ===================== PAGE ROUTES =====================

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register', (req, res) => res.redirect('/'));
app.get('/mypage', (req, res) => res.sendFile(path.join(__dirname, 'public', 'mypage.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', db: isDBReady() });
});

// ===================== START =====================

async function start() {
  try {
    await initDB();
  } catch (err) {
    console.error('DB init failed, continuing without DB:', err.message);
  }
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`   Database: ${isDBReady() ? 'Connected' : 'Not connected'}`);
  });
}
start();
