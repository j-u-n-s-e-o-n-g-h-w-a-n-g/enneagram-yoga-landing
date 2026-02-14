const bcrypt = require('bcryptjs');

module.exports = function(app, { getPool, isDBReady, CONFIG, middleware, services }) {
  const { requireDB, requireAuth } = middleware;
  const { sendSMS } = services.sms;
  const { generateTempPassword } = require('../words');

  // ===================== AUTH: register =====================

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

  // ===================== AUTH: login =====================

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

  // ===================== AUTH: logout =====================

  app.post('/api/logout', (req, res) => {
    if (!req.session) return res.json({ success: true });
    req.session.destroy(err => {
      if (err) return res.status(500).json({ error: '로그아웃 실패' });
      res.json({ success: true });
    });
  });

  // ===================== AUTH: me =====================

  app.get('/api/me', (req, res) => {
    if (!req.session || !req.session.userId) return res.json({ loggedIn: false });
    res.json({ loggedIn: true, user: { id: req.session.userId, name: req.session.userName, role: req.session.userRole } });
  });

  // ===================== AUTH: change-password =====================

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

  // ===================== AUTH: reset-password =====================

  app.post('/api/reset-password', requireDB, async (req, res) => {
    const pool = getPool();
    try {
      const { email, phone } = req.body;
      if (!email || !phone) return res.status(400).json({ error: '이메일과 전화번호를 모두 입력해주세요' });
      const normalizedPhone = phone.replace(/[-\s]/g, '');
      const userResult = await pool.query(
        "SELECT id, name, email FROM users WHERE email = $1 AND REPLACE(REPLACE(phone, '-', ''), ' ', '') = $2",
        [email, normalizedPhone]
      );
      if (userResult.rows.length === 0) {
        return res.status(404).json({ error: '일치하는 회원 정보를 찾을 수 없습니다' });
      }
      const user = userResult.rows[0];
      const tempPassword = generateTempPassword();
      const hashed = await bcrypt.hash(tempPassword, 10);
      await pool.query('UPDATE users SET password = $1, password_is_temp = TRUE WHERE id = $2', [hashed, user.id]);
      res.json({
        success: true,
        user_name: user.name,
        user_email: user.email,
        user_phone: normalizedPhone,
        temp_password: tempPassword,
        message: '새 임시비밀번호가 생성되었습니다. SMS로 발송해주세요.'
      });
    } catch (err) {
      console.error('Reset password error:', err);
      res.status(500).json({ error: '서버 오류가 발생했습니다' });
    }
  });
};
