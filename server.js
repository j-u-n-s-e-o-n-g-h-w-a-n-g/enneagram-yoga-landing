require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { getPool, initDB, isDBReady, getDbUrl } = require('./db');
const { generateTempPassword } = require('./words');

const app = express();
const PORT = process.env.PORT || 3000;

// ===================== CONFIG (환경변수 통합) =====================
const CONFIG = {
  PASS_PRICE: parseInt(process.env.PASS_PRICE) || 99000,
  PASS_CLASSES: parseInt(process.env.PASS_CLASSES) || 12,
  PASS_MONTHS: parseInt(process.env.PASS_MONTHS) || 3,
  BANK_NAME: process.env.BANK_NAME || '농협',
  BANK_ACCOUNT: process.env.BANK_ACCOUNT || '312-0025-5524-11',
  BANK_HOLDER: process.env.BANK_HOLDER || '황준성',
  HOST_EMAIL: process.env.HOST_EMAIL || 'junseong@junseonghwang.com',
};

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ===================== SESSION (before routes!) =====================
const sessionConfig = {
  secret: process.env.SESSION_SECRET || 'enneagram-yoga-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000,
    secure: process.env.NODE_ENV === 'production'
  }
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

// ===================== CONFIG API (공개) =====================

app.get('/api/config', (req, res) => {
  res.json({
    pass_price: CONFIG.PASS_PRICE,
    pass_classes: CONFIG.PASS_CLASSES,
    pass_months: CONFIG.PASS_MONTHS,
    bank_name: CONFIG.BANK_NAME,
    bank_account: CONFIG.BANK_ACCOUNT,
    bank_holder: CONFIG.BANK_HOLDER
  });
});

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
    const { depositor_name, amount, phone, email, transaction_id } = req.body;
    if (!depositor_name && !phone && !email) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: '입금자명, 전화번호, 이메일 중 하나 이상 필요합니다' });
    }

    // ===== 멱등성 체크: transaction_id가 있으면 중복 확인 =====
    if (transaction_id) {
      const dupCheck = await client.query(
        "SELECT id FROM payments WHERE transaction_id = $1",
        [transaction_id]
      );
      if (dupCheck.rows.length > 0) {
        await client.query('ROLLBACK');
        return res.json({
          success: true,
          status: 'duplicate',
          message: '이미 처리된 입금건입니다',
          payment_id: dupCheck.rows[0].id
        });
      }
    }

    let paidAmount = parseInt(amount) || 0;
    const expectedAmount = CONFIG.PASS_PRICE;

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

    // 2. Check amount - underpaid (24시간 이내 부분입금만 합산)
    if (paidAmount > 0 && paidAmount < expectedAmount) {
      const existingUserForCheck = await client.query('SELECT id FROM users WHERE email = $1 LIMIT 1', [application.email]);
      const existingUserId = existingUserForCheck.rows.length > 0 ? existingUserForCheck.rows[0].id : null;

      let previousTotal = 0;
      if (existingUserId) {
        const prevPayments = await client.query(
          "SELECT COALESCE(SUM(amount), 0) as total_prev FROM payments WHERE user_id = $1 AND status = 'underpaid' AND confirmed_at >= NOW() - INTERVAL '24 hours'",
          [existingUserId]
        );
        previousTotal = parseInt(prevPayments.rows[0].total_prev) || 0;
      } else {
        const prevPayments = await client.query(
          "SELECT COALESCE(SUM(amount), 0) as total_prev FROM payments WHERE user_id IS NULL AND depositor_name = $1 AND status = 'underpaid' AND confirmed_at >= NOW() - INTERVAL '24 hours'",
          [depositor_name || application.name]
        );
        previousTotal = parseInt(prevPayments.rows[0].total_prev) || 0;
      }
      const totalPaid = previousTotal + paidAmount;

      if (totalPaid >= expectedAmount) {
        if (existingUserId) {
          await client.query(
            "UPDATE payments SET status = 'confirmed', confirmed_at = NOW() WHERE user_id = $1 AND status = 'underpaid' AND confirmed_at >= NOW() - INTERVAL '24 hours'",
            [existingUserId]
          );
        } else {
          await client.query(
            "UPDATE payments SET status = 'confirmed', confirmed_at = NOW() WHERE user_id IS NULL AND depositor_name = $1 AND status = 'underpaid' AND confirmed_at >= NOW() - INTERVAL '24 hours'",
            [depositor_name || application.name]
          );
        }
        paidAmount = totalPaid;
      } else {
        const shortage = expectedAmount - totalPaid;
        if (existingUserId) {
          await client.query(
            "INSERT INTO payments (user_id, amount, depositor_name, status, confirmed_at, transaction_id) VALUES ($1, $2, $3, 'underpaid', NOW(), $4)",
            [existingUserId, paidAmount, depositor_name || application.name, transaction_id || null]
          );
        } else {
          await client.query(
            "INSERT INTO payments (user_id, amount, depositor_name, status, confirmed_at, transaction_id) VALUES (NULL, $1, $2, 'underpaid', NOW(), $3)",
            [paidAmount, depositor_name || application.name, transaction_id || null]
          );
        }
        await client.query('COMMIT');
        return res.json({
          success: false,
          status: 'underpaid',
          paid_amount: totalPaid,
          expected_amount: expectedAmount,
          shortage: shortage,
          user_name: application.name,
          user_phone: application.phone,
          message: '총 ' + totalPaid.toLocaleString() + '원이 입금되어 ' + shortage.toLocaleString() + '원이 부족합니다. ' + CONFIG.BANK_NAME + ' ' + CONFIG.BANK_ACCOUNT + ' (' + CONFIG.BANK_HOLDER + ') 계좌로 차액을 추가 입금해주세요.'
        });
      }
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
      tempPassword = generateTempPassword();
      const hashed = await bcrypt.hash(tempPassword, 10);
      const newUser = await client.query(
        'INSERT INTO users (name, email, phone, password, password_is_temp) VALUES ($1, $2, $3, $4, TRUE) RETURNING id',
        [application.name, application.email, application.phone, hashed]
      );
      userId = newUser.rows[0].id;
      isNewUser = true;
    }

    // 4. Create class pass
    const passResult = await client.query(
      "INSERT INTO class_passes (user_id, total_classes, remaining_classes, status, expires_at) VALUES ($1, $2, $2, 'active', NOW() + INTERVAL '" + CONFIG.PASS_MONTHS + " months') RETURNING *",
      [userId, CONFIG.PASS_CLASSES]
    );

    // 5. Create payment record
    await client.query(
      "INSERT INTO payments (user_id, amount, depositor_name, status, confirmed_at, class_pass_id, transaction_id) VALUES ($1, $2, $3, 'confirmed', NOW(), $4, $5)",
      [userId, paidAmount || expectedAmount, depositor_name || application.name, passResult.rows[0].id, transaction_id || null]
    );

    // 6. Update application
    await client.query(
      "UPDATE applications SET status = 'paid', user_id = $1, paid_at = NOW() WHERE id = $2",
      [userId, application.id]
    );

    // 7. Update NULL user_id underpaid records to point to user
    if (isNewUser) {
      await client.query(
        "UPDATE payments SET user_id = $1 WHERE user_id IS NULL AND depositor_name = $2",
        [userId, depositor_name || application.name]
      );
    }

    await client.query('COMMIT');

    // 8. Check overpaid
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

// ===================== ZOOM ATTENDANCE WEBHOOK (n8n 전용) =====================

app.post('/api/webhook/zoom-attendance', requireDB, requireApiKey, async (req, res) => {
  const pool = getPool();
  const client = await pool.connect();
  try {
    const { meeting_uuid, meeting_topic, participants } = req.body;
    if (!meeting_uuid || !participants || !Array.isArray(participants)) {
      return res.status(400).json({ error: 'meeting_uuid와 participants 배열이 필요합니다' });
    }

    const results = {
      processed: [],
      already_done: [],
      no_pass: [],
      not_found: [],
      host_skipped: []
    };

    for (const participant of participants) {
      const email = (participant.email || '').toLowerCase().trim();
      if (!email) continue;

      if (email === CONFIG.HOST_EMAIL) {
        results.host_skipped.push(email);
        continue;
      }

      const userResult = await client.query(
        'SELECT id, name, email FROM users WHERE LOWER(email) = $1',
        [email]
      );
      if (userResult.rows.length === 0) {
        results.not_found.push({ email, name: participant.name || '' });
        continue;
      }

      const user = userResult.rows[0];

      const dupCheck = await client.query(
        'SELECT id FROM attendance WHERE user_id = $1 AND zoom_meeting_uuid = $2',
        [user.id, meeting_uuid]
      );
      if (dupCheck.rows.length > 0) {
        results.already_done.push({ email, name: user.name });
        continue;
      }

      const passResult = await client.query(
        "SELECT * FROM class_passes WHERE user_id = $1 AND status = 'active' AND remaining_classes > 0 ORDER BY purchased_at ASC LIMIT 1",
        [user.id]
      );
      if (passResult.rows.length === 0) {
        results.no_pass.push({ email, name: user.name, user_id: user.id });
        continue;
      }

      const pass = passResult.rows[0];

      await client.query('BEGIN');
      try {
        await client.query(
          'UPDATE class_passes SET remaining_classes = remaining_classes - 1 WHERE id = $1',
          [pass.id]
        );
        if (pass.remaining_classes - 1 <= 0) {
          await client.query("UPDATE class_passes SET status = 'used' WHERE id = $1", [pass.id]);
        }
        await client.query(
          'INSERT INTO attendance (user_id, class_pass_id, zoom_meeting_uuid, note) VALUES ($1, $2, $3, $4)',
          [user.id, pass.id, meeting_uuid, 'Zoom 자동출석: ' + (meeting_topic || '')]
        );
        await client.query('COMMIT');

        results.processed.push({
          email,
          name: user.name,
          user_id: user.id,
          remaining: pass.remaining_classes - 1
        });
      } catch (txErr) {
        await client.query('ROLLBACK');
        console.error('Zoom attendance transaction error for', email, txErr);
      }
    }

    res.json({
      success: true,
      meeting_uuid,
      meeting_topic: meeting_topic || '',
      summary: {
        total_participants: participants.length,
        processed: results.processed.length,
        already_done: results.already_done.length,
        no_pass: results.no_pass.length,
        not_found: results.not_found.length,
        host_skipped: results.host_skipped.length
      },
      details: results
    });
  } catch (err) {
    console.error('Zoom attendance webhook error:', err);
    res.status(500).json({ error: '서버 오류가 발생했습니다' });
  } finally {
    client.release();
  }
});

// ===================== JOURNALING SMS TARGETS (n8n 전용) =====================

app.get('/api/webhook/journaling-targets', requireDB, requireApiKey, async (req, res) => {
  const pool = getPool();
  try {
    const result = await pool.query(`
      WITH pass_first_attendance AS (
        SELECT cp.id AS class_pass_id, cp.user_id, cp.expires_at,
          MIN(a.attended_at) AS first_attended_at,
          EXTRACT(DOW FROM MIN(a.attended_at) AT TIME ZONE 'Asia/Seoul') AS first_class_dow
        FROM class_passes cp
        JOIN attendance a ON a.class_pass_id = cp.id
        WHERE cp.status = 'active'
        GROUP BY cp.id
      ),
      eligible AS (
        SELECT pfa.*, u.name, u.phone, u.email,
          CASE
            WHEN pfa.first_attended_at::date = (CURRENT_DATE AT TIME ZONE 'Asia/Seoul' - INTERVAL '1 day')::date
                 AND NOT EXISTS (
                   SELECT 1 FROM journaling_sms_log jsl
                   WHERE jsl.class_pass_id = pfa.class_pass_id
                 )
            THEN 'first'
            WHEN EXTRACT(DOW FROM CURRENT_DATE AT TIME ZONE 'Asia/Seoul') = pfa.first_class_dow
                 AND (CURRENT_DATE AT TIME ZONE 'Asia/Seoul')::date >= (pfa.first_attended_at::date + INTERVAL '7 days')
                 AND EXISTS (
                   SELECT 1 FROM journaling_sms_log jsl
                   WHERE jsl.class_pass_id = pfa.class_pass_id AND jsl.send_type = 'first'
                 )
                 AND NOT EXISTS (
                   SELECT 1 FROM journaling_sms_log jsl
                   WHERE jsl.class_pass_id = pfa.class_pass_id
                     AND jsl.sent_at::date = (CURRENT_DATE AT TIME ZONE 'Asia/Seoul')::date
                 )
                 AND (pfa.expires_at IS NULL OR pfa.expires_at > NOW())
            THEN 'recurring'
            ELSE NULL
          END AS sms_type
        FROM pass_first_attendance pfa
        JOIN users u ON u.id = pfa.user_id
        WHERE u.role = 'member'
      )
      SELECT * FROM eligible WHERE sms_type IS NOT NULL
    `);
    res.json({ success: true, members: result.rows });
  } catch (err) {
    console.error('Journaling targets API error:', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

// ===================== JOURNALING SMS LOG (n8n 전용) =====================

app.post('/api/webhook/journaling-sms-log', requireDB, requireApiKey, async (req, res) => {
  const pool = getPool();
  try {
    const { user_id, class_pass_id, send_type, send_day_of_week } = req.body;
    if (!user_id || !class_pass_id || !send_type || send_day_of_week === undefined) {
      return res.status(400).json({ error: 'user_id, class_pass_id, send_type, send_day_of_week 필수' });
    }
    const result = await pool.query(
      'INSERT INTO journaling_sms_log (user_id, class_pass_id, send_type, send_day_of_week) VALUES ($1, $2, $3, $4) RETURNING *',
      [user_id, class_pass_id, send_type, send_day_of_week]
    );
    res.json({ success: true, log: result.rows[0] });
  } catch (err) {
    console.error('Journaling SMS log error:', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

// ===================== CARE SMS TARGETS (n8n 전용) =====================

app.get('/api/webhook/care-sms-targets', requireDB, requireApiKey, async (req, res) => {
  const pool = getPool();
  try {
    const result = await pool.query(`
      -- 1) 만료 7일 이내 (이용권당 1회)
      SELECT u.id AS user_id, u.name, u.phone, u.email,
             cp.id AS class_pass_id, cp.remaining_classes, cp.expires_at,
             'expiring_7d' AS sms_type
      FROM class_passes cp
      JOIN users u ON u.id = cp.user_id
      WHERE cp.status = 'active'
        AND cp.expires_at BETWEEN NOW() AND NOW() + INTERVAL '7 days'
        AND u.role = 'member'
        AND NOT EXISTS (
          SELECT 1 FROM care_sms_log csl
          WHERE csl.user_id = u.id AND csl.class_pass_id = cp.id AND csl.sms_type = 'expiring_7d'
        )

      UNION ALL

      -- 2) 7일 이상 미참석 (14일 간격)
      SELECT u.id AS user_id, u.name, u.phone, u.email,
             cp.id AS class_pass_id, cp.remaining_classes, cp.expires_at,
             'inactive_7d' AS sms_type
      FROM users u
      JOIN class_passes cp ON cp.user_id = u.id AND cp.status = 'active' AND cp.remaining_classes > 0
      WHERE u.role = 'member'
        AND EXISTS (
          SELECT 1 FROM attendance a2 WHERE a2.user_id = u.id
        )
        AND NOT EXISTS (
          SELECT 1 FROM attendance a WHERE a.user_id = u.id AND a.attended_at >= NOW() - INTERVAL '7 days'
        )
        AND NOT EXISTS (
          SELECT 1 FROM care_sms_log csl
          WHERE csl.user_id = u.id AND csl.class_pass_id = cp.id AND csl.sms_type = 'inactive_7d'
            AND csl.sent_at >= NOW() - INTERVAL '14 days'
        )

      UNION ALL

      -- 3) 잔여 1회 (이용권당 1회)
      SELECT u.id AS user_id, u.name, u.phone, u.email,
             cp.id AS class_pass_id, cp.remaining_classes, cp.expires_at,
             'renewal_1left' AS sms_type
      FROM class_passes cp
      JOIN users u ON u.id = cp.user_id
      WHERE cp.status = 'active' AND cp.remaining_classes = 1
        AND u.role = 'member'
        AND NOT EXISTS (
          SELECT 1 FROM care_sms_log csl
          WHERE csl.user_id = u.id AND csl.class_pass_id = cp.id AND csl.sms_type = 'renewal_1left'
        )
    `);
    res.json({ success: true, targets: result.rows });
  } catch (err) {
    console.error('Care SMS targets API error:', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

// ===================== CARE SMS LOG (n8n 전용) =====================

app.post('/api/webhook/care-sms-log', requireDB, requireApiKey, async (req, res) => {
  const pool = getPool();
  try {
    const { user_id, class_pass_id, sms_type } = req.body;
    if (!user_id || !class_pass_id || !sms_type) {
      return res.status(400).json({ error: 'user_id, class_pass_id, sms_type 필수' });
    }
    const result = await pool.query(
      'INSERT INTO care_sms_log (user_id, class_pass_id, sms_type) VALUES ($1, $2, $3) RETURNING *',
      [user_id, class_pass_id, sms_type]
    );
    res.json({ success: true, log: result.rows[0] });
  } catch (err) {
    console.error('Care SMS log error:', err);
    res.status(500).json({ error: '서버 오류' });
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

// ===================== PASSWORD RESET (SMS 기반) =====================

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
      [userId, CONFIG.PASS_PRICE, depositorName, 'pending']
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
    const search = req.query.search || '';
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    let whereClause = "WHERE u.role = 'member'";
    const params = [];
    if (search) {
      whereClause += " AND (u.name ILIKE $1 OR u.email ILIKE $1 OR u.phone ILIKE $1)";
      params.push('%' + search + '%');
    }

    const countResult = await pool.query(
      "SELECT COUNT(*) FROM users u " + whereClause,
      params
    );
    const totalCount = parseInt(countResult.rows[0].count);

    const result = await pool.query(
      "SELECT u.id, u.name, u.email, u.phone, u.created_at," +
      " (SELECT COALESCE(SUM(cp.remaining_classes), 0) FROM class_passes cp WHERE cp.user_id = u.id AND cp.status = 'active') as remaining_classes," +
      " (SELECT COUNT(*) FROM attendance a WHERE a.user_id = u.id) as total_attended" +
      " FROM users u " + whereClause +
      " ORDER BY u.created_at DESC LIMIT $" + (params.length + 1) + " OFFSET $" + (params.length + 2),
      [...params, limit, offset]
    );
    res.json({
      members: result.rows,
      pagination: { page, limit, total: totalCount, totalPages: Math.ceil(totalCount / limit) }
    });
  } catch (err) {
    console.error('Admin members error:', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

// ===================== ADMIN: 회원 상세 조회 =====================

app.get('/api/admin/members/:id', requireDB, requireAdmin, async (req, res) => {
  const pool = getPool();
  try {
    const userId = req.params.id;
    const userResult = await pool.query(
      'SELECT id, name, email, phone, password_is_temp, created_at FROM users WHERE id = $1 AND role = $2',
      [userId, 'member']
    );
    if (userResult.rows.length === 0) return res.status(404).json({ error: '회원을 찾을 수 없습니다' });
    const passResult = await pool.query('SELECT * FROM class_passes WHERE user_id = $1 ORDER BY purchased_at DESC', [userId]);
    const paymentResult = await pool.query('SELECT * FROM payments WHERE user_id = $1 ORDER BY created_at DESC', [userId]);
    const attendanceResult = await pool.query(
      'SELECT a.*, cp.total_classes, cp.remaining_classes as pass_remaining FROM attendance a LEFT JOIN class_passes cp ON a.class_pass_id = cp.id WHERE a.user_id = $1 ORDER BY a.attended_at DESC',
      [userId]
    );
    const creditLogsResult = await pool.query(
      'SELECT * FROM credit_logs WHERE user_id = $1 ORDER BY created_at DESC',
      [userId]
    );
    const totalAttended = attendanceResult.rows.length;
    const activePasses = passResult.rows.filter(p => p.status === 'active' && p.remaining_classes > 0);
    const totalRemaining = activePasses.reduce((sum, p) => sum + p.remaining_classes, 0);
    res.json({
      user: userResult.rows[0],
      passes: passResult.rows,
      payments: paymentResult.rows,
      attendance: attendanceResult.rows,
      credit_logs: creditLogsResult.rows,
      stats: { total_attended: totalAttended, total_remaining: totalRemaining, active_passes: activePasses.length }
    });
  } catch (err) {
    console.error('Admin member detail error:', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

// ===================== ADMIN: 회원 정보 수정 =====================

app.put('/api/admin/members/:id', requireDB, requireAdmin, async (req, res) => {
  const pool = getPool();
  try {
    const userId = req.params.id;
    const { name, email, phone } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: '이름을 입력해주세요' });

    // 이메일 중복 확인 (자기 자신 제외)
    if (email && email.trim()) {
      const dup = await pool.query('SELECT id FROM users WHERE email = $1 AND id != $2', [email.trim(), userId]);
      if (dup.rows.length > 0) return res.status(400).json({ error: '이미 사용 중인 이메일입니다' });
    }

    const result = await pool.query(
      'UPDATE users SET name = $1, email = $2, phone = $3 WHERE id = $4 AND role = $5 RETURNING id, name, email, phone',
      [name.trim(), (email || '').trim(), (phone || '').trim(), userId, 'member']
    );
    if (result.rows.length === 0) return res.status(404).json({ error: '회원을 찾을 수 없습니다' });
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error('Admin member update error:', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

// ===================== ADMIN: 회원 삭제 =====================

app.delete('/api/admin/members/:id', requireDB, requireAdmin, async (req, res) => {
  const pool = getPool();
  const client = await pool.connect();
  try {
    const userId = req.params.id;
    // 회원 존재 여부 확인
    const userCheck = await client.query('SELECT id, name FROM users WHERE id = $1 AND role = $2', [userId, 'member']);
    if (userCheck.rows.length === 0) {
      client.release();
      return res.status(404).json({ error: '회원을 찾을 수 없습니다' });
    }
    const userName = userCheck.rows[0].name;
    await client.query('BEGIN');
    // CASCADE 순서: attendance → class_passes → payments → care_sms_log → journaling_sms_log → users
    await client.query('DELETE FROM attendance WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM care_sms_log WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM journaling_sms_log WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM credit_logs WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM class_passes WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM payments WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM users WHERE id = $1', [userId]);
    await client.query('COMMIT');
    res.json({ success: true, message: userName + ' 회원이 삭제되었습니다' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Admin member delete error:', err);
    res.status(500).json({ error: '서버 오류' });
  } finally {
    client.release();
  }
});

// ===================== ADMIN: 이용권 횟수 추가 =====================

app.post('/api/admin/members/:id/add-credits', requireDB, requireAdmin, async (req, res) => {
  const pool = getPool();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const userId = req.params.id;
    const { credits, note } = req.body;
    const addCount = parseInt(credits);
    if (!addCount || addCount < 1 || addCount > 100) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: '추가할 횟수는 1~100 사이여야 합니다' });
    }
    const passResult = await client.query(
      "SELECT * FROM class_passes WHERE user_id = $1 AND status = 'active' ORDER BY purchased_at DESC LIMIT 1",
      [userId]
    );
    let passId;
    if (passResult.rows.length > 0) {
      passId = passResult.rows[0].id;
      await client.query(
        'UPDATE class_passes SET remaining_classes = remaining_classes + $1, total_classes = total_classes + $1 WHERE id = $2',
        [addCount, passId]
      );
    } else {
      const newPass = await client.query(
        "INSERT INTO class_passes (user_id, total_classes, remaining_classes, status, expires_at) VALUES ($1, $2, $2, 'active', NOW() + INTERVAL '" + CONFIG.PASS_MONTHS + " months') RETURNING id",
        [userId, addCount]
      );
      passId = newPass.rows[0].id;
    }
    // 이력 기록
    await client.query(
      'INSERT INTO credit_logs (user_id, class_pass_id, credits, note) VALUES ($1, $2, $3, $4)',
      [userId, passId, addCount, note || null]
    );
    await client.query('COMMIT');
    const updated = await pool.query(
      "SELECT COALESCE(SUM(remaining_classes), 0) as total_remaining FROM class_passes WHERE user_id = $1 AND status = 'active'",
      [userId]
    );
    res.json({
      success: true,
      added: addCount,
      pass_id: passId,
      total_remaining: parseInt(updated.rows[0].total_remaining),
      note: note || ''
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Add credits error:', err);
    res.status(500).json({ error: '서버 오류' });
  } finally {
    client.release();
  }
});

// ===================== ADMIN: 회원 출석 로그 조회 =====================

app.get('/api/admin/members/:id/attendance', requireDB, requireAdmin, async (req, res) => {
  const pool = getPool();
  try {
    const userId = req.params.id;
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;
    const result = await pool.query(
      "SELECT a.id, a.attended_at, a.note, a.zoom_meeting_uuid, cp.total_classes, cp.remaining_classes as pass_remaining, cp.status as pass_status FROM attendance a LEFT JOIN class_passes cp ON a.class_pass_id = cp.id WHERE a.user_id = $1 ORDER BY a.attended_at DESC LIMIT $2 OFFSET $3",
      [userId, limit, offset]
    );
    const countResult = await pool.query('SELECT COUNT(*) FROM attendance WHERE user_id = $1', [userId]);
    res.json({ attendance: result.rows, total: parseInt(countResult.rows[0].count), limit, offset });
  } catch (err) {
    console.error('Admin attendance log error:', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

app.get('/api/admin/payments', requireDB, requireAdmin, async (req, res) => {
  const pool = getPool();
  try {
    const status = req.query.status || 'all';
    const search = req.query.search || '';
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    let whereClause = '';
    const params = [];
    let paramIdx = 1;

    if (status !== 'all') {
      whereClause += ' WHERE p.status = $' + paramIdx;
      params.push(status);
      paramIdx++;
    }
    if (search) {
      whereClause += (whereClause ? ' AND' : ' WHERE') + ' (u.name ILIKE $' + paramIdx + ' OR u.phone ILIKE $' + paramIdx + ' OR p.depositor_name ILIKE $' + paramIdx + ')';
      params.push('%' + search + '%');
      paramIdx++;
    }

    const countResult = await pool.query(
      'SELECT COUNT(*) FROM payments p LEFT JOIN users u ON p.user_id = u.id' + whereClause,
      params
    );
    const totalCount = parseInt(countResult.rows[0].count);

    const result = await pool.query(
      'SELECT p.*, u.name as user_name, u.email as user_email, u.phone as user_phone FROM payments p LEFT JOIN users u ON p.user_id = u.id' + whereClause + ' ORDER BY p.created_at DESC LIMIT $' + paramIdx + ' OFFSET $' + (paramIdx + 1),
      [...params, limit, offset]
    );
    res.json({
      payments: result.rows,
      pagination: { page, limit, total: totalCount, totalPages: Math.ceil(totalCount / limit) }
    });
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
      "INSERT INTO class_passes (user_id, total_classes, remaining_classes, status, expires_at) VALUES ($1, $2, $2, $3, NOW() + INTERVAL '" + CONFIG.PASS_MONTHS + " months') RETURNING *",
      [payment.rows[0].user_id, CONFIG.PASS_CLASSES, 'active']
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
    const search = req.query.search || '';
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    let whereClause = '';
    const params = [];
    let paramIdx = 1;

    if (status !== 'all') {
      whereClause += ' WHERE status = $' + paramIdx;
      params.push(status);
      paramIdx++;
    }
    if (search) {
      whereClause += (whereClause ? ' AND' : ' WHERE') + ' (name ILIKE $' + paramIdx + ' OR email ILIKE $' + paramIdx + ' OR phone ILIKE $' + paramIdx + ')';
      params.push('%' + search + '%');
      paramIdx++;
    }

    const countResult = await pool.query('SELECT COUNT(*) FROM applications' + whereClause, params);
    const totalCount = parseInt(countResult.rows[0].count);

    const result = await pool.query(
      'SELECT * FROM applications' + whereClause + ' ORDER BY created_at DESC LIMIT $' + paramIdx + ' OFFSET $' + (paramIdx + 1),
      [...params, limit, offset]
    );
    res.json({
      applications: result.rows,
      pagination: { page, limit, total: totalCount, totalPages: Math.ceil(totalCount / limit) }
    });
  } catch (err) {
    console.error('Admin applications error:', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

// ===================== ADMIN: 신청 정보 수정 =====================

app.put('/api/admin/applications/:id', requireDB, requireAdmin, async (req, res) => {
  const pool = getPool();
  try {
    const appId = req.params.id;
    const { name, email, phone } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: '이름을 입력해주세요' });

    // 같은 이메일의 다른 pending 신청이 있는지 확인
    if (email && email.trim()) {
      const dup = await pool.query(
        "SELECT id FROM applications WHERE email = $1 AND id != $2 AND status = 'pending'",
        [email.trim(), appId]
      );
      if (dup.rows.length > 0) return res.status(400).json({ error: '동일 이메일의 대기 중인 신청이 이미 있습니다' });
    }

    const result = await pool.query(
      'UPDATE applications SET name = $1, email = $2, phone = $3 WHERE id = $4 RETURNING id, name, email, phone, status',
      [name.trim(), (email || '').trim(), (phone || '').trim(), appId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: '신청 내역을 찾을 수 없습니다' });
    res.json({ success: true, application: result.rows[0] });
  } catch (err) {
    console.error('Admin application update error:', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

// ===================== ADMIN: 신청 삭제 =====================

app.delete('/api/admin/applications/:id', requireDB, requireAdmin, async (req, res) => {
  const pool = getPool();
  try {
    const appId = req.params.id;
    const appCheck = await pool.query('SELECT id, name, status FROM applications WHERE id = $1', [appId]);
    if (appCheck.rows.length === 0) return res.status(404).json({ error: '신청 내역을 찾을 수 없습니다' });

    const appName = appCheck.rows[0].name;
    await pool.query('DELETE FROM applications WHERE id = $1', [appId]);
    res.json({ success: true, message: appName + '님의 신청 내역이 삭제되었습니다' });
  } catch (err) {
    console.error('Admin application delete error:', err);
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

// ===================== API: 첫 출석 회원 조회 (n8n 저널링 안내용 - 하위 호환) =====================

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
app.get('/term', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

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
