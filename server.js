require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { getPool, initDB, isDBReady, getDbUrl } = require('./db');
const { generateTempPassword } = require('./words');
const crypto = require('crypto');

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
  SOLAPI_API_KEY: process.env.SOLAPI_API_KEY || 'NCS4FNOFBWYK96ZI',
  SOLAPI_API_SECRET: process.env.SOLAPI_API_SECRET || 'E6SA8I6NCT04MKTQN8TX0Y4SSGHEJMGR',
  SOLAPI_SENDER: process.env.SOLAPI_SENDER || '07079548182',
  RESEND_API_KEY: process.env.RESEND_API_KEY || 're_RfLPds6p_GxskQTJaTUCpn4HHengcj64y',
  POPBILL_LINK_ID: process.env.POPBILL_LINK_ID || 'ENNEAGRAM',
  POPBILL_SECRET_KEY: process.env.POPBILL_SECRET_KEY || 'q52EkWadYGB1H6FghRyzWxW7u1jbNwHk74+k48vprag=',
  POPBILL_CORP_NUM: process.env.POPBILL_CORP_NUM || '6660203422',
  DISCORD_WEBHOOK_URL: process.env.DISCORD_WEBHOOK_URL || 'https://discord.com/api/webhooks/1470651597640962138/dFDBwRlV7FfFBO0x-VJB2Vk_kJPAjy2QCGVd3msIcrwXd_X3WEKyZPvHCF1ij1TisFv9',
};

// ===================== 서비스 초기화 =====================
const smsService = require('./services/sms')(CONFIG);
const emailService = require('./services/email')(CONFIG);
const cashreceiptService = require('./services/cashreceipt')(CONFIG);
const notificationService = require('./services/notification')();
const discordService = require('./services/discord')(CONFIG);

const services = {
  sms: smsService,
  email: emailService,
  cashreceipt: cashreceiptService,
  notification: notificationService,
  discord: discordService,
};

// ===================== 미들웨어 초기화 =====================
const middleware = require('./middleware')({ isDBReady });

// Trust proxy (Railway, Heroku 등 리버스 프록시 환경에서 필요)
app.set('trust proxy', 1);

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
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true, // XSS 공격 방지
    sameSite: 'lax' // CSRF 공격 방지
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

// ===================== 라우트 컨텍스트 =====================
const routeContext = { getPool, isDBReady, CONFIG, middleware, services };

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

app.post('/api/applications', middleware.requireDB, async (req, res) => {
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

// ===================== 라우트 모듈 등록 =====================
require('./routes/webhook')(app, routeContext);
require('./routes/admin')(app, routeContext);
require('./routes/auth')(app, routeContext);
require('./routes/member')(app, routeContext);

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
