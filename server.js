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
  HOST_EMAIL: process.env.HOST_EMAIL || '',
  SOLAPI_API_KEY: process.env.SOLAPI_API_KEY || '',
  SOLAPI_API_SECRET: process.env.SOLAPI_API_SECRET || '',
  SOLAPI_SENDER: process.env.SOLAPI_SENDER || '',
  RESEND_API_KEY: process.env.RESEND_API_KEY || '',
  POPBILL_LINK_ID: process.env.POPBILL_LINK_ID || '',
  POPBILL_SECRET_KEY: process.env.POPBILL_SECRET_KEY || '',
  POPBILL_CORP_NUM: process.env.POPBILL_CORP_NUM || '',
  DISCORD_WEBHOOK_URL: process.env.DISCORD_WEBHOOK_URL || '',
  ZOOM_MEETING_URL: process.env.ZOOM_MEETING_URL || '',
  ZOOM_PASSWORD: process.env.ZOOM_PASSWORD || 'yoga',
  ZOOM_ACCOUNT_ID: process.env.ZOOM_ACCOUNT_ID || '',
  ZOOM_CLIENT_ID: process.env.ZOOM_CLIENT_ID || '',
  ZOOM_CLIENT_SECRET: process.env.ZOOM_CLIENT_SECRET || '',
  ZOOM_MEETING_ID: process.env.ZOOM_MEETING_ID || '87426930070',
  BACKUP_GITHUB_TOKEN: process.env.BACKUP_GITHUB_TOKEN || '',
  BACKUP_GITHUB_OWNER: process.env.BACKUP_GITHUB_OWNER || '',
  BACKUP_GITHUB_REPO: process.env.BACKUP_GITHUB_REPO || '',
  BACKUP_GITHUB_BRANCH: process.env.BACKUP_GITHUB_BRANCH || 'main',
};

// ===================== ZOOM OAuth TOKEN =====================
let zoomTokenCache = { token: null, expiresAt: 0 };

async function getZoomAccessToken() {
  const now = Date.now();
  if (zoomTokenCache.token && zoomTokenCache.expiresAt > now + 5 * 60 * 1000) {
    return zoomTokenCache.token;
  }
  const { ZOOM_ACCOUNT_ID, ZOOM_CLIENT_ID, ZOOM_CLIENT_SECRET } = CONFIG;
  if (!ZOOM_ACCOUNT_ID || !ZOOM_CLIENT_ID || !ZOOM_CLIENT_SECRET) {
    throw new Error('Zoom OAuth credentials not configured');
  }
  const basicAuth = Buffer.from(`${ZOOM_CLIENT_ID}:${ZOOM_CLIENT_SECRET}`).toString('base64');
  const response = await fetch(
    `https://zoom.us/oauth/token?grant_type=account_credentials&account_id=${ZOOM_ACCOUNT_ID}`,
    { method: 'POST', headers: { 'Authorization': `Basic ${basicAuth}`, 'Content-Type': 'application/x-www-form-urlencoded' } }
  );
  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Zoom OAuth failed: ${response.status} ${errText}`);
  }
  const data = await response.json();
  zoomTokenCache = { token: data.access_token, expiresAt: now + (data.expires_in * 1000) };
  return zoomTokenCache.token;
}

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

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'");
  next();
});

// ===================== SESSION (before routes!) =====================
const sessionConfig = {
  secret: process.env.SESSION_SECRET || (() => { console.warn('⚠️ SESSION_SECRET not set, using random key'); return crypto.randomBytes(32).toString('hex'); })(),
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
    sessionConfig.store = new pgSession({ pool: initPool, tableName: 'session', pruneSessionInterval: 3600 });
    console.log('✅ Session store: PostgreSQL');
  } catch (err) {
    console.warn('⚠️  PG session store failed, using memory store:', err.message);
  }
} else {
  console.log('⚠️  Session store: Memory (no database URL)');
}
app.use(session(sessionConfig));

// ===================== CSRF Protection =====================
app.use((req, res, next) => {
  if (req.session && !req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  next();
});

app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.session.csrfToken });
});

function requireCsrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const token = req.headers['x-csrf-token'];
  if (!token || token !== req.session?.csrfToken) {
    return res.status(403).json({ error: 'CSRF 토큰이 유효하지 않습니다' });
  }
  next();
}

app.use('/api/login', requireCsrf);
app.use('/api/register', requireCsrf);
app.use('/api/logout', requireCsrf);
app.use('/api/change-password', requireCsrf);
app.use('/api/reset-password', requireCsrf);
app.use('/api/applications', requireCsrf);
app.use('/api/members', requireCsrf);
app.use('/api/admin', requireCsrf);
app.use('/api/passes', requireCsrf);
app.use('/api/zoom-register', requireCsrf);

// ===================== Rate Limiter (sliding window) =====================
const appRateLimiter = (() => {
  const windows = new Map();
  const WINDOW_MS = 15 * 60 * 1000; // 15분
  const MAX_REQUESTS = 15;
  setInterval(() => { const now = Date.now(); for (const [k,v] of windows) { const valid = v.filter(t => now - t < WINDOW_MS); if (valid.length === 0) windows.delete(k); else windows.set(k, valid); } }, 300000).unref();
  return (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    const timestamps = (windows.get(ip) || []).filter(t => now - t < WINDOW_MS);
    if (timestamps.length >= MAX_REQUESTS) {
      return res.status(429).json({ error: '너무 많은 요청입니다. 잠시 후 다시 시도해주세요.' });
    }
    timestamps.push(now);
    windows.set(ip, timestamps);
    next();
  };
})();

// ===================== 라우트 컨텍스트 =====================
const routeContext = { getPool, isDBReady, CONFIG, middleware, services, getZoomAccessToken };

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

app.post('/api/applications', middleware.requireDB, appRateLimiter, async (req, res) => {
  const pool = getPool();
  try {
    const { name, email, phone, consents } = req.body;
    if (!name || !email || !phone) return res.status(400).json({ error: '이름, 이메일, 전화번호를 모두 입력해주세요' });
    if (name.length > 50) return res.status(400).json({ error: '이름은 50자 이하로 입력해주세요' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: '올바른 이메일 형식이 아닙니다' });
    const normalizedPhone = phone.replace(/[-\s]/g, '');
    if (!/^01[016789]\d{7,8}$/.test(normalizedPhone)) return res.status(400).json({ error: '올바른 전화번호 형식이 아닙니다' });
    // 동일 이메일+pending이면 업데이트
    const existing = await pool.query(
      "SELECT id FROM applications WHERE email = $1 AND status = 'pending' AND deleted_at IS NULL",
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
    // 동의 내역 기록
    if (consents && Array.isArray(consents)) {
      const ip = req.ip || req.headers['x-forwarded-for'] || '';
      const ua = req.headers['user-agent'] || '';
      for (const c of consents) {
        try {
          await pool.query(
            'INSERT INTO consent_log (application_id, consent_type, consented, ip_address, user_agent) VALUES ($1, $2, $3, $4, $5)',
            [application.id, c.type, c.agreed !== false, ip, ua]
          );
        } catch (logErr) { console.error('Consent log error:', logErr.message); }
      }
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
  try { await initDB(); } catch (err) { console.error('DB init failed:', err.message); }
  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`   Database: ${isDBReady() ? 'Connected' : 'Not connected'}`);
  });
  process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down...');
    server.close(() => { const p = getPool(); if (p) p.end(); process.exit(0); });
    setTimeout(() => process.exit(1), 10000);
  });
  process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down...');
    server.close(() => { const p = getPool(); if (p) p.end(); process.exit(0); });
    setTimeout(() => process.exit(1), 10000);
  });
}
start();
