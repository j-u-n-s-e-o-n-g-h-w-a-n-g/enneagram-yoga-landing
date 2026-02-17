module.exports = function(deps) {
  const { isDBReady } = deps;

  function requireDB(req, res, next) {
    if (!isDBReady()) return res.status(503).json({ error: '데이터베이스가 연결되지 않았습니다.' });
    next();
  }

  function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) return res.status(401).json({ error: '로그인이 필요합니다' });
    next();
  }

  async function requireAdmin(req, res, next) {
    if (!req.session.userId) return res.status(401).json({ error: '로그인이 필요합니다' });
    // Re-verify admin role from DB every 5 minutes
    const now = Date.now();
    if (!req.session.roleCheckedAt || now - req.session.roleCheckedAt > 300000) {
      try {
        const { isDBReady: checkDB } = deps;
        if (checkDB()) {
          const { getPool } = require('./db');
          const pool = getPool();
          if (pool) {
            const result = await pool.query('SELECT role FROM users WHERE id = $1 AND deleted_at IS NULL', [req.session.userId]);
            if (result.rows.length === 0 || result.rows[0].role !== 'admin') {
              req.session.destroy();
              return res.status(403).json({ error: '관리자 권한이 없습니다' });
            }
            req.session.userRole = result.rows[0].role;
            req.session.roleCheckedAt = now;
          }
        }
      } catch (err) {
        console.error('Admin role re-check error:', err.message);
      }
    }
    if (req.session.userRole !== 'admin') return res.status(403).json({ error: '관리자 권한이 없습니다' });
    next();
  }

  function requireApiKey(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    const validKey = process.env.N8N_API_KEY;
    if (!validKey) return res.status(503).json({ error: 'API key not configured on server' });
    if (apiKey !== validKey) return res.status(401).json({ error: 'Invalid API key' });
    next();
  }

  return { requireDB, requireAuth, requireAdmin, requireApiKey };
};
