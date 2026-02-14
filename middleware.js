module.exports = function({ isDBReady }) {
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

  return { requireDB, requireAuth, requireAdmin, requireApiKey };
};
