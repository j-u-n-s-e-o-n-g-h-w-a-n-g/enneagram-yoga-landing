module.exports = function(app, { getPool, isDBReady, CONFIG, middleware, services }) {
  const { requireDB, requireAuth } = middleware;

  // ===================== MEMBER: mypage =====================

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

  // ===================== MEMBER: passes/request =====================

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
};
