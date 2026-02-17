module.exports = function(app, { getPool, isDBReady, CONFIG, middleware, services }) {
  const { requireDB, requireAuth } = middleware;

  // ===================== Helper: auto-expire passes =====================

  async function autoExpirePasses(pool, passes) {
    for (const pass of passes) {
      if (pass.status === 'active' && pass.expires_at && new Date(pass.expires_at) < new Date()) {
        await pool.query("UPDATE class_passes SET status = 'expired' WHERE id = $1", [pass.id]);
        pass.status = 'expired';
      }
    }
  }

  // ===================== MEMBER: mypage =====================

  app.get('/api/mypage', requireDB, requireAuth, async (req, res) => {
    const pool = getPool();
    try {
      const userId = req.session.userId;
      const userResult = await pool.query('SELECT id, name, email, phone, password_is_temp, created_at FROM users WHERE id = $1 AND deleted_at IS NULL', [userId]);
      const passResult = await pool.query('SELECT * FROM class_passes WHERE user_id = $1 ORDER BY purchased_at DESC LIMIT 50', [userId]);

      // Auto-expire passes that have passed their expiration date
      await autoExpirePasses(pool, passResult.rows);

      const paymentResult = await pool.query('SELECT * FROM payments WHERE user_id = $1 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 50', [userId]);

      const attendancePage = parseInt(req.query.attendance_page) || 1;
      const attendanceLimit = 50;
      const attendanceOffset = (attendancePage - 1) * attendanceLimit;
      const attendanceResult = await pool.query(
        'SELECT * FROM attendance WHERE user_id = $1 ORDER BY attended_at DESC LIMIT $2 OFFSET $3',
        [userId, attendanceLimit, attendanceOffset]
      );
      const attendanceCount = await pool.query('SELECT COUNT(*) FROM attendance WHERE user_id = $1', [userId]);

      res.json({
        user: userResult.rows[0],
        passes: passResult.rows,
        payments: paymentResult.rows,
        attendance: attendanceResult.rows,
        attendance_pagination: {
          page: attendancePage,
          limit: attendanceLimit,
          total: parseInt(attendanceCount.rows[0].count)
        }
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

      // Check for recent pending payment (duplicate prevention)
      const recentPending = await pool.query(
        "SELECT id FROM payments WHERE user_id = $1 AND status = 'pending' AND created_at > NOW() - INTERVAL '1 hour' AND deleted_at IS NULL",
        [userId]
      );
      if (recentPending.rows.length > 0) {
        return res.status(400).json({ error: '이미 입금 대기 중인 결제가 있습니다. 잠시 후 다시 시도해주세요.' });
      }

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
