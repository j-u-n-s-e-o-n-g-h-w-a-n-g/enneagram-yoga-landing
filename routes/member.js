module.exports = function(app, { getPool, isDBReady, CONFIG, middleware, services, getZoomAccessToken }) {
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

  // ===================== MEMBER: zoom-register =====================

  app.get('/api/zoom-status', requireDB, requireAuth, async (req, res) => {
    const pool = getPool();
    try {
      const userId = req.session.userId;
      const result = await pool.query(
        "SELECT id FROM class_passes WHERE user_id = $1 AND status = 'active' AND remaining_classes > 0 AND expires_at > NOW() LIMIT 1",
        [userId]
      );
      res.json({ hasPass: result.rows.length > 0 });
    } catch (err) {
      console.error('Zoom status error:', err);
      res.status(500).json({ error: '서버 오류' });
    }
  });

  app.post('/api/zoom-register', requireDB, requireAuth, async (req, res) => {
    const pool = getPool();
    try {
      const userId = req.session.userId;

      // 1. Check valid class pass
      const passResult = await pool.query(
        "SELECT id FROM class_passes WHERE user_id = $1 AND status = 'active' AND remaining_classes > 0 AND expires_at > NOW() LIMIT 1",
        [userId]
      );
      if (passResult.rows.length === 0) {
        return res.status(403).json({ error: '유효한 이용권이 없습니다. 이용권을 구매해주세요.', hasPass: false });
      }

      // 2. Get user info
      const userResult = await pool.query('SELECT name, email FROM users WHERE id = $1', [userId]);
      if (userResult.rows.length === 0) return res.status(404).json({ error: '사용자를 찾을 수 없습니다' });
      const user = userResult.rows[0];

      // 3. Get Zoom access token
      const accessToken = await getZoomAccessToken();
      const meetingId = CONFIG.ZOOM_MEETING_ID;

      // 4. Register as Zoom meeting registrant
      const registerRes = await fetch(`https://api.zoom.us/v2/meetings/${meetingId}/registrants`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: user.email, first_name: user.name })
      });

      if (registerRes.ok) {
        const regData = await registerRes.json();
        return res.json({ success: true, join_url: regData.join_url });
      }

      // 5. Handle duplicate registration
      const errBody = await registerRes.json().catch(() => ({}));
      if (registerRes.status === 409 || errBody.code === 3027) {
        // Fetch existing registration
        const listRes = await fetch(`https://api.zoom.us/v2/meetings/${meetingId}/registrants?status=approved&page_size=300`, {
          headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        if (listRes.ok) {
          const listData = await listRes.json();
          const existing = listData.registrants.find(r => r.email.toLowerCase() === user.email.toLowerCase());
          if (existing) return res.json({ success: true, join_url: existing.join_url });
        }
        return res.status(500).json({ error: 'Zoom 등록 정보를 가져올 수 없습니다. 관리자에게 문의해주세요.' });
      }

      console.error('Zoom registration error:', registerRes.status, errBody);
      return res.status(500).json({ error: 'Zoom 등록 중 오류가 발생했습니다' });
    } catch (err) {
      console.error('Zoom register error:', err);
      res.status(500).json({ error: '서버 오류가 발생했습니다' });
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
