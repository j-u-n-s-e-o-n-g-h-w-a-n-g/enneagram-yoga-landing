async function logAudit(pool, adminId, action, detail) {
  try {
    await pool.query(
      'INSERT INTO audit_log (admin_id, action, detail) VALUES ($1, $2, $3)',
      [adminId, action, JSON.stringify(detail)]
    );
  } catch (err) {
    console.error('Audit log error:', err.message);
  }
}

module.exports = function(app, { getPool, isDBReady, CONFIG, middleware, services }) {
  const { requireDB, requireAdmin } = middleware;
  const { sendSMS } = services.sms;
  const { sendEmail } = services.email;
  const { issueCashReceipt } = services.cashreceipt;
  const { logNotification } = services.notification;

  // ===================== ADMIN: 회원 목록 =====================

  app.get('/api/admin/members', requireDB, requireAdmin, async (req, res) => {
    const pool = getPool();
    try {
      const search = req.query.search || '';
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 20;
      const offset = (page - 1) * limit;

      let whereClause = "WHERE u.role = 'member' AND u.deleted_at IS NULL";
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
        'SELECT id, name, email, phone, password_is_temp, created_at FROM users WHERE id = $1 AND role = $2 AND deleted_at IS NULL',
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

      if (email && email.trim() && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
        return res.status(400).json({ error: '올바른 이메일 형식이 아닙니다' });
      }
      if (phone && phone.trim()) {
        const normalizedPhone = phone.trim().replace(/[-\s]/g, '');
        if (!/^01[016789]\d{7,8}$/.test(normalizedPhone)) {
          return res.status(400).json({ error: '올바른 전화번호 형식이 아닙니다' });
        }
      }

      // 이메일 중복 확인 (자기 자신 제외)
      if (email && email.trim()) {
        const dup = await pool.query('SELECT id FROM users WHERE email = $1 AND id != $2 AND deleted_at IS NULL', [email.trim(), userId]);
        if (dup.rows.length > 0) return res.status(400).json({ error: '이미 사용 중인 이메일입니다' });
      }

      const result = await pool.query(
        'UPDATE users SET name = $1, email = $2, phone = $3 WHERE id = $4 AND role = $5 AND deleted_at IS NULL RETURNING id, name, email, phone',
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
    try {
      const userId = req.params.id;
      const userCheck = await pool.query('SELECT id, name FROM users WHERE id = $1 AND role = $2 AND deleted_at IS NULL', [userId, 'member']);
      if (userCheck.rows.length === 0) return res.status(404).json({ error: '회원을 찾을 수 없습니다' });
      const userName = userCheck.rows[0].name;
      await pool.query('UPDATE users SET deleted_at = NOW() WHERE id = $1', [userId]);
      await logAudit(pool, req.session.userId, 'delete_member', { member_id: userId, member_name: userName });
      res.json({ success: true, message: userName + ' 회원이 삭제되었습니다' });
    } catch (err) {
      console.error('Admin member delete error:', err);
      res.status(500).json({ error: '서버 오류' });
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
        "SELECT * FROM class_passes WHERE user_id = $1 AND status = 'active' AND (expires_at IS NULL OR expires_at > NOW()) ORDER BY purchased_at DESC LIMIT 1",
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
          "INSERT INTO class_passes (user_id, total_classes, remaining_classes, status, expires_at) VALUES ($1, $2, $2, 'active', NOW() + ($3 * INTERVAL '1 month')) RETURNING id",
          [userId, addCount, CONFIG.PASS_MONTHS]
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
      await logAudit(pool, req.session.userId, 'add_credits', { member_id: userId, credits: addCount, note: note || '' });
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

  // ===================== ADMIN: 결제 목록 =====================

  app.get('/api/admin/payments', requireDB, requireAdmin, async (req, res) => {
    const pool = getPool();
    try {
      const status = req.query.status || 'all';
      const search = req.query.search || '';
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 20;
      const offset = (page - 1) * limit;

      let whereClause = ' WHERE p.deleted_at IS NULL';
      const params = [];
      let paramIdx = 1;

      if (status !== 'all') {
        whereClause += ' AND p.status = $' + paramIdx;
        params.push(status);
        paramIdx++;
      }
      if (search) {
        whereClause += ' AND (u.name ILIKE $' + paramIdx + ' OR u.phone ILIKE $' + paramIdx + ' OR p.depositor_name ILIKE $' + paramIdx + ')';
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

  // ===================== ADMIN: 결제 확인 =====================

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
        "INSERT INTO class_passes (user_id, total_classes, remaining_classes, status, expires_at) VALUES ($1, $2, $2, $3, NOW() + ($4 * INTERVAL '1 month')) RETURNING *",
        [payment.rows[0].user_id, CONFIG.PASS_CLASSES, 'active', CONFIG.PASS_MONTHS]
      );
      await client.query(
        'UPDATE payments SET status = $1, confirmed_at = NOW(), class_pass_id = $2 WHERE id = $3',
        ['confirmed', passResult.rows[0].id, paymentId]
      );
      await client.query('COMMIT');
      await logAudit(pool, req.session.userId, 'confirm_payment', { payment_id: paymentId });
      res.json({ success: true, pass: passResult.rows[0] });
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('Confirm payment error:', err);
      res.status(500).json({ error: '서버 오류' });
    } finally {
      client.release();
    }
  });

  // ===================== ADMIN: 결제 삭제 =====================

  app.delete('/api/admin/payments/:id', requireDB, requireAdmin, async (req, res) => {
    const pool = getPool();
    try {
      const paymentId = req.params.id;
      const payment = await pool.query('SELECT * FROM payments WHERE id = $1 AND deleted_at IS NULL', [paymentId]);
      if (payment.rows.length === 0) { return res.status(404).json({ error: '결제를 찾을 수 없습니다' }); }
      // If payment was confirmed and has a class_pass, deactivate the pass
      if (payment.rows[0].status === 'confirmed' && payment.rows[0].class_pass_id) {
        await pool.query("UPDATE class_passes SET status = 'cancelled' WHERE id = $1", [payment.rows[0].class_pass_id]);
      }
      await pool.query('UPDATE payments SET deleted_at = NOW() WHERE id = $1', [paymentId]);
      await logAudit(pool, req.session.userId, 'delete_payment', { payment_id: paymentId, had_pass: !!payment.rows[0].class_pass_id });
      res.json({ success: true });
    } catch (err) {
      console.error('Delete payment error:', err);
      res.status(500).json({ error: '서버 오류' });
    }
  });

  // ===================== ADMIN: 수동 출석 =====================

  app.post('/api/admin/members/:id/attend', requireDB, requireAdmin, async (req, res) => {
    const pool = getPool();
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const userId = req.params.id;
      const passResult = await client.query(
        "SELECT * FROM class_passes WHERE user_id = $1 AND status = 'active' AND remaining_classes > 0 AND (expires_at IS NULL OR expires_at > NOW()) ORDER BY purchased_at ASC LIMIT 1",
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

  // ===================== ADMIN: 통계 =====================

  app.get('/api/admin/stats', requireDB, requireAdmin, async (req, res) => {
    const pool = getPool();
    try {
      const totalMembers = await pool.query("SELECT COUNT(*) FROM users WHERE role = 'member' AND deleted_at IS NULL");
      const pendingPayments = await pool.query("SELECT COUNT(*) FROM payments WHERE status = 'pending' AND deleted_at IS NULL");
      const activePasses = await pool.query("SELECT COUNT(*) FROM class_passes WHERE status = 'active' AND remaining_classes > 0");
      const todayAttendance = await pool.query("SELECT COUNT(*) FROM attendance WHERE attended_at::date = CURRENT_DATE");
      const pendingApps = await pool.query("SELECT COUNT(*) FROM applications WHERE status = 'pending' AND deleted_at IS NULL");
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

  // ===================== ADMIN: 신청 목록 =====================

  app.get('/api/admin/applications', requireDB, requireAdmin, async (req, res) => {
    const pool = getPool();
    try {
      const status = req.query.status || 'all';
      const search = req.query.search || '';
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 20;
      const offset = (page - 1) * limit;

      let whereClause = ' WHERE deleted_at IS NULL';
      const params = [];
      let paramIdx = 1;

      if (status !== 'all') {
        whereClause += ' AND status = $' + paramIdx;
        params.push(status);
        paramIdx++;
      }
      if (search) {
        whereClause += ' AND (name ILIKE $' + paramIdx + ' OR email ILIKE $' + paramIdx + ' OR phone ILIKE $' + paramIdx + ')';
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
      const appCheck = await pool.query('SELECT id, name, status FROM applications WHERE id = $1 AND deleted_at IS NULL', [appId]);
      if (appCheck.rows.length === 0) return res.status(404).json({ error: '신청 내역을 찾을 수 없습니다' });

      const appName = appCheck.rows[0].name;
      await pool.query('UPDATE applications SET deleted_at = NOW() WHERE id = $1', [appId]);
      await logAudit(pool, req.session.userId, 'delete_application', { application_id: appId });
      res.json({ success: true, message: appName + '님의 신청 내역이 삭제되었습니다' });
    } catch (err) {
      console.error('Admin application delete error:', err);
      res.status(500).json({ error: '서버 오류' });
    }
  });

  // ===================== ADMIN: 알림 발송 내역 조회 =====================

  app.get('/api/admin/members/:id/notifications', requireDB, requireAdmin, async (req, res) => {
    const pool = getPool();
    try {
      const userId = req.params.id;
      const result = await pool.query(
        'SELECT nl.*, p.amount as payment_amount, p.depositor_name FROM notification_log nl LEFT JOIN payments p ON nl.payment_id = p.id WHERE nl.user_id = $1 ORDER BY nl.created_at DESC LIMIT 50',
        [userId]
      );
      res.json({ notifications: result.rows });
    } catch (err) {
      console.error('Notification log error:', err);
      res.status(500).json({ error: '서버 오류' });
    }
  });

  // ===================== ADMIN: 수동 재발송 =====================

  app.post('/api/admin/members/:id/resend', requireDB, requireAdmin, async (req, res) => {
    const pool = getPool();
    try {
      const userId = req.params.id;
      const { type } = req.body;
      const userResult = await pool.query('SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL', [userId]);
      if (userResult.rows.length === 0) return res.status(404).json({ error: '회원을 찾을 수 없습니다' });
      const user = userResult.rows[0];
      const payResult = await pool.query("SELECT * FROM payments WHERE user_id = $1 AND status = 'confirmed' ORDER BY confirmed_at DESC LIMIT 1", [userId]);
      const payment = payResult.rows[0] || null;

      if (type === 'sms') {
        const msg = user.name + '님,\n[데일리 요가 클래스] 안내\n\n▶ 로그인: https://junseonghwang.com/login\n▶ 수업 시간: 평일 오전 9:30 / 오후 6:30\n\n* Zoom: https://us06web.zoom.us/j/87426930070?pwd=FFf88PQ1ZeyP8MJ1gCMqW6oaB35qqZ.1\n* 암호: yoga';
        const { success, groupId } = await sendSMS(user.phone, msg);
        await logNotification(pool, userId, payment?.id, 'sms', success ? 'success' : 'failed', { groupId, manual: true });
        return res.json({ success, message: success ? 'SMS 재발송 성공' : 'SMS 재발송 실패' });
      }

      if (type === 'email') {
        const html = '<div style="font-family:sans-serif;max-width:600px;margin:0 auto;line-height:1.8"><p><strong>' + user.name + '</strong>님,<br>[데일리 요가 클래스] 안내</p><ul style="list-style:none;padding:0"><li>▶ 로그인: <a href="https://junseonghwang.com/login">https://junseonghwang.com/login</a></li><li>▶ 수업 시간: 평일 오전 9:30 / 오후 6:30</li></ul><hr><ul style="list-style:none;padding:0"><li>Zoom: <a href="https://us06web.zoom.us/j/87426930070?pwd=FFf88PQ1ZeyP8MJ1gCMqW6oaB35qqZ.1">참여하기</a></li><li>Zoom 암호: yoga</li></ul></div>';
        const { success, email_id } = await sendEmail(user.email, '[데일리 요가 클래스] 수업 안내', html);
        await logNotification(pool, userId, payment?.id, 'email', success ? 'success' : 'failed', { email_id, manual: true });
        return res.json({ success, message: success ? '이메일 재발송 성공' : '이메일 재발송 실패' });
      }

      if (type === 'cashreceipt') {
        if (!payment) return res.status(400).json({ error: '확인된 결제 내역이 없습니다' });
        const cr = await issueCashReceipt({ phone: user.phone, name: user.name, email: user.email, amount: payment.amount, memo: '관리자 수동 발행' });
        await logNotification(pool, userId, payment.id, 'cashreceipt', cr.success ? 'success' : 'failed', { mgtKey: cr.mgtKey, manual: true, receipt_amount: cr.receiptAmount });
        return res.json({ success: cr.success, message: cr.success ? '현금영수증 재발행 성공' : '현금영수증 재발행 실패' });
      }

      res.status(400).json({ error: 'type은 sms, email, cashreceipt 중 하나여야 합니다' });
    } catch (err) {
      console.error('Admin resend error:', err);
      res.status(500).json({ error: '서버 오류' });
    }
  });

  // ===================== ADMIN: 단체 SMS 대상 조회 =====================

  app.get('/api/admin/bulk-sms/targets', requireDB, requireAdmin, async (req, res) => {
    const pool = getPool();
    try {
      const type = req.query.type || 'active';
      let result;

      if (type === 'active') {
        // 유효한 이용권 보유 회원 (잔여 > 0 + 만료 안됨)
        result = await pool.query(`
          SELECT u.id, u.name, u.phone, u.email,
            COALESCE(SUM(cp.remaining_classes), 0) as remaining_classes
          FROM users u
          JOIN class_passes cp ON cp.user_id = u.id
            AND cp.status = 'active' AND cp.remaining_classes > 0
            AND (cp.expires_at IS NULL OR cp.expires_at > NOW())
          WHERE u.role = 'member' AND u.deleted_at IS NULL
            AND u.phone IS NOT NULL AND u.phone != ''
          GROUP BY u.id, u.name, u.phone, u.email
          ORDER BY u.name
        `);
      } else {
        // 유효 이용권 없는 회원
        result = await pool.query(`
          SELECT u.id, u.name, u.phone, u.email, 0 as remaining_classes
          FROM users u
          WHERE u.role = 'member' AND u.deleted_at IS NULL
            AND u.phone IS NOT NULL AND u.phone != ''
            AND NOT EXISTS (
              SELECT 1 FROM class_passes cp
              WHERE cp.user_id = u.id AND cp.status = 'active' AND cp.remaining_classes > 0
                AND (cp.expires_at IS NULL OR cp.expires_at > NOW())
            )
          ORDER BY u.name
        `);
      }

      res.json({ members: result.rows, count: result.rows.length });
    } catch (err) {
      console.error('Bulk SMS targets error:', err);
      res.status(500).json({ error: '서버 오류' });
    }
  });

  // ===================== ADMIN: 단체 SMS 발송 =====================

  app.post('/api/admin/bulk-sms', requireDB, requireAdmin, async (req, res) => {
    const pool = getPool();
    try {
      const { type, message } = req.body;
      if (!type || !message || !message.trim()) {
        return res.status(400).json({ error: '발송 대상과 메시지를 입력해주세요' });
      }
      if (message.length > 2000) {
        return res.status(400).json({ error: '메시지는 2000자 이하로 입력해주세요' });
      }

      // 대상 회원 조회
      let members;
      if (type === 'active') {
        const result = await pool.query(`
          SELECT u.id, u.name, u.phone
          FROM users u
          JOIN class_passes cp ON cp.user_id = u.id
            AND cp.status = 'active' AND cp.remaining_classes > 0
            AND (cp.expires_at IS NULL OR cp.expires_at > NOW())
          WHERE u.role = 'member' AND u.deleted_at IS NULL
            AND u.phone IS NOT NULL AND u.phone != ''
          GROUP BY u.id, u.name, u.phone
        `);
        members = result.rows;
      } else {
        const result = await pool.query(`
          SELECT u.id, u.name, u.phone
          FROM users u
          WHERE u.role = 'member' AND u.deleted_at IS NULL
            AND u.phone IS NOT NULL AND u.phone != ''
            AND NOT EXISTS (
              SELECT 1 FROM class_passes cp
              WHERE cp.user_id = u.id AND cp.status = 'active' AND cp.remaining_classes > 0
                AND (cp.expires_at IS NULL OR cp.expires_at > NOW())
            )
        `);
        members = result.rows;
      }

      if (members.length === 0) {
        return res.status(400).json({ error: '발송 대상이 없습니다' });
      }

      // 순차 발송
      let sent = 0;
      let failed = 0;
      const details = [];

      for (const member of members) {
        const personalMsg = message.replace(/\{name\}/g, member.name);
        try {
          const { success, groupId } = await sendSMS(member.phone, personalMsg);
          if (success) {
            sent++;
            details.push({ name: member.name, phone: member.phone, status: 'success' });
          } else {
            failed++;
            details.push({ name: member.name, phone: member.phone, status: 'failed' });
          }
          await logNotification(pool, member.id, null, 'sms', success ? 'success' : 'failed', { groupId, bulk: true, bulk_type: type });
        } catch (smsErr) {
          failed++;
          details.push({ name: member.name, phone: member.phone, status: 'error' });
        }
      }

      await logAudit(pool, req.session.userId, 'bulk_sms', { type, total: members.length, sent, failed, message: message.substring(0, 100) });
      res.json({ success: true, total: members.length, sent, failed, details });
    } catch (err) {
      console.error('Bulk SMS error:', err);
      res.status(500).json({ error: '서버 오류' });
    }
  });
};
