module.exports = function(app, { getPool, isDBReady, CONFIG, middleware, services, getZoomAccessToken }) {
  const { requireDB, requireApiKey } = middleware;
  const { sendSMS } = services.sms;
  const { sendEmail } = services.email;
  const { issueCashReceipt } = services.cashreceipt;
  const { logNotification } = services.notification;
  const { notifyDiscord } = services.discord;
  const bcrypt = require('bcryptjs');
  const { generateTempPassword } = require('../words');

  function validateWebhookInput(body, maxLengths) {
    for (const [key, max] of Object.entries(maxLengths)) {
      if (body[key] && String(body[key]).length > max) {
        return `${key} exceeds maximum length of ${max}`;
      }
    }
    return null;
  }

  // ===================== payment-confirm helpers =====================

  async function findMatchingApplication(client, { depositor_name, phone, email }) {
    const normalizedPhone = phone ? phone.replace(/[-\s]/g, '') : null;
    let appResult;
    if (normalizedPhone) {
      appResult = await client.query(
        "SELECT * FROM applications WHERE REPLACE(REPLACE(phone, '-', ''), ' ', '') = $1 AND status = 'pending' AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1 FOR UPDATE",
        [normalizedPhone]
      );
    }
    if ((!appResult || appResult.rows.length === 0) && email) {
      appResult = await client.query(
        "SELECT * FROM applications WHERE email = $1 AND status = 'pending' AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1 FOR UPDATE",
        [email]
      );
    }
    if ((!appResult || appResult.rows.length === 0) && depositor_name) {
      appResult = await client.query(
        "SELECT * FROM applications WHERE name = $1 AND status = 'pending' AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1 FOR UPDATE",
        [depositor_name]
      );
    }
    return appResult && appResult.rows.length > 0 ? appResult.rows[0] : null;
  }

  async function handleUnderpaid(client, { application, paidAmount, expectedAmount, depositor_name, transaction_id }) {
    const existingUserForCheck = await client.query('SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL LIMIT 1', [application.email]);
    const existingUserId = existingUserForCheck.rows.length > 0 ? existingUserForCheck.rows[0].id : null;
    const depName = depositor_name || application.name;

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
        [depName]
      );
      previousTotal = parseInt(prevPayments.rows[0].total_prev) || 0;
    }
    const totalPaid = previousTotal + paidAmount;

    if (totalPaid >= expectedAmount) {
      const whereClause = existingUserId
        ? ["user_id = $1", [existingUserId]]
        : ["user_id IS NULL AND depositor_name = $1", [depName]];
      await client.query(
        `UPDATE payments SET status = 'confirmed', confirmed_at = NOW() WHERE ${whereClause[0]} AND status = 'underpaid' AND confirmed_at >= NOW() - INTERVAL '24 hours'`,
        whereClause[1]
      );
      return { completed: true, totalPaid };
    }

    // Still underpaid - record partial payment
    const shortage = expectedAmount - totalPaid;
    if (existingUserId) {
      await client.query(
        "INSERT INTO payments (user_id, amount, depositor_name, status, confirmed_at, transaction_id) VALUES ($1, $2, $3, 'underpaid', NOW(), $4)",
        [existingUserId, paidAmount, depName, transaction_id || null]
      );
    } else {
      await client.query(
        "INSERT INTO payments (user_id, amount, depositor_name, status, confirmed_at, transaction_id) VALUES (NULL, $1, $2, 'underpaid', NOW(), $3)",
        [paidAmount, depName, transaction_id || null]
      );
    }
    return { completed: false, totalPaid, shortage };
  }

  async function createOrGetUser(client, application) {
    const existingUser = await client.query('SELECT id, email FROM users WHERE email = $1 AND deleted_at IS NULL', [application.email]);
    if (existingUser.rows.length > 0) {
      return { userId: existingUser.rows[0].id, isNewUser: false, tempPassword: null };
    }
    const tempPassword = generateTempPassword();
    const hashed = await bcrypt.hash(tempPassword, 10);
    const newUser = await client.query(
      'INSERT INTO users (name, email, phone, password, password_is_temp) VALUES ($1, $2, $3, $4, TRUE) RETURNING id',
      [application.name, application.email, application.phone, hashed]
    );
    return { userId: newUser.rows[0].id, isNewUser: true, tempPassword };
  }

  // ===================== WEBHOOK: payment-confirm =====================

  app.post('/api/webhook/payment-confirm', requireDB, requireApiKey, async (req, res) => {
    const pool = getPool();
    const client = await pool.connect();
    try {
      // 원본 webhook 데이터 보존 (트랜잭션 밖에서)
      try { await pool.query("INSERT INTO webhook_raw_log (source, payload) VALUES ('payment-confirm', $1)", [JSON.stringify(req.body)]); } catch(e) { console.error('Raw log error:', e.message); }

      await client.query('BEGIN');
      const { depositor_name, amount, phone, email, transaction_id } = req.body;
      if (!depositor_name && !phone && !email) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: '입금자명, 전화번호, 이메일 중 하나 이상 필요합니다' });
      }

      // ===== 멱등성 체크 =====
      if (transaction_id) {
        const dupCheck = await client.query("SELECT id FROM payments WHERE transaction_id = $1", [transaction_id]);
        if (dupCheck.rows.length > 0) {
          await client.query('ROLLBACK');
          return res.json({ success: true, status: 'duplicate', message: '이미 처리된 입금건입니다', payment_id: dupCheck.rows[0].id });
        }
      }

      let paidAmount = parseInt(amount) || 0;
      const expectedAmount = CONFIG.PASS_PRICE;

      // 1. Find matching application
      const application = await findMatchingApplication(client, { depositor_name, phone, email });
      if (!application) {
        await client.query('ROLLBACK');
        return res.status(404).json({ success: false, status: 'not_found', error: '매칭되는 신청 내역을 찾을 수 없습니다', depositor_name, phone, email });
      }

      // 2. Handle underpaid
      if (paidAmount > 0 && paidAmount < expectedAmount) {
        const underpaidResult = await handleUnderpaid(client, { application, paidAmount, expectedAmount, depositor_name, transaction_id });
        if (!underpaidResult.completed) {
          await client.query('COMMIT');
          return res.json({
            success: false, status: 'underpaid',
            paid_amount: underpaidResult.totalPaid, expected_amount: expectedAmount, shortage: underpaidResult.shortage,
            user_name: application.name, user_phone: application.phone,
            message: '총 ' + underpaidResult.totalPaid.toLocaleString() + '원이 입금되어 ' + underpaidResult.shortage.toLocaleString() + '원이 부족합니다. ' + CONFIG.BANK_NAME + ' ' + CONFIG.BANK_ACCOUNT + ' (' + CONFIG.BANK_HOLDER + ') 계좌로 차액을 추가 입금해주세요.'
          });
        }
        paidAmount = underpaidResult.totalPaid;
      }

      // 3. Create or get user
      const { userId, isNewUser, tempPassword } = await createOrGetUser(client, application);

      // 4. Create class pass
      const passResult = await client.query(
        "INSERT INTO class_passes (user_id, total_classes, remaining_classes, status, expires_at) VALUES ($1, $2, $2, 'active', NOW() + ($3 * INTERVAL '1 month')) RETURNING *",
        [userId, CONFIG.PASS_CLASSES, CONFIG.PASS_MONTHS]
      );

      // 5. Create payment record
      const paymentInsert = await client.query(
        "INSERT INTO payments (user_id, amount, depositor_name, status, confirmed_at, class_pass_id, transaction_id) VALUES ($1, $2, $3, 'confirmed', NOW(), $4, $5) RETURNING id",
        [userId, paidAmount || expectedAmount, depositor_name || application.name, passResult.rows[0].id, transaction_id || null]
      );
      const paymentId = paymentInsert.rows[0].id;

      // 6. Update application
      await client.query("UPDATE applications SET status = 'paid', user_id = $1, paid_at = NOW() WHERE id = $2", [userId, application.id]);

      // 7. Link orphan underpaid records to user
      if (isNewUser) {
        await client.query("UPDATE payments SET user_id = $1 WHERE user_id IS NULL AND depositor_name = $2", [userId, depositor_name || application.name]);
      }

      await client.query('COMMIT');

      // 8. Check overpaid
      let overpaidInfo = null;
      if (paidAmount > expectedAmount) {
        const excess = paidAmount - expectedAmount;
        overpaidInfo = { status: 'overpaid', excess, message: paidAmount.toLocaleString() + '원이 입금되어 ' + excess.toLocaleString() + '원이 초과 입금되었습니다. 차액은 입금하신 계좌로 반환될 예정입니다.' };
      }

      res.json({
        success: true, status: overpaidInfo ? 'overpaid' : 'confirmed',
        application_created_at: application.created_at, user_id: userId, payment_id: paymentId,
        temp_password: tempPassword, user_name: application.name, user_email: application.email,
        user_phone: application.phone, is_new_user: isNewUser,
        pass_id: passResult.rows[0].id, expires_at: passResult.rows[0].expires_at,
        paid_amount: paidAmount || expectedAmount, overpaid: overpaidInfo
      });
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('Payment confirm webhook error:', err);
      res.status(500).json({ error: '서버 오류가 발생했습니다' });
    } finally {
      client.release();
    }
  });

  // ===================== WEBHOOK: zoom-attendance =====================

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
          'SELECT id, name, email FROM users WHERE LOWER(email) = $1 AND deleted_at IS NULL',
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

  // ===================== WEBHOOK: journaling-targets =====================

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

  // ===================== WEBHOOK: care-sms-targets =====================

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

  // ===================== WEBHOOK: send-sms =====================

  app.post('/api/webhook/send-sms', requireDB, requireApiKey, async (req, res) => {
    try {
      const validationError = validateWebhookInput(req.body, { to: 20, text: 2000 });
      if (validationError) return res.status(400).json({ error: validationError });

      const { phone, message, sms_type, user_id, class_pass_id, log_table, payment_id } = req.body;
      if (!phone || !message) return res.status(400).json({ error: 'phone, message 필수' });
      const cleanPhone = phone.replace(/[-\s]/g, '');
      if (cleanPhone.length < 10) return res.status(400).json({ error: '유효하지 않은 전화번호' });

      // Send SMS with retry (1 retry on failure)
      let smsResult = await sendSMS(phone, message);
      if (!smsResult.success) {
        console.warn('SMS first attempt failed, retrying in 2s...', { phone: cleanPhone, statusCode: smsResult.statusCode });
        await new Promise(r => setTimeout(r, 2000));
        smsResult = await sendSMS(phone, message);
      }
      const { success, groupId, statusCode, result } = smsResult;

      // Log to specific table if specified
      if (success && log_table && user_id) {
        const pool = getPool();
        try {
          if (log_table === 'journaling_sms_log' && class_pass_id) {
            await pool.query('INSERT INTO journaling_sms_log (user_id, class_pass_id, send_type, send_day_of_week) VALUES ($1, $2, $3, $4)', [user_id, class_pass_id, sms_type || 'unknown', req.body.send_day_of_week || 0]);
          } else if (log_table === 'care_sms_log' && class_pass_id) {
            await pool.query('INSERT INTO care_sms_log (user_id, class_pass_id, sms_type) VALUES ($1, $2, $3)', [user_id, class_pass_id, sms_type || 'unknown']);
          }
        } catch (logErr) { console.error('SMS log insert error:', logErr); }
      }

      // Log to notification_log
      if (user_id || payment_id) {
        await logNotification(getPool(), user_id, payment_id, 'sms', success ? 'success' : 'failed', { groupId, statusCode, phone: cleanPhone });
      }

      res.json({ success, statusCode, groupId, message: success ? 'SMS 발송 성공' : 'SMS 발송 실패', detail: success ? null : result });
    } catch (err) {
      console.error('Send SMS API error:', err);
      res.status(500).json({ error: 'SMS 발송 중 서버 오류' });
    }
  });

  // ===================== WEBHOOK: send-email =====================

  app.post('/api/webhook/send-email', requireDB, requireApiKey, async (req, res) => {
    try {
      const validationError = validateWebhookInput(req.body, { to: 255, subject: 500, html: 50000 });
      if (validationError) return res.status(400).json({ error: validationError });

      const { to, from: fromAddr, subject, html, text, attachments, user_id, payment_id } = req.body;
      if (!to || !subject || (!html && !text)) return res.status(400).json({ error: 'to, subject, html/text 필수' });

      const { success, email_id, result } = await sendEmail(to, subject, html, { from: fromAddr, text, attachments });

      if (user_id || payment_id) {
        await logNotification(getPool(), user_id, payment_id, 'email', success ? 'success' : 'failed', { email_id, to });
      }

      res.json({ success, email_id: email_id || null, detail: success ? null : result });
    } catch (err) {
      console.error('Send Email API error:', err);
      res.status(500).json({ error: '이메일 발송 중 서버 오류' });
    }
  });

  // ===================== WEBHOOK: issue-cashreceipt =====================

  app.post('/api/webhook/issue-cashreceipt', requireDB, requireApiKey, async (req, res) => {
    try {
      const { phone, name, email, amount, user_id, payment_id } = req.body;
      if (!phone || !name || !amount) return res.status(400).json({ error: 'phone, name, amount 필수' });

      const cr = await issueCashReceipt({ phone, name, email, amount });
      if (!cr.success && cr.error) return res.json({ success: false, error: cr.error, detail: cr.tokenData });

      if (user_id || payment_id) {
        await logNotification(getPool(), user_id, payment_id, 'cashreceipt', cr.success ? 'success' : 'failed', { mgtKey: cr.mgtKey, receipt_amount: cr.receiptAmount, phone });
      }

      res.json({ success: cr.success, mgtKey: cr.mgtKey, receipt_amount: cr.receiptAmount, detail: cr.success ? null : cr.issueResult });
    } catch (err) {
      console.error('Popbill cashreceipt error:', err);
      res.status(500).json({ error: '현금영수증 발행 중 오류' });
    }
  });

  // ===================== WEBHOOK: notify-discord =====================

  app.post('/api/webhook/notify-discord', requireDB, requireApiKey, async (req, res) => {
    try {
      const validationError = validateWebhookInput(req.body, { message: 4000 });
      if (validationError) return res.status(400).json({ error: validationError });

      const { message } = req.body;
      if (!message) {
        return res.status(400).json({ error: 'message 필수' });
      }

      const { success } = await notifyDiscord(message);
      res.json({ success });
    } catch (err) {
      console.error('Discord notify error:', err);
      res.status(500).json({ error: 'Discord 알림 중 오류' });
    }
  });

  // ===================== WEBHOOK: backup =====================

  app.get('/api/webhook/backup', requireDB, requireApiKey, async (req, res) => {
    const pool = getPool();
    try {
      const users = await pool.query('SELECT id, name, email, phone, role, password_is_temp, created_at, deleted_at FROM users ORDER BY id');
      const applications = await pool.query('SELECT * FROM applications ORDER BY id');
      const classPasses = await pool.query('SELECT * FROM class_passes ORDER BY id');
      const payments = await pool.query('SELECT * FROM payments ORDER BY id');
      const attendance = await pool.query('SELECT * FROM attendance ORDER BY id');
      const journalingSmsLog = await pool.query('SELECT * FROM journaling_sms_log ORDER BY id');
      const careSmsLog = await pool.query('SELECT * FROM care_sms_log ORDER BY id');
      const creditLogs = await pool.query('SELECT * FROM credit_logs ORDER BY id');
      const notificationLog = await pool.query('SELECT * FROM notification_log ORDER BY id');
      const auditLog = await pool.query('SELECT * FROM audit_log ORDER BY id');

      res.json({
        success: true,
        backup_date: new Date().toISOString(),
        data: {
          users: users.rows,
          applications: applications.rows,
          class_passes: classPasses.rows,
          payments: payments.rows,
          attendance: attendance.rows,
          journaling_sms_log: journalingSmsLog.rows,
          care_sms_log: careSmsLog.rows,
          credit_logs: creditLogs.rows,
          notification_log: notificationLog.rows,
          audit_log: auditLog.rows
        },
        counts: {
          users: users.rows.length,
          applications: applications.rows.length,
          class_passes: classPasses.rows.length,
          payments: payments.rows.length,
          attendance: attendance.rows.length,
          journaling_sms_log: journalingSmsLog.rows.length,
          care_sms_log: careSmsLog.rows.length,
          credit_logs: creditLogs.rows.length,
          notification_log: notificationLog.rows.length,
          audit_log: auditLog.rows.length
        }
      });
    } catch (err) {
      console.error('Backup API error:', err);
      res.status(500).json({ error: '백업 데이터 조회 중 오류가 발생했습니다' });
    }
  });

  // ===================== WEBHOOK: backup-to-github =====================

  app.post('/api/webhook/backup-to-github', requireDB, requireApiKey, async (req, res) => {
    try {
      const github_token = CONFIG.BACKUP_GITHUB_TOKEN;
      const repo_owner = CONFIG.BACKUP_GITHUB_OWNER;
      const repo_name = CONFIG.BACKUP_GITHUB_REPO;
      const branch = CONFIG.BACKUP_GITHUB_BRANCH || 'main';
      if (!github_token || !repo_owner || !repo_name) {
        return res.status(400).json({ error: 'GitHub 백업 환경변수가 설정되지 않았습니다 (BACKUP_GITHUB_TOKEN, BACKUP_GITHUB_OWNER, BACKUP_GITHUB_REPO)' });
      }

      const pool = getPool();
      const now = new Date();
      const kst = new Date(now.getTime() + 9 * 60 * 60 * 1000);
      const dateStr = kst.toISOString().slice(0, 10);

      // Gather backup data
      const users = await pool.query('SELECT id, name, email, phone, role, password_is_temp, created_at, deleted_at FROM users ORDER BY id');
      const applications = await pool.query('SELECT * FROM applications ORDER BY id');
      const classPasses = await pool.query('SELECT * FROM class_passes ORDER BY id');
      const payments = await pool.query('SELECT * FROM payments ORDER BY id');
      const attendance = await pool.query('SELECT * FROM attendance ORDER BY id');
      const journalingSmsLog = await pool.query('SELECT * FROM journaling_sms_log ORDER BY id');
      const careSmsLog = await pool.query('SELECT * FROM care_sms_log ORDER BY id');
      const creditLogs = await pool.query('SELECT * FROM credit_logs ORDER BY id');
      const notificationLog = await pool.query('SELECT * FROM notification_log ORDER BY id');
      const auditLog = await pool.query('SELECT * FROM audit_log ORDER BY id');

      const backupData = {
        backup_date: now.toISOString(),
        counts: {
          users: users.rows.length,
          applications: applications.rows.length,
          class_passes: classPasses.rows.length,
          payments: payments.rows.length,
          attendance: attendance.rows.length,
          journaling_sms_log: journalingSmsLog.rows.length,
          care_sms_log: careSmsLog.rows.length,
          credit_logs: creditLogs.rows.length,
          notification_log: notificationLog.rows.length,
          audit_log: auditLog.rows.length
        },
        data: {
          users: users.rows,
          applications: applications.rows,
          class_passes: classPasses.rows,
          payments: payments.rows,
          attendance: attendance.rows,
          journaling_sms_log: journalingSmsLog.rows,
          care_sms_log: careSmsLog.rows,
          credit_logs: creditLogs.rows,
          notification_log: notificationLog.rows,
          audit_log: auditLog.rows
        }
      };

      const contentBase64 = Buffer.from(JSON.stringify(backupData, null, 2)).toString('base64');
      const filePath = `backups/${dateStr}_db_backup.json`;

      // Check if file exists (to get SHA for update)
      let sha = null;
      try {
        const checkController = new AbortController();
        const checkTimeoutId = setTimeout(() => checkController.abort(), 15000);
        const checkResp = await fetch(`https://api.github.com/repos/${repo_owner}/${repo_name}/contents/${filePath}?ref=${branch}`, {
          headers: { 'Authorization': `token ${github_token}` },
          signal: checkController.signal
        });
        clearTimeout(checkTimeoutId);
        if (checkResp.ok) {
          const existing = await checkResp.json();
          sha = existing.sha;
        }
      } catch (e) { /* file doesn't exist yet or timeout */ }

      const payload = {
        message: `[자동백업] ${dateStr} DB 백업 (회원 ${users.rows.length}명, 결제 ${payments.rows.length}건)`,
        content: contentBase64,
        branch: branch
      };
      if (sha) payload.sha = sha;

      const putController = new AbortController();
      const putTimeoutId = setTimeout(() => putController.abort(), 15000);
      const ghResp = await fetch(`https://api.github.com/repos/${repo_owner}/${repo_name}/contents/${filePath}`, {
        method: 'PUT',
        headers: {
          'Authorization': `token ${github_token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload),
        signal: putController.signal
      });
      clearTimeout(putTimeoutId);

      const ghResult = await ghResp.json();
      res.json({
        success: ghResp.ok,
        file_path: filePath,
        commit_sha: ghResult.commit?.sha || null
      });
    } catch (err) {
      console.error('GitHub backup error:', err);
      res.status(500).json({ error: 'GitHub 백업 중 오류' });
    }
  });

  // ===================== WEBHOOK: active-members =====================

  app.get('/api/webhook/active-members', requireDB, requireApiKey, async (req, res) => {
    const pool = getPool();
    try {
      // recent_only=true: 최근 7일 이내 출석한 회원 + 신규가입 7일 이내 회원만
      const recentOnly = req.query.recent_only === 'true';
      let query = `
        SELECT u.id, u.name, u.phone, u.email,
          COALESCE(SUM(cp.remaining_classes), 0) as remaining_classes
        FROM users u
        JOIN class_passes cp ON cp.user_id = u.id AND cp.status = 'active' AND cp.remaining_classes > 0
        WHERE u.role = 'member'
      `;
      if (recentOnly) {
        query += `
          AND (
            EXISTS (SELECT 1 FROM attendance a WHERE a.user_id = u.id AND a.attended_at >= NOW() - INTERVAL '7 days')
            OR u.created_at >= NOW() - INTERVAL '7 days'
          )
        `;
      }
      query += `
        GROUP BY u.id, u.name, u.phone, u.email
        HAVING COALESCE(SUM(cp.remaining_classes), 0) > 0
      `;
      const result = await pool.query(query);
      res.json({ success: true, members: result.rows });
    } catch (err) {
      console.error('Active members API error:', err);
      res.status(500).json({ error: '서버 오류' });
    }
  });

  // ===================== WEBHOOK: zoom-token (프록시) =====================

  app.get('/api/webhook/zoom-token', requireApiKey, async (req, res) => {
    try {
      const token = await getZoomAccessToken();
      res.json({ success: true, access_token: token });
    } catch (err) {
      console.error('Zoom token proxy error:', err);
      res.status(500).json({ error: 'Zoom 토큰 발급 실패' });
    }
  });
};
