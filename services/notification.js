module.exports = function() {
  async function logNotification(pool, userId, paymentId, type, status, detail) {
    try {
      await pool.query(
        'INSERT INTO notification_log (user_id, payment_id, type, status, detail) VALUES ($1, $2, $3, $4, $5)',
        [userId || null, paymentId || null, type, status, JSON.stringify(detail)]
      );
    } catch (err) { console.error('notification_log insert error:', err); }
  }

  return { logNotification };
};
