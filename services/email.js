module.exports = function(CONFIG) {
  async function sendEmail(to, subject, html, { from, text, attachments } = {}) {
    const emailPayload = { from: from || '황준성 <junseong@junseonghwang.com>', to, subject };
    if (html) emailPayload.html = html;
    if (text) emailPayload.text = text;
    if (attachments && Array.isArray(attachments)) emailPayload.attachments = attachments;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${CONFIG.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(emailPayload),
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      const result = await response.json();
      const success = !!result.id;
      return { success, email_id: result.id, result };
    } catch (err) {
      clearTimeout(timeoutId);
      console.error('Email send error:', err.message);
      return { success: false, error: err.message };
    }
  }

  return { sendEmail };
};
