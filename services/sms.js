const crypto = require('crypto');

module.exports = function(CONFIG) {
  async function sendSMS(phone, message) {
    const cleanPhone = phone.replace(/[-\s]/g, '');
    const date = new Date().toISOString();
    const salt = crypto.randomBytes(32).toString('hex');
    const signature = crypto.createHmac('sha256', CONFIG.SOLAPI_API_SECRET).update(date + salt).digest('hex');
    const authHeader = `HMAC-SHA256 apiKey=${CONFIG.SOLAPI_API_KEY}, date=${date}, salt=${salt}, signature=${signature}`;
    const msgType = message.length > 90 ? 'LMS' : 'SMS';
    const response = await fetch('https://api.solapi.com/messages/v4/send', {
      method: 'POST',
      headers: { 'Authorization': authHeader, 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: { to: cleanPhone, from: CONFIG.SOLAPI_SENDER, text: message, type: msgType } })
    });
    const result = await response.json();
    const success = result.statusCode === '2000' || !!result.groupId;
    return { success, groupId: result.groupId, statusCode: result.statusCode, result };
  }

  return { sendSMS };
};
