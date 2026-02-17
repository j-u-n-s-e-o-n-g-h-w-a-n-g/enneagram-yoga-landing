module.exports = function(CONFIG) {
  async function notifyDiscord(message) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(CONFIG.DISCORD_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: message }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      return { success: response.ok };
    } catch (err) {
      clearTimeout(timeoutId);
      console.error('Discord notify error:', err.message);
      return { success: false };
    }
  }

  return { notifyDiscord };
};
