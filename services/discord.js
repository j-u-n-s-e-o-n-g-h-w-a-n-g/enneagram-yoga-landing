module.exports = function(CONFIG) {
  async function notifyDiscord(message) {
    const response = await fetch(CONFIG.DISCORD_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: message })
    });
    return { success: response.ok };
  }

  return { notifyDiscord };
};
