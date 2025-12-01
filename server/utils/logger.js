const fs = require('fs');
const path = require('path');

const LOG_DIR = path.join(__dirname, '..', 'logs');
const LOG_FILE = path.join(LOG_DIR, 'security.log');

if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

async function log(eventType, message, meta = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    eventType,
    message,
    meta,
  };
  const line = JSON.stringify(entry) + '\n';
  try {
    await fs.promises.appendFile(LOG_FILE, line, { encoding: 'utf8' });
  } catch (err) {
    // Fallback to console.error if file write fails
    console.error('Failed to write security log:', err);
    console.log(line);
  }
}

module.exports = {
  log,
  LOG_FILE,
};
