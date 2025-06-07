const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const net = require('net');

// Anti-drift port lock
const tester = net.createServer()
  .once('error', err => {
    if (err.code === 'EADDRINUSE') {
      console.error(`[FATAL] Port ${process.env.PORT} is already in use. Exiting to avoid PM2 ghost drift.`);
      process.exit(1);
    }
  })
  .once('listening', () => tester.close());

if (process.env.PORT) tester.listen(process.env.PORT);
// End anti-drift

// Forbid .env file usage, only allow PM2 injected variables
if (fs.existsSync('.env') || fs.existsSync('/home/ubuntu/project/.env')) {
  throw new Error('Do not use .env file! Only use PM2 ecosystem.config.js for environment variables.');
}
// End env check

const PORT = process.env.PORT;
const SECRET = process.env.WEBHOOK_SECRET;

if (!PORT || !SECRET) {
  throw new Error('Missing required environment variables: PORT and/or WEBHOOK_SECRET.');
}

const LOG_FILE = '/home/ubuntu/memory_shard.log';
const SIGNATURE_HEADER = 'x-hub-signature-256';

function isValidSignature(req, body) {
  const signature = req.headers[SIGNATURE_HEADER];
  if (!signature) return false;
  const hmac = crypto.createHmac('sha256', SECRET);
  const digest = 'sha256=' + hmac.update(body).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest));
}

const server = http.createServer((req, res) => {
  if (req.method !== 'POST') {
    res.writeHead(405);
    return res.end('Method Not Allowed');
  }

  let buffer = '';
  req.on('data', chunk => {
    buffer += chunk.toString();
  });

  req.on('end', () => {
    if (!isValidSignature(req, buffer)) {
      console.warn('[WARN] Invalid Signature');
      res.writeHead(403);
      return res.end('Forbidden');
    }

    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] ${buffer}\n`;

    fs.appendFile(LOG_FILE, logEntry, err => {
      if (err) {
        console.error('[ERROR] Failed to write log:', err);
        res.writeHead(500);
        return res.end('Internal Error');
      }
      console.log('[OK] Behavior logged');
      res.writeHead(200);
      res.end('OK');
    });
  });
});

server.listen(PORT, () => {
  console.log(`[READY] Listener running on port ${PORT}`);
});
