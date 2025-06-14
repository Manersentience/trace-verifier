const http = require('http');
const crypto = require('crypto');
const fs = require('fs');

const PORT = process.env.PORT;
const SECRET = process.env.WEBHOOK_SECRET;
const LOG_FILE = './memory_shard.log'; // <--- 只允许本地目录，不要写 /data!

if (!PORT || !SECRET) {
  throw new Error('Missing PORT or WEBHOOK_SECRET env variable');
}

const SIGNATURE_HEADER = 'x-hub-signature-256';

function isValidSignature(req, body) {
  const signature = req.headers[SIGNATURE_HEADER];
  if (!signature) return false;
  const hmac = crypto.createHmac('sha256', SECRET);
  const digest = hmac.update(body).digest('hex');
  const sigHex = signature.startsWith('sha256=') ? signature.slice(7) : signature;
  if (sigHex.length !== digest.length) return false;
  return crypto.timingSafeEqual(Buffer.from(sigHex, 'hex'), Buffer.from(digest, 'hex'));
}

const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/api/push') {
    let buffer = '';
    req.on('data', chunk => {
      buffer += chunk.toString();
    });
    req.on('end', () => {
      if (!isValidSignature(req, buffer)) {
        res.writeHead(403);
        return res.end('Forbidden');
      }
      const timestamp = new Date().toISOString();
      const logEntry = `[${timestamp}] ${buffer}\n`;
      fs.appendFile(LOG_FILE, logEntry, err => {
        if (err) {
          res.writeHead(500);
          return res.end('Internal Error');
        }
        res.writeHead(200);
        res.end('OK');
      });
    });
  } else {
    res.writeHead(404);
    res.end('Not Found');
  }
});

server.listen(PORT, () => {
  console.log(`[READY] Railway listener on port ${PORT}`);
});
