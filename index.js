const crypto = require('crypto');
const http = require('http');

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || 'your_secret_here';

function verifySignature(req, body) {
    const signature = req.headers['x-hub-signature-256'];
    if (!signature) return false;
    const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET);
    const digest = 'sha256=' + hmac.update(body).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest));
}

const server = http.createServer((req, res) => {
    // 只允许 POST /api/push
    if (req.method !== 'POST' || req.url !== '/api/push') {
        res.writeHead(404);
        return res.end('Not Found');
    }

    let buffer = '';
    req.on('data', chunk => {
        buffer += chunk.toString();
    });

    req.on('end', () => {
        // 如果需要校验签名
        // if (!verifySignature(req, buffer)) {
        //     res.writeHead(403);
        //     return res.end('Forbidden: Invalid Signature');
        // }
        console.log('[Webhook Payload]', buffer);
        res.writeHead(200);
        res.end('Webhook received');
    });
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
    console.log(`Webhook listener running on port ${PORT}`);
});
