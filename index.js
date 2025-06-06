const crypto = require('crypto');
const http = require('http');

// 设置你的 GitHub Secret
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || 'your_secret_here';

// 允许的来源平台
const ALLOWED_USER_AGENTS = ['GitHub-Hookshot', 'Notion', 'WeChat'];

function verifySignature(req, body) {
    const signature = req.headers['x-hub-signature-256'];
    if (!signature) return false;
    const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET);
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
        if (!verifySignature(req, buffer)) {
            res.writeHead(403);
            return res.end('Forbidden: Invalid Signature');
        }

        console.log('[Webhook Payload]', buffer);  // 打印 payload 内容
        res.writeHead(200);
        res.end('Webhook received');
    });
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
    console.log(`Webhook listener running on port ${PORT}`);
});