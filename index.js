const crypto = require('crypto');
const http = require('http');

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || 'your_secret_here';
const PORT = process.env.PORT || 8080;

function verifySignature(req, body) {
    const signature = req.headers['x-hub-signature-256'];
    if (!signature) {
        console.warn('?Missing x-hub-signature-256');
        return false;
    }

    const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET);
    const digest = 'sha256=' + hmac.update(body).digest('hex');

    if (process.env.DEBUG === 'true') {
        console.log('GitHub Signature:', signature);
        console.log('Computed Digest:', digest);
    }

    try {
        return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest));
    } catch (err) {
        return false;
    }
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
        // ?? ´¦Àí GitHub ping ÇëÇó
        if (req.headers['x-github-event'] === 'ping') {
            res.writeHead(200);
            return res.end('pong');
        }

        if (!verifySignature(req, buffer)) {
            res.writeHead(403);
            return res.end('Forbidden: Invalid Signature');
        }

        console.log('[Webhook Payload]', buffer);
        res.writeHead(200);
        res.end('Webhook received');
    });
});

server.listen(PORT, () => {
    console.log(`? Webhook listener running on port ${PORT}`);
});
