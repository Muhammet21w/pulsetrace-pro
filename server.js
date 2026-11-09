'use strict';

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

if (typeof fetch !== 'function') {
    console.error('FATAL: Node.js 18 veya üstü gerekli (fetch desteği yok).');
    process.exit(1);
}

const app = express();
const PORT = Number(process.env.PORT || 3000);
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
    if (IS_PRODUCTION) {
        console.error('FATAL: Production ortamında en az 32 karakterlik JWT_SECRET zorunludur.');
        process.exit(1);
    }
    console.warn('UYARI: JWT_SECRET ayarlanmamış veya kısa.');
}

const SIGNING_SECRET = JWT_SECRET || crypto.randomBytes(48).toString('hex');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'pulsetrace_enterprise.db');
const db = new Database(DB_PATH);
if (process.env.RENDER && !process.env.DB_PATH) {
    console.warn('[DB] Render ortamında DB_PATH tanımlı değil. Kalıcı disk bağlanmadıysa SQLite verileri deploy/restart sonrası kaybolabilir.');
}

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

// Render proxy IP bilgisini doğru almak için.
app.set('trust proxy', 1);

// =====================================================
// PAKETLER
// =====================================================

const PLANS = {
    free: {
        name: 'Free',
        amount: 0,
        errorLimit: 3000,
        projectLimit: 3
    },
    starter: {
        name: 'Starter',
        amount: 7990,
        errorLimit: 10000,
        projectLimit: 10
    },
    pro: {
        name: 'Pro',
        amount: 14990,
        errorLimit: 50000,
        projectLimit: 50
    }
};

const SUBSCRIPTION_DAYS = 30;

// =====================================================
// VERİTABANI MIGRATION SİSTEMİ
// =====================================================

function tableExists(table) {
    return Boolean(
        db.prepare(`
            SELECT name
            FROM sqlite_master
            WHERE type = 'table' AND name = ?
        `).get(table)
    );
}

function addColumnIfMissing(table, column, definition) {
    if (!tableExists(table)) {
        console.warn(`[DB MIGRATION] ${table} tablosu bulunamadı.`);
        return false;
    }

    const columns = db.prepare(`PRAGMA table_info("${table}")`).all();

    if (columns.some(col => col.name === column)) {
        return false;
    }

    db.exec(`ALTER TABLE "${table}" ADD COLUMN "${column}" ${definition}`);

    console.log(`[DB MIGRATION] ${table}.${column} eklendi.`);
    return true;
}

function backfillDateColumn(table, column) {
    if (!tableExists(table)) return;

    const columns = db.prepare(`PRAGMA table_info("${table}")`).all();

    if (!columns.some(col => col.name === column)) return;

    db.prepare(`
        UPDATE "${table}"
        SET "${column}" = CURRENT_TIMESTAMP
        WHERE "${column}" IS NULL OR "${column}" = ''
    `).run();
}

// =====================================================
// TABLOLAR
// =====================================================

db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    plan_type TEXT DEFAULT 'free',
    monthly_error_count INTEGER DEFAULT 0,
    error_limit INTEGER DEFAULT 3000,
    role TEXT DEFAULT 'user',
    trial_ends_at TEXT,
    subscription_ends_at TEXT,
    reset_code TEXT,
    reset_code_expires TEXT,
    reset_attempts INTEGER NOT NULL DEFAULT 0,
    reset_requested_at TEXT,
    usage_month TEXT,
    token_version INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS pending_registrations (
    email TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    otp_code TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT,
    device_hash TEXT
);

CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    name TEXT NOT NULL,
    api_key_hash TEXT UNIQUE NOT NULL,
    api_key_prefix TEXT NOT NULL,
    status TEXT DEFAULT 'Aktif',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    revoked_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER,
    level TEXT,
    status TEXT DEFAULT 'Aktif',
    message TEXT,
    stack TEXT,
    url TEXT,
    ip TEXT,
    browser TEXT,
    fingerprint TEXT,
    count INTEGER DEFAULT 1,
    affected_users INTEGER DEFAULT 0,
    first_seen TEXT,
    last_seen TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    environment TEXT,
    release TEXT,
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS error_clients (
    error_id INTEGER,
    client_uuid TEXT,
    PRIMARY KEY(error_id, client_uuid),
    FOREIGN KEY(error_id) REFERENCES errors(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS payment_notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    plan TEXT,
    amount TEXT,
    method TEXT,
    note TEXT,
    status TEXT DEFAULT 'Bekliyor',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS trial_claims (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    ip_hash TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS payment_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    merchant_oid TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    plan TEXT NOT NULL,
    amount_kurus INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    paid_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

// =====================================================
// EKSİK SÜTUNLARI TAMAMLAMA
// =====================================================

addColumnIfMissing('users', 'plan_type', "TEXT DEFAULT 'free'");
addColumnIfMissing('users', 'monthly_error_count', 'INTEGER DEFAULT 0');
addColumnIfMissing('users', 'error_limit', 'INTEGER DEFAULT 3000');
addColumnIfMissing('users', 'role', "TEXT DEFAULT 'user'");
addColumnIfMissing('users', 'trial_ends_at', 'TEXT');
addColumnIfMissing('users', 'subscription_ends_at', 'TEXT');
addColumnIfMissing('users', 'reset_code', 'TEXT');
addColumnIfMissing('users', 'reset_code_expires', 'TEXT');
addColumnIfMissing('users', 'reset_attempts', 'INTEGER NOT NULL DEFAULT 0');
addColumnIfMissing('users', 'reset_requested_at', 'TEXT');
addColumnIfMissing('users', 'usage_month', 'TEXT');
addColumnIfMissing('users', 'token_version', 'INTEGER NOT NULL DEFAULT 0');
addColumnIfMissing('users', 'created_at', 'TEXT');

addColumnIfMissing('pending_registrations', 'attempts', 'INTEGER NOT NULL DEFAULT 0');
addColumnIfMissing('pending_registrations', 'updated_at', 'TEXT');
addColumnIfMissing('pending_registrations', 'device_hash', 'TEXT');

addColumnIfMissing('projects', 'user_id', 'INTEGER');
addColumnIfMissing('projects', 'name', 'TEXT');
addColumnIfMissing('projects', 'api_key_hash', 'TEXT');
addColumnIfMissing('projects', 'api_key_prefix', 'TEXT');
addColumnIfMissing('projects', 'status', "TEXT DEFAULT 'Aktif'");
addColumnIfMissing('projects', 'created_at', 'TEXT');
addColumnIfMissing('projects', 'revoked_at', 'TEXT');

addColumnIfMissing('errors', 'project_id', 'INTEGER');
addColumnIfMissing('errors', 'level', 'TEXT');
addColumnIfMissing('errors', 'status', "TEXT DEFAULT 'Aktif'");
addColumnIfMissing('errors', 'message', 'TEXT');
addColumnIfMissing('errors', 'stack', 'TEXT');
addColumnIfMissing('errors', 'url', 'TEXT');
addColumnIfMissing('errors', 'ip', 'TEXT');
addColumnIfMissing('errors', 'browser', 'TEXT');
addColumnIfMissing('errors', 'fingerprint', 'TEXT');
addColumnIfMissing('errors', 'count', 'INTEGER DEFAULT 1');
addColumnIfMissing('errors', 'affected_users', 'INTEGER DEFAULT 0');
addColumnIfMissing('errors', 'first_seen', 'TEXT');
addColumnIfMissing('errors', 'last_seen', 'TEXT');
addColumnIfMissing('errors', 'timestamp', 'TEXT');
addColumnIfMissing('errors', 'environment', 'TEXT');
addColumnIfMissing('errors', 'release', 'TEXT');

addColumnIfMissing('error_clients', 'error_id', 'INTEGER');
addColumnIfMissing('error_clients', 'client_uuid', 'TEXT');

addColumnIfMissing('payment_notifications', 'user_id', 'INTEGER');
addColumnIfMissing('payment_notifications', 'plan', 'TEXT');
addColumnIfMissing('payment_notifications', 'amount', 'TEXT');
addColumnIfMissing('payment_notifications', 'method', 'TEXT');
addColumnIfMissing('payment_notifications', 'note', 'TEXT');
addColumnIfMissing('payment_notifications', 'status', "TEXT DEFAULT 'Bekliyor'");
addColumnIfMissing('payment_notifications', 'created_at', 'TEXT');

addColumnIfMissing('payment_orders', 'merchant_oid', 'TEXT');
addColumnIfMissing('payment_orders', 'user_id', 'INTEGER');
addColumnIfMissing('payment_orders', 'plan', 'TEXT');
addColumnIfMissing('payment_orders', 'amount_kurus', 'INTEGER');
addColumnIfMissing('payment_orders', 'status', "TEXT DEFAULT 'pending'");
addColumnIfMissing('payment_orders', 'created_at', 'TEXT');
addColumnIfMissing('payment_orders', 'paid_at', 'TEXT');

// =====================================================
// TARİH ALANLARI
// =====================================================

backfillDateColumn('users', 'created_at');
backfillDateColumn('projects', 'created_at');
backfillDateColumn('payment_notifications', 'created_at');
backfillDateColumn('errors', 'first_seen');
backfillDateColumn('errors', 'last_seen');
backfillDateColumn('errors', 'timestamp');

db.prepare(`
    UPDATE errors
    SET count = 1
    WHERE count IS NULL OR count < 1
`).run();

db.prepare(`
    UPDATE errors
    SET affected_users = 0
    WHERE affected_users IS NULL
`).run();

// =====================================================
// İNDEKSLER
// =====================================================

db.exec(`
CREATE INDEX IF NOT EXISTS idx_projects_user
ON projects(user_id);

CREATE INDEX IF NOT EXISTS idx_errors_project_last_seen
ON errors(project_id, last_seen);

CREATE INDEX IF NOT EXISTS idx_errors_fingerprint
ON errors(project_id, fingerprint);

CREATE INDEX IF NOT EXISTS idx_error_clients_client
ON error_clients(client_uuid);

CREATE INDEX IF NOT EXISTS idx_users_email
ON users(email);

CREATE INDEX IF NOT EXISTS idx_projects_revoked
ON projects(user_id, revoked_at);

CREATE INDEX IF NOT EXISTS idx_errors_status
ON errors(project_id, status);

CREATE INDEX IF NOT EXISTS idx_payment_orders_user
ON payment_orders(user_id);

CREATE INDEX IF NOT EXISTS idx_payment_orders_status
ON payment_orders(status);

CREATE UNIQUE INDEX IF NOT EXISTS idx_trial_claims_device
ON trial_claims(device_hash);
`);

console.log('[DB] Veritabanı ve migration kontrolleri tamamlandı.');

// =====================================================
// GÜVENLİK VE MIDDLEWARE
// =====================================================

app.disable('x-powered-by');

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

    if (IS_PRODUCTION) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }

    next();
});

function buildAllowedOrigins() {
    const list = new Set();
    const add = value => {
        if (!value) return;
        try { list.add(new URL(value.trim()).origin); } catch { /* yoksay */ }
    };
    add(process.env.PUBLIC_BASE_URL);
    add(process.env.RENDER_EXTERNAL_URL);
    (process.env.CORS_ORIGINS || '').split(',').forEach(add);
    return list;
}

const ALLOWED_ORIGINS = buildAllowedOrigins();

app.use(cors((req, callback) => {
    const origin = req.headers.origin;
    const base = {
        methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
    };

    // Origin yoksa (curl, sunucudan sunucuya) serbest.
    if (!origin) return callback(null, { ...base, origin: true });

    let parsed;
    try { parsed = new URL(origin); } catch { return callback(null, { ...base, origin: false }); }

    const sameOrigin = parsed.host === req.headers.host;
    const isLocalDev = !IS_PRODUCTION &&
        ['localhost', '127.0.0.1'].includes(parsed.hostname);

    if (sameOrigin || isLocalDev || ALLOWED_ORIGINS.has(parsed.origin)) {
        return callback(null, { ...base, origin: true });
    }

    // Hata fırlatmak yerine CORS başlığı vermeyiz; tarayıcı engeller.
    return callback(null, { ...base, origin: false });
}));

app.use(express.json({ limit: '256kb' }));

// PayTR callback form-urlencoded gönderir.
app.use(express.urlencoded({
    extended: false,
    limit: '32kb'
}));

// =====================================================
// RATE LIMIT
// =====================================================

const rateBuckets = new Map();

function rateLimit({
    windowMs = 60000,
    max = 30,
    keyFn = req => req.ip
} = {}) {
    return (req, res, next) => {
        const now = Date.now();
        const key = `${req.path}:${keyFn(req)}`;

        let item = rateBuckets.get(key);

        if (!item && rateBuckets.size > 50000) {
            for (const [bucketKey, bucket] of rateBuckets) {
                if (bucket.resetAt <= now) rateBuckets.delete(bucketKey);
                if (rateBuckets.size <= 40000) break;
            }
        }

        if (!item || item.resetAt <= now) {
            item = {
                count: 0,
                resetAt: now + windowMs
            };
        }

        item.count += 1;
        rateBuckets.set(key, item);

        if (item.count > max) {
            res.setHeader(
                'Retry-After',
                Math.ceil((item.resetAt - now) / 1000)
            );

            return res.status(429).json({
                success: false,
                message: 'Çok fazla istek gönderildi. Lütfen biraz bekleyin.'
            });
        }

        next();
    };
}

setInterval(() => {
    const now = Date.now();

    for (const [key, value] of rateBuckets) {
        if (value.resetAt <= now) {
            rateBuckets.delete(key);
        }
    }
}, 60000).unref();

// =====================================================
// YARDIMCI FONKSİYONLAR
// =====================================================

function cleanEmail(value) {
    return typeof value === 'string'
        ? value.trim().toLowerCase()
        : '';
}

function validEmail(email) {
    return email.length <= 254 &&
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function safeString(value, max = 4000) {
    return typeof value === 'string'
        ? value.trim().slice(0, max)
        : '';
}

function sha256(value) {
    return crypto.createHash('sha256')
        .update(value)
        .digest('hex');
}

function deviceHash(deviceId) {
    return crypto.createHmac('sha256', SIGNING_SECRET)
        .update(`trial-device:${deviceId}`)
        .digest('hex');
}

function otpHash(email, code, purpose) {
    return crypto.createHmac('sha256', SIGNING_SECRET)
        .update(`${purpose}:${email}:${code}`)
        .digest('hex');
}

function safeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') {
        return false;
    }

    const aa = Buffer.from(a);
    const bb = Buffer.from(b);

    return aa.length === bb.length &&
        crypto.timingSafeEqual(aa, bb);
}

function generateOtp() {
    return crypto.randomInt(100000, 1000000).toString();
}

function createApiKey() {
    return `pt_live_${crypto.randomBytes(32).toString('hex')}`;
}

function sendError(res, status, message) {
    return res.status(status).json({
        success: false,
        message
    });
}

function getClientIp(req) {
    let ip = req.ip || req.socket?.remoteAddress || '';

    if (ip.startsWith('::ffff:')) {
        ip = ip.substring(7);
    }

    if (ip === '::1') {
        ip = '127.0.0.1';
    }

    return ip;
}

function createMerchantOid() {
    return (
        'PT' +
        Date.now().toString(36).toUpperCase() +
        crypto.randomBytes(8).toString('hex').toUpperCase()
    );
}

function getPublicBaseUrl() {
    const configured = process.env.PUBLIC_BASE_URL;

    if (!configured) {
        throw new Error('PUBLIC_BASE_URL ortam değişkeni eksik.');
    }

    const parsed = new URL(configured);

    if (
        IS_PRODUCTION &&
        parsed.protocol !== 'https:'
    ) {
        throw new Error('Production ortamında PUBLIC_BASE_URL HTTPS olmalıdır.');
    }

    return parsed.origin;
}

// =====================================================
// BREVO E-POSTA SİSTEMİ
// =====================================================

const FREE_MAIL_DOMAINS = [
    'gmail.com', 'googlemail.com', 'yahoo.com', 'outlook.com',
    'hotmail.com', 'icloud.com', 'yandex.com', 'proton.me'
];

function getMailSender() {
    const email = (process.env.MAIL_FROM_EMAIL || '').trim();
    return {
        email,
        name: process.env.MAIL_FROM_NAME || 'PulseTrace Pro'
    };
}

function escapeHtmlServer(value) {
    return String(value).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
    })[c]);
}

function buildCodeEmail(title, intro, code, footer) {
    return `<!doctype html><html><body style="margin:0;padding:24px;background:#f4f6f8;font-family:Arial,Helvetica,sans-serif;">
<div style="max-width:480px;margin:auto;background:#ffffff;border-radius:10px;padding:28px;border:1px solid #e3e7eb;">
<h2 style="margin:0 0 12px;color:#111;">${escapeHtmlServer(title)}</h2>
<p style="color:#444;font-size:14px;line-height:1.5;">${escapeHtmlServer(intro)}</p>
<div style="font-size:32px;letter-spacing:8px;font-weight:bold;text-align:center;background:#f0fff6;border:1px dashed #00b04f;border-radius:8px;padding:16px;margin:20px 0;color:#006b30;">${escapeHtmlServer(code)}</div>
<p style="color:#777;font-size:12px;line-height:1.5;">${escapeHtmlServer(footer)}</p>
</div></body></html>`;
}

async function sendMail({ to, subject, text, html }) {
    const apiKey = process.env.BREVO_API_KEY;

    // Geliştirme ortamında anahtar yoksa kodu konsola yaz, akış test edilebilsin.
    if (!apiKey && !IS_PRODUCTION) {
        console.warn(`[MAIL-DEV] BREVO_API_KEY yok. E-posta gönderilmedi.\n  Alıcı: ${to}\n  Konu: ${subject}\n  İçerik: ${text}`);
        return { dev: true };
    }

    if (!apiKey) {
        throw new Error('BREVO_API_KEY tanımlı değil.');
    }

    const sender = getMailSender();

    if (!sender.email) {
        throw new Error('MAIL_FROM_EMAIL tanımlı değil. Brevo\'da doğrulanmış bir gönderen adresi girin.');
    }

    const payload = {
        sender: { email: sender.email, name: sender.name },
        to: [{ email: to }],
        subject,
        textContent: text
    };

    if (html) payload.htmlContent = html;

    let lastError;

    // Geçici ağ/5xx hatalarında 2 kez daha dene.
    for (let attempt = 1; attempt <= 3; attempt++) {
        try {
            const response = await fetch('https://api.brevo.com/v3/smtp/email', {
                method: 'POST',
                headers: {
                    accept: 'application/json',
                    'api-key': apiKey,
                    'content-type': 'application/json'
                },
                body: JSON.stringify(payload),
                signal: AbortSignal.timeout(15000)
            });

            const responseText = await response.text();
            let data = {};

            try { data = responseText ? JSON.parse(responseText) : {}; }
            catch { data = { message: responseText }; }

            if (response.ok) {
                console.log(`[MAIL] Gönderildi -> ${to} (messageId: ${data.messageId || '-'})`);
                return data;
            }

            const detail = `Brevo HTTP ${response.status} | code=${data.code || '-'} | ${data.message || responseText}`;
            const error = new Error(detail);
            error.status = response.status;

            // 4xx (kimlik, gönderen, IP yetkisi) tekrar denemekle düzelmez.
            if (response.status < 500 && response.status !== 429) throw error;

            lastError = error;
        } catch (err) {
            if (err.status && err.status < 500 && err.status !== 429) throw err;
            lastError = err;
        }

        await new Promise(resolve => setTimeout(resolve, attempt * 800));
    }

    throw lastError || new Error('Brevo bilinmeyen hata.');
}

// Sunucu açılırken Brevo ayarlarını kontrol edip nedenini loga yazar.
async function checkMailConfig() {
    const apiKey = process.env.BREVO_API_KEY;
    const sender = getMailSender();

    if (!apiKey) {
        console.warn('[MAIL-CHECK] BREVO_API_KEY tanımlı değil; e-posta gönderilemeyecek.');
        return;
    }

    if (!sender.email) {
        console.warn('[MAIL-CHECK] MAIL_FROM_EMAIL tanımlı değil; e-posta gönderilemeyecek.');
        return;
    }

    const senderDomain = sender.email.split('@')[1]?.toLowerCase();

    if (FREE_MAIL_DOMAINS.includes(senderDomain)) {
        console.warn(`[MAIL-CHECK] Gönderen adres ${senderDomain} gibi ücretsiz bir servise ait. Gmail/Yahoo DMARC kuralları nedeniyle bu adresle gönderilen e-postalar çoğunlukla spam'e düşer veya hiç ulaşmaz. Kendi alan adınızda bir gönderen kullanın.`);
    }

    try {
        const response = await fetch('https://api.brevo.com/v3/senders', {
            headers: { accept: 'application/json', 'api-key': apiKey },
            signal: AbortSignal.timeout(10000)
        });

        const data = await response.json().catch(() => ({}));

        if (response.status === 401) {
            console.error(`[MAIL-CHECK] Brevo 401: ${data.message || 'yetkisiz'}. API anahtarı yanlış olabilir veya Brevo > Security > Authorized IPs listesi bu sunucunun çıkış IP'sini engelliyor (Render'da IP değişkendir; "Deactivate blocking" seçeneğini kullanın).`);
            return;
        }

        if (!response.ok) {
            console.error(`[MAIL-CHECK] Brevo senders HTTP ${response.status}: ${data.message || ''}`);
            return;
        }

        const found = (data.senders || []).find(
            item => String(item.email).toLowerCase() === sender.email.toLowerCase()
        );

        if (!found) {
            console.error(`[MAIL-CHECK] ${sender.email} Brevo'da tanımlı gönderen DEĞİL. Brevo > Senders, Domains & Dedicated IPs bölümünden ekleyip doğrulayın.`);
        } else if (!found.active) {
            console.error(`[MAIL-CHECK] ${sender.email} Brevo'da var ama doğrulanmamış (aktif değil). Gelen 6 haneli kodla doğrulayın.`);
        } else {
            console.log(`[MAIL-CHECK] Brevo bağlantısı ve gönderen (${sender.email}) tamam.`);
        }
    } catch (err) {
        console.error('[MAIL-CHECK] Brevo kontrolü yapılamadı:', err.message);
    }
}

// =====================================================
// JWT OTURUM SİSTEMİ
// =====================================================

function getSubscriptionState(user) {
    const now = Date.now();
    const plan = String(user?.plan_type || '').toLowerCase();
    const expiryRaw = plan === 'free'
        ? user?.trial_ends_at
        : user?.subscription_ends_at;
    const expiry = expiryRaw ? Date.parse(expiryRaw) : NaN;
    const active = ['free', 'starter', 'pro'].includes(plan) &&
        Number.isFinite(expiry) && expiry > now;
    return {
        active,
        plan,
        expiry: Number.isFinite(expiry) ? new Date(expiry).toISOString() : null,
        expired: !active,
        isTrial: plan === 'free'
    };
}

function verifyJwtSession(req, res, next) {
    const authHeader = req.headers.authorization || '';
    if (!authHeader.startsWith('Bearer ')) {
        return sendError(res, 401, 'Oturum tokenı bulunamadı.');
    }
    try {
        const decoded = jwt.verify(authHeader.slice(7), SIGNING_SECRET, { issuer: 'pulsetrace-pro' });
        const user = db.prepare(`
            SELECT id, email, plan_type, monthly_error_count, error_limit, role,
                   trial_ends_at, subscription_ends_at, token_version
            FROM users WHERE id = ?
        `).get(decoded.userId);
        if (!user || Number(decoded.tokenVersion || 0) !== Number(user.token_version || 0)) {
            return sendError(res, 401, 'Oturum geçersiz. Lütfen tekrar giriş yapın.');
        }
        req.user = user;
        next();
    } catch {
        return sendError(res, 401, 'Oturum süresi doldu veya geçersiz token.');
    }
}

function requireActiveSubscription(req, res, next) {
    const state = getSubscriptionState(req.user);
    if (!state.active) {
        return res.status(402).json({
            success: false,
            code: 'SUBSCRIPTION_REQUIRED',
            message: state.isTrial
                ? '7 günlük deneme süreniz sona erdi. Devam etmek için Starter veya Pro paketi satın alın.'
                : 'Abonelik süreniz sona erdi. Devam etmek için paketinizi yenileyin.',
            subscriptionExpired: true,
            plan: state.plan,
            expiresAt: state.expiry
        });
    }
    next();
}

function issueToken(user) {
    return jwt.sign(
        {
            userId: user.id,
            email: user.email,
            tokenVersion: Number(user.token_version || 0)
        },
        SIGNING_SECRET,
        {
            expiresIn: '7d',
            issuer: 'pulsetrace-pro'
        }
    );
}

function resetMonthlyUsage(userId) {
    const month = new Date().toISOString().slice(0, 7);

    db.prepare(`
        UPDATE users
        SET monthly_error_count = 0, usage_month = ?
        WHERE id = ?
        AND (usage_month IS NULL OR usage_month <> ?)
    `).run(month, userId, month);
}

// =====================================================
// HEALTH CHECK
// =====================================================

app.get('/api/health', (req, res) => {
    try {
        db.prepare('SELECT 1').get();

        res.json({
            success: true,
            status: 'ok',
            timestamp: new Date().toISOString()
        });

    } catch (err) {
        console.error('Health check error:', err.message);
        sendError(res, 503, 'Veritabanı sağlık kontrolü başarısız.');
    }
});

// =====================================================
// KAYIT
// =====================================================

app.post(
    '/api/auth/register',
    rateLimit({ max: 10, windowMs: 15 * 60 * 1000 }),
    async (req, res) => {
        const email = cleanEmail(req.body?.email);

        const password = typeof req.body?.password === 'string'
            ? req.body.password
            : '';
        const deviceId = safeString(req.body?.deviceId, 100);
        if (!/^[a-f0-9]{64}$/i.test(deviceId)) {
            return sendError(res, 400, 'Cihaz doğrulama bilgisi geçersiz. Sayfayı yenileyip tekrar deneyin.');
        }
        const hashedDevice = deviceHash(deviceId);

        if (
            !validEmail(email) ||
            password.length < 10 ||
            password.length > 128
        ) {
            return sendError(
                res,
                400,
                'Geçerli e-posta girin. Şifre 10-128 karakter olmalıdır.'
            );
        }

        if (
            db.prepare('SELECT id FROM users WHERE email = ?').get(email)
        ) {
            return sendError(
                res,
                409,
                'Bu e-posta adresi zaten kullanımda.'
            );
        }

        // Aynı adrese art arda kod göndermeyi engelle (60 sn).
        const previous = db.prepare(`
            SELECT updated_at FROM pending_registrations WHERE email = ?
        `).get(email);

        if (previous?.updated_at) {
            const waitMs = 60000 - (Date.now() - Date.parse(previous.updated_at));
            if (waitMs > 0) {
                return sendError(
                    res,
                    429,
                    `Yeni kod istemek için ${Math.ceil(waitMs / 1000)} saniye bekleyin.`
                );
            }
        }

        const code = generateOtp();

        const expiresAt = new Date(
            Date.now() + 10 * 60 * 1000
        ).toISOString();

        try {
            const passwordHash = await bcrypt.hash(password, 12);

            db.prepare(`
                INSERT INTO pending_registrations (
                    email,
                    password_hash,
                    otp_code,
                    expires_at,
                    attempts,
                    updated_at,
                    device_hash
                )
                VALUES (?, ?, ?, ?, 0, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                    password_hash = excluded.password_hash,
                    otp_code = excluded.otp_code,
                    expires_at = excluded.expires_at,
                    attempts = 0,
                    updated_at = excluded.updated_at,
                    device_hash = excluded.device_hash
            `).run(
                email,
                passwordHash,
                otpHash(email, code, 'register'),
                expiresAt,
                new Date().toISOString(),
                hashedDevice
            );

            await sendMail({
                to: email,
                subject: 'PulseTrace Pro - Hesap doğrulama kodunuz',
                text: `PulseTrace Pro kayıt doğrulama kodunuz: ${code}. Kod 10 dakika geçerlidir.`,
                html: buildCodeEmail(
                    'Hesabınızı doğrulayın',
                    'PulseTrace Pro kaydınızı tamamlamak için aşağıdaki kodu girin.',
                    code,
                    'Kod 10 dakika geçerlidir. Bu işlemi siz başlatmadıysanız bu e-postayı yok sayabilirsiniz.'
                )
            });

            res.json({
                success: true,
                message: 'Doğrulama kodu e-posta adresinize gönderildi.'
            });

        } catch (err) {
            console.error('Register/mail error:', err.message);

            db.prepare(`
                DELETE FROM pending_registrations
                WHERE email = ?
            `).run(email);

            sendError(
                res,
                503,
                'E-posta gönderilemedi. Lütfen daha sonra tekrar deneyin.'
            );
        }
    }
);

// =====================================================
// KAYIT KODUNU TEKRAR GÖNDER
// =====================================================

app.post(
    '/api/auth/resend-otp',
    rateLimit({ max: 6, windowMs: 15 * 60 * 1000 }),
    async (req, res) => {
        const email = cleanEmail(req.body?.email);

        if (!validEmail(email)) {
            return sendError(res, 400, 'Geçerli bir e-posta girin.');
        }

        const pending = db.prepare(`
            SELECT email, updated_at FROM pending_registrations WHERE email = ?
        `).get(email);

        if (!pending) {
            return sendError(res, 400, 'Bekleyen kayıt bulunamadı. Lütfen baştan kayıt olun.');
        }

        const waitMs = 60000 - (Date.now() - Date.parse(pending.updated_at || 0));
        if (waitMs > 0) {
            return sendError(res, 429, `Yeni kod istemek için ${Math.ceil(waitMs / 1000)} saniye bekleyin.`);
        }

        const code = generateOtp();
        const now = new Date().toISOString();

        db.prepare(`
            UPDATE pending_registrations
            SET otp_code = ?, expires_at = ?, attempts = 0, updated_at = ?
            WHERE email = ?
        `).run(
            otpHash(email, code, 'register'),
            new Date(Date.now() + 10 * 60 * 1000).toISOString(),
            now,
            email
        );

        try {
            await sendMail({
                to: email,
                subject: 'PulseTrace Pro - Hesap doğrulama kodunuz',
                text: `PulseTrace Pro kayıt doğrulama kodunuz: ${code}. Kod 10 dakika geçerlidir.`,
                html: buildCodeEmail(
                    'Hesabınızı doğrulayın',
                    'PulseTrace Pro kaydınızı tamamlamak için aşağıdaki kodu girin.',
                    code,
                    'Kod 10 dakika geçerlidir.'
                )
            });

            res.json({ success: true, message: 'Yeni doğrulama kodu gönderildi.' });
        } catch (err) {
            console.error('Resend OTP mail error:', err.message);
            sendError(res, 503, 'E-posta gönderilemedi. Lütfen daha sonra tekrar deneyin.');
        }
    }
);

// =====================================================
// OTP DOĞRULAMA
// =====================================================

app.post(
    '/api/auth/verify-otp',
    rateLimit({ max: 10, windowMs: 10 * 60 * 1000 }),
    (req, res) => {
        const email = cleanEmail(req.body?.email);
        const code = safeString(req.body?.code, 6);

        if (!validEmail(email) || !/^\d{6}$/.test(code)) {
            return sendError(
                res,
                400,
                'E-posta ve 6 haneli kod gereklidir.'
            );
        }

        const pending = db.prepare(`
            SELECT *
            FROM pending_registrations
            WHERE email = ?
        `).get(email);

        if (!pending) {
            return sendError(
                res,
                400,
                'Kayıt isteği bulunamadı veya süresi doldu.'
            );
        }

        if (pending.attempts >= 5) {
            db.prepare(`
                DELETE FROM pending_registrations
                WHERE email = ?
            `).run(email);

            return sendError(
                res,
                429,
                'Çok fazla hatalı kod girildi. Yeniden kayıt isteği oluşturun.'
            );
        }

        if (Date.now() > Date.parse(pending.expires_at)) {
            db.prepare(`
                DELETE FROM pending_registrations
                WHERE email = ?
            `).run(email);

            return sendError(
                res,
                400,
                'Kodun süresi doldu. Yeniden kayıt olun.'
            );
        }

        if (
            !safeEqual(
                pending.otp_code,
                otpHash(email, code, 'register')
            )
        ) {
            db.prepare(`
                UPDATE pending_registrations
                SET attempts = attempts + 1
                WHERE email = ?
            `).run(email);

            return sendError(res, 400, 'Doğrulama kodu hatalı.');
        }

        try {
            const created = db.transaction(() => {
                if (!pending.device_hash) {
                    throw new Error('DEVICE_HASH_MISSING');
                }
                const claimed = db.prepare('SELECT user_id FROM trial_claims WHERE device_hash = ?').get(pending.device_hash);
                const trialGranted = !claimed;
                const result = db.prepare(`
                    INSERT INTO users (
                        email,
                        password_hash,
                        plan_type,
                        monthly_error_count,
                        error_limit,
                        role,
                        trial_ends_at,
                        usage_month
                    )
                    VALUES (?, ?, 'free', 0, 3000, 'user', ?, ?)
                `).run(
                    email,
                    pending.password_hash,
                    // Bu cihazda deneme daha önce kullanıldıysa hesap açılır ama deneme verilmez.
                    trialGranted
                        ? new Date(Date.now() + 7 * 86400000).toISOString()
                        : new Date(Date.now() - 1000).toISOString(),
                    new Date().toISOString().slice(0, 7)
                );

                const userId = Number(result.lastInsertRowid);
                if (trialGranted) {
                    db.prepare(`INSERT INTO trial_claims (device_hash, user_id, ip_hash) VALUES (?, ?, ?)`)
                        .run(pending.device_hash, userId, sha256(getClientIp(req) || 'unknown'));
                }
                const rawKey = createApiKey();

                db.prepare(`
                    INSERT INTO projects (
                        user_id,
                        name,
                        api_key_hash,
                        api_key_prefix
                    )
                    VALUES (?, ?, ?, ?)
                `).run(
                    userId,
                    'Varsayılan Proje',
                    sha256(rawKey),
                    `${rawKey.slice(0, 14)}...`
                );

                db.prepare(`
                    DELETE FROM pending_registrations
                    WHERE email = ?
                `).run(email);

                return {
                    id: userId,
                    rawApiKey: rawKey,
                    trialGranted
                };
            })();

            const user = db.prepare(`
                SELECT id, email, role, token_version
                FROM users
                WHERE id = ?
            `).get(created.id);

            res.json({
                success: true,
                token: issueToken(user),
                userId: user.id,
                email: user.email,
                role: user.role,
                rawApiKey: created.rawApiKey,
                trialGranted: created.trialGranted,
                message: created.trialGranted
                    ? 'Hesabınız oluşturuldu. API anahtarını şimdi güvenli bir yere kaydedin; tekrar gösterilmez.'
                    : 'Hesabınız oluşturuldu ancak bu cihazda deneme süresi daha önce kullanılmış. Devam etmek için paket satın alın.'
            });

        } catch (err) {
            if (String(err.message).includes('UNIQUE constraint failed: users.email')) {
                db.prepare('DELETE FROM pending_registrations WHERE email = ?').run(email);
                return sendError(res, 409, 'Bu e-posta adresi zaten kullanımda. Giriş yapın.');
            }
            console.error('OTP verification error:', err.message);
            sendError(res, 500, 'Hesap oluşturulamadı. Lütfen tekrar deneyin.');
        }
    }
);

// =====================================================
// GİRİŞ
// =====================================================

app.post(
    '/api/auth/login',
    rateLimit({ max: 10, windowMs: 15 * 60 * 1000 }),
    async (req, res) => {
        const email = cleanEmail(req.body?.email);

        const password = typeof req.body?.password === 'string'
            ? req.body.password
            : '';
        if (!validEmail(email) || !password) {
            return sendError(
                res,
                400,
                'E-posta ve şifre zorunludur.'
            );
        }

        const user = db.prepare(`
            SELECT *
            FROM users
            WHERE email = ?
        `).get(email);

        if (
            !user ||
            !(await bcrypt.compare(password, user.password_hash))
        ) {
            return sendError(
                res,
                401,
                'E-posta veya şifre hatalı.'
            );
        }

        resetMonthlyUsage(user.id);

        const freshUser = db.prepare(`
            SELECT
                id,
                email,
                role,
                token_version,
                plan_type,
                subscription_ends_at
            FROM users
            WHERE id = ?
        `).get(user.id);

        res.json({
            success: true,
            token: issueToken(freshUser),
            userId: freshUser.id,
            email: freshUser.email,
            role: freshUser.role,
            plan: freshUser.plan_type,
            subscriptionEndsAt: freshUser.subscription_ends_at
        });
    }
);

// =====================================================
// ŞİFRE SIFIRLAMA İSTEĞİ
// =====================================================

app.post(
    '/api/auth/forgot-password',
    rateLimit({ max: 5, windowMs: 15 * 60 * 1000 }),
    async (req, res) => {
        const email = cleanEmail(req.body?.email);

        if (!validEmail(email)) {
            return sendError(res, 400, 'Geçerli bir e-posta girin.');
        }

        const user = db.prepare(`
            SELECT id
            FROM users
            WHERE email = ?
        `).get(email);

        const genericMessage =
            'Eğer bu e-posta kayıtlıysa sıfırlama kodu gönderilmiştir.';

        if (!user) {
            return res.json({
                success: true,
                message: genericMessage
            });
        }

        // Aynı hesaba 60 sn içinde ikinci kod gönderme (mail kotası ve spam koruması).
        const lastRequest = db.prepare(`
            SELECT reset_requested_at FROM users WHERE id = ?
        `).get(user.id)?.reset_requested_at;

        if (lastRequest && Date.now() - Date.parse(lastRequest) < 60000) {
            return sendError(res, 429, 'Yeni kod istemeden önce lütfen 1 dakika bekleyin. Önceki kod hâlâ geçerli.');
        }

        const code = generateOtp();

        const expires = new Date(
            Date.now() + 15 * 60 * 1000
        ).toISOString();

        db.prepare(`
            UPDATE users
            SET reset_code = ?, reset_code_expires = ?, reset_attempts = 0, reset_requested_at = ?
            WHERE id = ?
        `).run(
            otpHash(email, code, 'reset'),
            expires,
            new Date().toISOString(),
            user.id
        );

        try {
            await sendMail({
                to: email,
                subject: 'PulseTrace Pro - Şifre sıfırlama kodunuz',
                text: `Şifre sıfırlama kodunuz: ${code}. Kod 15 dakika geçerlidir.`,
                html: buildCodeEmail(
                    'Şifre sıfırlama',
                    'Şifrenizi sıfırlamak için aşağıdaki kodu kullanın.',
                    code,
                    'Kod 15 dakika geçerlidir. Bu isteği siz yapmadıysanız bu e-postayı yok sayın; şifreniz değişmez.'
                )
            });

            res.json({
                success: true,
                message: genericMessage
            });

        } catch (err) {
            console.error('Reset mail error:', err.message);

            db.prepare(`
                UPDATE users
                SET reset_code = NULL, reset_code_expires = NULL, reset_requested_at = NULL
                WHERE id = ?
            `).run(user.id);

            sendError(
                res,
                503,
                'Şifre sıfırlama e-postası gönderilemedi. Lütfen daha sonra tekrar deneyin.'
            );
        }
    }
);

// =====================================================
// YENİ ŞİFREYİ KAYDET
// =====================================================

app.post(
    '/api/auth/reset-password',
    rateLimit({ max: 15, windowMs: 15 * 60 * 1000 }),
    async (req, res) => {
        const email = cleanEmail(req.body?.email);
        const code = safeString(req.body?.code, 6);

        const newPassword =
            typeof req.body?.newPassword === 'string'
                ? req.body.newPassword
                : '';

        if (
            !validEmail(email) ||
            !/^\d{6}$/.test(code) ||
            newPassword.length < 10 ||
            newPassword.length > 128
        ) {
            return sendError(
                res,
                400,
                'E-posta, 6 haneli kod ve en az 10 karakterlik yeni şifre gereklidir.'
            );
        }

        const user = db.prepare(`
            SELECT id, reset_code, reset_code_expires, reset_attempts
            FROM users
            WHERE email = ?
        `).get(email);

        if (
            !user ||
            !user.reset_code ||
            !user.reset_code_expires ||
            Date.now() > Date.parse(user.reset_code_expires)
        ) {
            return sendError(
                res,
                400,
                'Kod geçersiz veya süresi dolmuş. Yeni kod isteyin.'
            );
        }

        if (Number(user.reset_attempts || 0) >= 5) {
            db.prepare(`
                UPDATE users SET reset_code = NULL, reset_code_expires = NULL, reset_attempts = 0
                WHERE id = ?
            `).run(user.id);

            return sendError(res, 429, 'Çok fazla hatalı deneme. Yeni sıfırlama kodu isteyin.');
        }

        if (!safeEqual(user.reset_code, otpHash(email, code, 'reset'))) {
            db.prepare(`
                UPDATE users SET reset_attempts = reset_attempts + 1 WHERE id = ?
            `).run(user.id);

            return sendError(res, 400, 'Kod hatalı.');
        }

        try {
            const hash = await bcrypt.hash(newPassword, 12);

            db.prepare(`
                UPDATE users
                SET
                    password_hash = ?,
                    reset_code = NULL,
                    reset_code_expires = NULL,
                    reset_attempts = 0,
                    token_version = token_version + 1
                WHERE id = ?
            `).run(hash, user.id);

            res.json({
                success: true,
                message: 'Şifreniz değiştirildi. Güvenlik için yeniden giriş yapın.'
            });

        } catch (err) {
            console.error('Password reset error:', err.message);
            sendError(res, 500, 'Şifre güncellenemedi.');
        }
    }
);

// =====================================================
// ÖDEME PAKETLERİNİ LİSTELE
// =====================================================

app.get('/api/payments/plans', (req, res) => {
    res.json({
        success: true,
        currency: 'TRY',
        plans: [
            {
                id: 'starter',
                name: 'Starter',
                price: 79.90,
                period: '30 gün',
                projectLimit: PLANS.starter.projectLimit,
                errorLimit: PLANS.starter.errorLimit
            },
            {
                id: 'pro',
                name: 'Pro',
                price: 149.90,
                period: '30 gün',
                projectLimit: PLANS.pro.projectLimit,
                errorLimit: PLANS.pro.errorLimit
            }
        ]
    });
});

// =====================================================
// PAYTR ÖDEME BAŞLAT
// =====================================================

app.post(
    '/api/payments/create',
    verifyJwtSession,
    rateLimit({ max: 5, windowMs: 10 * 60 * 1000 }),
    async (req, res) => {
        let createdMerchantOid = null;
        try {
            const planId = safeString(req.body?.plan, 20).toLowerCase();

            if (!['starter', 'pro'].includes(planId)) {
                return sendError(
                    res,
                    400,
                    'Geçersiz paket seçimi.'
                );
            }

            const plan = PLANS[planId];

            const merchantId = process.env.PAYTR_MERCHANT_ID;
            const merchantKey = process.env.PAYTR_MERCHANT_KEY;
            const merchantSalt = process.env.PAYTR_MERCHANT_SALT;

            if (!merchantId || !merchantKey || !merchantSalt) {
                console.error('PayTR ortam değişkenleri eksik.');

                return sendError(
                    res,
                    503,
                    'Ödeme sistemi henüz yapılandırılmamış.'
                );
            }

            const email = req.user.email;
            const userName = safeString(req.body?.userName, 60);
            const userAddress = safeString(req.body?.userAddress, 400);
            const userPhone = safeString(req.body?.userPhone, 20);

            const normalizedPhone = userPhone.replace(/\D/g, '');
            if (!userName || !userAddress || normalizedPhone.length < 10 || normalizedPhone.length > 15) {
                return sendError(res, 400, 'Ödeme için ad soyad, adres ve 10-15 haneli telefon numarası gereklidir.');
            }

            if (!validEmail(email) || email.length > 100) {
                return sendError(
                    res,
                    400,
                    'Hesap e-posta adresi PayTR için geçersiz.'
                );
            }

            const userIp = getClientIp(req);

            if (!userIp) {
                return sendError(
                    res,
                    400,
                    'Kullanıcı IP adresi alınamadı.'
                );
            }

            const merchantOid = createMerchantOid();
            createdMerchantOid = merchantOid;
            const paymentAmount = String(plan.amount);

            const basket = [
                [
                    `PulseTrace Pro ${plan.name} - 30 Gun`,
                    (plan.amount / 100).toFixed(2),
                    1
                ]
            ];

            const userBasket = Buffer
                .from(JSON.stringify(basket))
                .toString('base64');

            const noInstallment = '1';
            const maxInstallment = '0';
            const currency = 'TL';

            const testMode =
                process.env.PAYTR_TEST_MODE === '1'
                    ? '1'
                    : '0';

            const baseUrl = getPublicBaseUrl();

            const successUrl = `${baseUrl}/?payment=success`;
            const failUrl = `${baseUrl}/?payment=failed`;

            const hashString =
                merchantId +
                userIp +
                merchantOid +
                email +
                paymentAmount +
                userBasket +
                noInstallment +
                maxInstallment +
                currency +
                testMode;

            const paytrToken = crypto
                .createHmac('sha256', merchantKey)
                .update(hashString + merchantSalt)
                .digest('base64');

            const formData = new URLSearchParams();

            formData.append('merchant_id', merchantId);
            formData.append('user_ip', userIp);
            formData.append('merchant_oid', merchantOid);
            formData.append('email', email);
            formData.append('payment_amount', paymentAmount);
            formData.append('paytr_token', paytrToken);
            formData.append('user_basket', userBasket);
            formData.append('debug_on', testMode === '1' ? '1' : '0');
            formData.append('no_installment', noInstallment);
            formData.append('max_installment', maxInstallment);
            formData.append('user_name', userName);
            formData.append('user_address', userAddress);
            formData.append('user_phone', normalizedPhone);
            formData.append('merchant_ok_url', successUrl);
            formData.append('merchant_fail_url', failUrl);
            formData.append('timeout_limit', '30');
            formData.append('currency', currency);
            formData.append('test_mode', testMode);
            formData.append('lang', 'tr');

            db.prepare(`
                INSERT INTO payment_orders (
                    merchant_oid,
                    user_id,
                    plan,
                    amount_kurus,
                    status
                )
                VALUES (?, ?, ?, ?, 'pending')
            `).run(
                merchantOid,
                req.user.id,
                planId,
                plan.amount
            );

            const response = await fetch(
                'https://www.paytr.com/odeme/api/get-token',
                {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: formData.toString(),
                    signal: AbortSignal.timeout(20000)
                }
            );

            const responseText = await response.text();

            let paytrResponse;

            try {
                paytrResponse = JSON.parse(responseText);
            } catch {
                throw new Error('PayTR geçersiz yanıt döndürdü.');
            }

            if (
                !response.ok ||
                paytrResponse.status !== 'success' ||
                !paytrResponse.token
            ) {
                console.error(
                    'PayTR token error:',
                    paytrResponse.reason || responseText
                );

                db.prepare(`
                    UPDATE payment_orders
                    SET status = 'token_failed'
                    WHERE merchant_oid = ?
                    AND status = 'pending'
                `).run(merchantOid);

                return sendError(
                    res,
                    502,
                    paytrResponse.reason ||
                    'PayTR ödeme oturumu oluşturulamadı.'
                );
            }

            res.json({
                success: true,
                merchantOid,
                plan: planId,
                amount: (plan.amount / 100).toFixed(2),
                currency: 'TRY',
                token: paytrResponse.token,
                iframeUrl:
                    `https://www.paytr.com/odeme/guvenli/${encodeURIComponent(paytrResponse.token)}`
            });

        } catch (err) {
            console.error('Payment create error:', err.message);
            if (createdMerchantOid) {
                try { db.prepare(`UPDATE payment_orders SET status = 'token_failed' WHERE merchant_oid = ? AND status = 'pending'`).run(createdMerchantOid); } catch {}
            }
            sendError(
                res,
                500,
                'Ödeme başlatılamadı. Lütfen tekrar deneyin.'
            );
        }
    }
);

// =====================================================
// PAYTR ÖDEME BİLDİRİMİ / CALLBACK
// =====================================================

app.post(
    '/api/payments/paytr-callback',
    rateLimit({ max: 120, windowMs: 60000 }),
    (req, res) => {
        try {
            const merchantKey = process.env.PAYTR_MERCHANT_KEY;
            const merchantSalt = process.env.PAYTR_MERCHANT_SALT;

            if (!merchantKey || !merchantSalt) {
                console.error('PayTR callback anahtarları eksik.');
                return res.status(500).send('ERROR');
            }

            const merchantOid = safeString(
                req.body?.merchant_oid,
                100
            );

            const status = safeString(
                req.body?.status,
                20
            );

            const totalAmount = safeString(
                req.body?.total_amount,
                30
            );

            const receivedHash = safeString(
                req.body?.hash,
                200
            );

            if (
                !merchantOid ||
                !status ||
                !totalAmount ||
                !receivedHash
            ) {
                console.error('PayTR callback eksik alan içeriyor.');
                return res.status(400).send('ERROR');
            }

            const hashString =
                merchantOid +
                merchantSalt +
                status +
                totalAmount;

            const calculatedHash = crypto
                .createHmac('sha256', merchantKey)
                .update(hashString)
                .digest('base64');

            if (!safeEqual(calculatedHash, receivedHash)) {
                console.error(
                    'PayTR callback hash doğrulaması başarısız:',
                    merchantOid
                );

                return res.status(400).send('ERROR');
            }

            const order = db.prepare(`
                SELECT *
                FROM payment_orders
                WHERE merchant_oid = ?
            `).get(merchantOid);

            if (!order) {
                console.error(
                    'PayTR callback siparişi bulunamadı:',
                    merchantOid
                );
                return res.status(200).send('OK');
            }

            if (order.status !== 'pending') {
                return res.status(200).send('OK');
            }

            const receivedAmount = Number(totalAmount);

            if (
                !Number.isSafeInteger(receivedAmount) ||
                receivedAmount !== Number(order.amount_kurus)
            ) {
                db.prepare(`
                    UPDATE payment_orders
                    SET status = 'amount_mismatch'
                    WHERE merchant_oid = ?
                    AND status = 'pending'
                `).run(merchantOid);

                return res.status(200).send('OK');
            }

            if (status !== 'success') {
                db.prepare(`
                    UPDATE payment_orders
                    SET status = 'failed'
                    WHERE merchant_oid = ?
                    AND status = 'pending'
                `).run(merchantOid);

                return res.status(200).send('OK');
            }

            const plan = PLANS[order.plan];

            if (!plan || !['starter', 'pro'].includes(order.plan)) {
                db.prepare(`
                    UPDATE payment_orders
                    SET status = 'invalid_plan'
                    WHERE merchant_oid = ?
                `).run(merchantOid);

                return res.status(200).send('OK');
            }

            const now = new Date();

            const subscription = db.prepare(`
                SELECT subscription_ends_at
                FROM users
                WHERE id = ?
            `).get(order.user_id);

            if (!subscription) {
                db.prepare(`
                    UPDATE payment_orders
                    SET status = 'user_missing'
                    WHERE merchant_oid = ?
                `).run(merchantOid);

                return res.status(200).send('OK');
            }

            const currentExpiry = subscription.subscription_ends_at
                ? Date.parse(subscription.subscription_ends_at)
                : 0;

            const startTime =
                Number.isFinite(currentExpiry) &&
                currentExpiry > now.getTime()
                    ? currentExpiry
                    : now.getTime();

            const newExpiry = new Date(
                startTime + SUBSCRIPTION_DAYS * 24 * 60 * 60 * 1000
            ).toISOString();

            db.transaction(() => {
                const updateOrder = db.prepare(`
                    UPDATE payment_orders
                    SET
                        status = 'paid',
                        paid_at = ?
                    WHERE merchant_oid = ?
                    AND status = 'pending'
                `).run(
                    now.toISOString(),
                    merchantOid
                );

                if (!updateOrder.changes) {
                    return;
                }

                db.prepare(`
                    UPDATE users
                    SET
                        plan_type = ?,
                        error_limit = ?,
                        subscription_ends_at = ?
                    WHERE id = ?
                `).run(
                    order.plan,
                    plan.errorLimit,
                    newExpiry,
                    order.user_id
                );
            })();

            console.log(
                `[PAYTR] Ödeme başarılı. Kullanıcı: ${order.user_id}, Paket: ${order.plan}, Bitiş: ${newExpiry}`
            );

            return res.status(200).send('OK');

        } catch (err) {
            console.error(
                'PayTR callback error:',
                err.message
            );

            return res.status(500).send('ERROR');
        }
    }
);

// =====================================================
// KULLANICI PAKET BİLGİLERİ
// =====================================================

app.get(
    '/api/user/subscription',
    verifyJwtSession,
    (req, res) => {
        resetMonthlyUsage(req.user.id);

        const user = db.prepare(`
            SELECT
                email,
                plan_type,
                monthly_error_count,
                error_limit,
                role,
                trial_ends_at,
                subscription_ends_at
            FROM users
            WHERE id = ?
        `).get(req.user.id);

        const state = getSubscriptionState(user);
        const remainingMs = state.expiry ? Math.max(0, Date.parse(state.expiry) - Date.now()) : 0;
        const trialExpired = user.plan_type === 'free' && !state.active;
        const subscriptionExpired = ['starter', 'pro'].includes(user.plan_type) && !state.active;

        res.json({
            ...user,
            accessActive: state.active,
            accessExpired: !state.active,
            accessEndsAt: state.expiry,
            daysRemaining: Math.ceil(remainingMs / 86400000),
            subscriptionExpired,
            trialExpired,
            subscriptionMessage: state.active
                ? (state.isTrial ? '7 günlük deneme süreniz devam ediyor.' : 'Aboneliğiniz aktif.')
                : (trialExpired ? 'Deneme süreniz sona erdi. Devam etmek için paket satın alın.' : 'Aboneliğiniz sona erdi. Yenileme yapmanız gerekiyor.'),
            plans: {
                free: {
                    price: 0,
                    projectLimit: PLANS.free.projectLimit,
                    errorLimit: PLANS.free.errorLimit
                },
                starter: {
                    price: 79.90,
                    projectLimit: PLANS.starter.projectLimit,
                    errorLimit: PLANS.starter.errorLimit
                },
                pro: {
                    price: 149.90,
                    projectLimit: PLANS.pro.projectLimit,
                    errorLimit: PLANS.pro.errorLimit
                }
            }
        });
    }
);

// =====================================================
// PROJELERİ LİSTELE
// =====================================================

app.get('/api/projects', verifyJwtSession, requireActiveSubscription, (req, res) => {
    try {
        const projects = db.prepare(`
            SELECT
                id,
                name,
                api_key_prefix AS apiKey,
                status,
                created_at
            FROM projects
            WHERE user_id = ?
            AND revoked_at IS NULL
            ORDER BY id DESC
        `).all(req.user.id);

        res.json(projects);

    } catch (err) {
        console.error('Project list error:', err.message);
        sendError(res, 500, 'Projeler listelenemedi.');
    }
});

// =====================================================
// PROJE OLUŞTUR
// =====================================================

app.post('/api/projects', verifyJwtSession, requireActiveSubscription, (req, res) => {
    const name = safeString(req.body?.name, 80);
    if (!name) return sendError(res, 400, 'Proje adı zorunludur.');
    try {
        const created = db.transaction(() => {
            const projectCount = db.prepare(`
                SELECT COUNT(*) AS n FROM projects
                WHERE user_id = ? AND revoked_at IS NULL
            `).get(req.user.id).n;
            const plan = PLANS[req.user.plan_type];
            if (!plan) throw new Error('INVALID_PLAN');
            if (projectCount >= plan.projectLimit) throw new Error('PROJECT_LIMIT');
            const rawKey = createApiKey();
            const result = db.prepare(`
                INSERT INTO projects (user_id, name, api_key_hash, api_key_prefix, status, created_at)
                VALUES (?, ?, ?, ?, 'Aktif', CURRENT_TIMESTAMP)
            `).run(req.user.id, name, sha256(rawKey), `${rawKey.slice(0, 14)}...`);
            return { id: Number(result.lastInsertRowid), rawKey };
        })();
        res.status(201).json({
            success: true,
            project: { id: created.id, name, apiKey: created.rawKey, status: 'Aktif', created_at: new Date().toISOString() },
            warning: 'Bu API anahtarı yalnızca şimdi gösterilir. Güvenli biçimde saklayın.'
        });
    } catch (err) {
        if (err.message === 'PROJECT_LIMIT') {
            const plan = PLANS[req.user.plan_type] || PLANS.free;
            return sendError(res, 403, `Paketiniz en fazla ${plan.projectLimit} proje oluşturabilir.`);
        }
        console.error('Project create error:', err.message);
        sendError(res, 500, 'Proje oluşturulamadı.');
    }
});

// =====================================================
// API ANAHTARI YENİLE
// =====================================================

app.post(
    '/api/projects/:id/rotate-key',
    verifyJwtSession,
    requireActiveSubscription,
    (req, res) => {
        const projectId = Number(req.params.id);

        if (!Number.isSafeInteger(projectId) || projectId <= 0) {
            return sendError(res, 400, 'Geçersiz proje ID.');
        }

        try {
            const project = db.prepare(`
                SELECT id
                FROM projects
                WHERE id = ?
                AND user_id = ?
                AND revoked_at IS NULL
            `).get(projectId, req.user.id);

            if (!project) {
                return sendError(res, 404, 'Proje bulunamadı.');
            }

            const rawKey = createApiKey();

            db.prepare(`
                UPDATE projects
                SET api_key_hash = ?, api_key_prefix = ?
                WHERE id = ?
                AND user_id = ?
            `).run(
                sha256(rawKey),
                `${rawKey.slice(0, 14)}...`,
                projectId,
                req.user.id
            );

            res.json({
                success: true,
                apiKey: rawKey,
                message: 'Yeni anahtar oluşturuldu. Eski anahtar artık geçersiz.'
            });

        } catch (err) {
            console.error('Project key rotation error:', err.message);
            sendError(res, 500, 'API anahtarı yenilenemedi.');
        }
    }
);

// =====================================================
// PROJE SİL / PASİFLEŞTİR
// =====================================================

app.delete(
    '/api/projects/:id',
    verifyJwtSession,
    requireActiveSubscription,
    (req, res) => {
        const projectId = Number(req.params.id);

        if (!Number.isSafeInteger(projectId) || projectId <= 0) {
            return sendError(res, 400, 'Geçersiz proje ID.');
        }

        try {
            const result = db.prepare(`
                UPDATE projects
                SET revoked_at = ?, status = ?
                WHERE id = ?
                AND user_id = ?
                AND revoked_at IS NULL
            `).run(
                new Date().toISOString(),
                'Pasif',
                projectId,
                req.user.id
            );

            if (!result.changes) {
                return sendError(res, 404, 'Proje bulunamadı.');
            }

            res.json({ success: true });

        } catch (err) {
            console.error('Project delete error:', err.message);
            sendError(res, 500, 'Proje silinemedi.');
        }
    }
);

// =====================================================
// HARİCİ UYGULAMALARDAN HATA ALMA
// =====================================================

app.post(
    '/api/errors',
    rateLimit({ max: 120, windowMs: 60000 }),
    (req, res) => {
        const rawKey = safeString(
            req.get('x-api-key') ||
            (req.get('authorization') || '')
                .replace(/^Bearer\s+/i, ''),
            200
        );

        if (!rawKey.startsWith('pt_live_')) {
            return sendError(res, 401, 'Proje API anahtarı gerekli.');
        }

        try {
            const project = db.prepare(`
                SELECT
                    p.id,
                    p.user_id,
                    p.status,
                    p.revoked_at,
                    u.error_limit,
                    u.monthly_error_count,
                    u.usage_month,
                    u.plan_type,
                    u.trial_ends_at,
                    u.subscription_ends_at
                FROM projects p
                JOIN users u ON u.id = p.user_id
                WHERE p.api_key_hash = ?
            `).get(sha256(rawKey));

            if (
                !project ||
                project.revoked_at ||
                project.status !== 'Aktif'
            ) {
                return sendError(
                    res,
                    401,
                    'API anahtarı geçersiz veya iptal edilmiş.'
                );
            }

            const entitlement = getSubscriptionState(project);
            if (!entitlement.active) {
                return res.status(402).json({
                    success: false,
                    code: 'SUBSCRIPTION_REQUIRED',
                    message: 'Deneme veya abonelik süresi sona erdi. Hata gönderimi için paket satın alın.',
                    subscriptionExpired: true
                });
            }

            resetMonthlyUsage(project.user_id);

            const message = safeString(
                req.body?.message,
                4000
            );

            if (!message) {
                return sendError(
                    res,
                    400,
                    'message alanı zorunludur.'
                );
            }

            const stack = safeString(
                req.body?.stack || req.body?.stackTrace,
                12000
            );

            const url = safeString(req.body?.url, 2000);

            const levelInput = safeString(
                req.body?.level || 'error',
                20
            ).toLowerCase();

            const level = [
                'fatal',
                'critical',
                'error',
                'warning',
                'info'
            ].includes(levelInput)
                ? (
                    ['fatal', 'critical'].includes(levelInput)
                        ? 'Kritik'
                        : levelInput === 'warning'
                            ? 'Uyari'
                            : 'Hata'
                )
                : 'Hata';

            const environment = safeString(
                req.body?.environment || 'production',
                40
            );

            const release = safeString(
                req.body?.release,
                100
            );

            const clientUuid = safeString(
                req.body?.userId ||
                req.body?.user_id ||
                req.body?.clientId ||
                '',
                128
            );

            const browser = safeString(
                req.body?.browser || req.get('user-agent') || '',
                500
            );

            const ip = safeString(req.ip || '', 64);

            const fingerprint = sha256(
                `${project.id}|${message}|${stack.split('\n')[0]}|${url}`
            ).slice(0, 48);

            const now = new Date().toISOString();

            const result = db.transaction(() => {
                const quotaUpdate = db.prepare(`
                    UPDATE users
                    SET monthly_error_count = monthly_error_count + 1
                    WHERE id = ? AND monthly_error_count < error_limit
                `).run(project.user_id);
                if (!quotaUpdate.changes) throw new Error('QUOTA_EXCEEDED');

                const existing = db.prepare(`
                    SELECT id
                    FROM errors
                    WHERE project_id = ?
                    AND fingerprint = ?
                    AND status = 'Aktif'
                `).get(project.id, fingerprint);

                let errorId;

                if (existing) {
                    errorId = existing.id;

                    db.prepare(`
                        UPDATE errors
                        SET
                            count = count + 1,
                            last_seen = ?,
                            level = ?,
                            message = ?,
                            stack = ?,
                            url = ?,
                            ip = ?,
                            browser = ?,
                            environment = ?,
                            release = ?
                        WHERE id = ?
                    `).run(
                        now,
                        level,
                        message,
                        stack,
                        url,
                        ip,
                        browser,
                        environment,
                        release,
                        errorId
                    );

                } else {
                    const inserted = db.prepare(`
                        INSERT INTO errors (
                            project_id,
                            level,
                            status,
                            message,
                            stack,
                            url,
                            ip,
                            browser,
                            fingerprint,
                            count,
                            affected_users,
                            first_seen,
                            last_seen,
                            timestamp,
                            environment,
                            release
                        )
                        VALUES (?, ?, 'Aktif', ?, ?, ?, ?, ?, ?, 1, 0, ?, ?, ?, ?, ?)
                    `).run(
                        project.id,
                        level,
                        message,
                        stack,
                        url,
                        ip,
                        browser,
                        fingerprint,
                        now,
                        now,
                        now,
                        environment,
                        release
                    );

                    errorId = Number(inserted.lastInsertRowid);
                }

                if (clientUuid) {
                    db.prepare(`
                        INSERT OR IGNORE INTO error_clients (
                            error_id,
                            client_uuid
                        )
                        VALUES (?, ?)
                    `).run(errorId, clientUuid);
                }

                const uniqueUsers = db.prepare(`
                    SELECT COUNT(*) AS n
                    FROM error_clients
                    WHERE error_id = ?
                `).get(errorId).n;

                db.prepare(`
                    UPDATE errors
                    SET affected_users = ?
                    WHERE id = ?
                `).run(uniqueUsers, errorId);

                return {
                    errorId,
                    grouped: Boolean(existing),
                    occurrenceCount: existing
                        ? db.prepare(`
                            SELECT count
                            FROM errors
                            WHERE id = ?
                        `).get(errorId).count
                        : 1
                };
            })();

            res.status(202).json({
                success: true,
                message: 'Hata olayı alındı.',
                ...result
            });

        } catch (err) {
            if (err.message === 'QUOTA_EXCEEDED') {
                return sendError(res, 429, 'Aylık hata raporu kotanız doldu.');
            }
            console.error('Error ingestion failed:', err.message);
            sendError(res, 500, 'Hata olayı kaydedilemedi.');
        }
    }
);

// =====================================================
// HATALARI LİSTELE
// =====================================================

app.get('/api/errors', verifyJwtSession, requireActiveSubscription, (req, res) => {
    try {
        const requestedLimit = req.query.limit === undefined ? 200 : Number(req.query.limit);
        if (!Number.isInteger(requestedLimit) || requestedLimit < 1) {
            return sendError(res, 400, 'limit pozitif bir tam sayı olmalıdır.');
        }

        const limit = Number.isFinite(requestedLimit)
            ? Math.min(Math.max(requestedLimit, 1), 500)
            : 200;

        const beforeId = req.query.beforeId === undefined ? null : Number(req.query.beforeId);
        if (beforeId !== null && (!Number.isSafeInteger(beforeId) || beforeId <= 0)) {
            return sendError(res, 400, 'Geçersiz beforeId.');
        }

        const projectId = req.query.projectId
            ? Number(req.query.projectId)
            : null;

        let sql = `
            SELECT e.*, p.name AS project
            FROM errors e
            JOIN projects p ON p.id = e.project_id
            WHERE p.user_id = ?
            AND p.revoked_at IS NULL
        `;

        const params = [req.user.id];

        if (projectId !== null) {
            if (!Number.isInteger(projectId)) {
                return sendError(res, 400, 'Geçersiz proje ID.');
            }

            sql += ' AND e.project_id = ?';
            params.push(projectId);
        }

        if (beforeId !== null) {
            sql += ' AND e.id < ?';
            params.push(beforeId);
        }

        sql += ' ORDER BY e.id DESC LIMIT ?';
        params.push(limit);

        res.json(db.prepare(sql).all(...params));

    } catch (err) {
        console.error('Error list error:', err.message);
        sendError(res, 500, 'Hatalar listelenemedi.');
    }
});

// =====================================================
// HATA ÇÖZÜLDÜ OLARAK İŞARETLE
// =====================================================

app.patch(
    '/api/errors/:id/resolve',
    verifyJwtSession,
    requireActiveSubscription,
    (req, res) => {
        const id = Number(req.params.id);

        if (!Number.isSafeInteger(id) || id <= 0) {
            return sendError(res, 400, 'Geçersiz hata ID.');
        }

        try {
            const result = db.prepare(`
                UPDATE errors
                SET status = 'Çözüldü'
                WHERE id = ?
                AND project_id IN (
                    SELECT id
                    FROM projects
                    WHERE user_id = ?
                    AND revoked_at IS NULL
                )
            `).run(id, req.user.id);

            if (!result.changes) {
                return sendError(
                    res,
                    404,
                    'Hata bulunamadı veya işlem yetkiniz yok.'
                );
            }

            res.json({ success: true });

        } catch (err) {
            console.error('Resolve error:', err.message);
            sendError(res, 500, 'Hata durumu güncellenemedi.');
        }
    }
);

// =====================================================
// ANA SAYFA
// =====================================================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// =====================================================
// GENEL HATA YAKALAMA
// =====================================================

app.use((err, req, res, next) => {
    console.error(
        'Unhandled request error:',
        err.message
    );

    if (res.headersSent) {
        return next(err);
    }

    const status = err.type === 'entity.too.large'
        ? 413
        : (err.message === 'CORS origin not allowed' ? 403 : 500);

    sendError(
        res,
        status,
        status === 413
            ? 'İstek boyutu çok büyük.'
            : status === 403
                ? 'Bu kaynaktan gelen isteğe izin verilmiyor.'
                : 'Sunucu hatası.'
    );
});

// =====================================================
// SUNUCUYU BAŞLAT
// =====================================================

const server = app.listen(PORT, () => {
    console.log(
        `[PulseTrace Pro] Sunucu aktif: http://localhost:${PORT}`
    );

    console.log(`[PulseTrace Pro] Veritabanı: ${DB_PATH}`);

    console.log('[PulseTrace Pro] Migration kontrolleri tamamlandı.');
    console.log('[PulseTrace Pro] PayTR ödeme modülü hazır.');

    checkMailConfig();
});

// Süresi dolmuş bekleyen kayıtları saatte bir temizle.
setInterval(() => {
    try {
        db.prepare(`
            DELETE FROM pending_registrations WHERE expires_at < ?
        `).run(new Date(Date.now() - 3600000).toISOString());
    } catch (err) {
        console.error('Pending cleanup error:', err.message);
    }
}, 3600000).unref();

// =====================================================
// GÜVENLİ KAPATMA
// =====================================================

function shutdown() {
    console.log('[PulseTrace Pro] Sunucu kapatılıyor...');

    server.close(() => {
        try {
            db.close();

            console.log(
                '[PulseTrace Pro] Veritabanı kapatıldı.'
            );

        } catch (err) {
            console.error(
                '[PulseTrace Pro] Veritabanı kapatma hatası:',
                err.message
            );
        }

        process.exit(0);
    });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);