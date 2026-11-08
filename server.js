'use strict';

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
    if (IS_PRODUCTION) {
        console.error('FATAL: Production ortamında en az 32 karakterlik JWT_SECRET zorunludur.');
        process.exit(1);
    }
    console.warn('UYARI: JWT_SECRET ayarlanmamış veya kısa. Yerel test için geçici anahtar kullanılıyor.');
}

const SIGNING_SECRET = JWT_SECRET || crypto.randomBytes(48).toString('hex');
const DB_PATH = path.join(__dirname, 'pulsetrace_enterprise.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

function addColumnIfMissing(table, column, definition) {
    const columns = db.prepare(`PRAGMA table_info(${table})`).all();
    if (!columns.some(c => c.name === column)) {
        db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
    }
}

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
    reset_code TEXT,
    reset_code_expires TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS pending_registrations (
    email TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    otp_code TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    name TEXT NOT NULL,
    api_key_hash TEXT UNIQUE NOT NULL,
    api_key_prefix TEXT NOT NULL,
    status TEXT DEFAULT 'Aktif',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
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
`);

addColumnIfMissing('users', 'usage_month', 'TEXT');
addColumnIfMissing('users', 'token_version', 'INTEGER NOT NULL DEFAULT 0');
addColumnIfMissing('pending_registrations', 'attempts', 'INTEGER NOT NULL DEFAULT 0');
addColumnIfMissing('pending_registrations', 'updated_at', 'TEXT');
addColumnIfMissing('projects', 'revoked_at', 'TEXT');
addColumnIfMissing('errors', 'environment', 'TEXT');
addColumnIfMissing('errors', 'release', 'TEXT');

db.exec(`
CREATE INDEX IF NOT EXISTS idx_projects_user ON projects(user_id);
CREATE INDEX IF NOT EXISTS idx_errors_project_last_seen ON errors(project_id, last_seen);
CREATE INDEX IF NOT EXISTS idx_errors_fingerprint ON errors(project_id, fingerprint);
CREATE INDEX IF NOT EXISTS idx_error_clients_client ON error_clients(client_uuid);
`);

app.disable('x-powered-by');
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (IS_PRODUCTION) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});

app.use(cors({
    origin(origin, callback) {
        const allowedOrigins = ['https://pulsetrace-pro.onrender.com'];
        if (!origin) return callback(null, true);
        if (allowedOrigins.includes(origin.replace(/\/$/, ''))) return callback(null, true);
        return callback(new Error('CORS origin not allowed'));
    },
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
}));

app.use(express.json({ limit: '256kb' }));

const rateBuckets = new Map();
function rateLimit({ windowMs = 60000, max = 30, keyFn = req => req.ip } = {}) {
    return (req, res, next) => {
        const now = Date.now();
        const key = `${req.path}:${keyFn(req)}`;
        let item = rateBuckets.get(key);
        if (!item || item.resetAt <= now) item = { count: 0, resetAt: now + windowMs };
        item.count += 1;
        rateBuckets.set(key, item);
        if (item.count > max) {
            res.setHeader('Retry-After', Math.ceil((item.resetAt - now) / 1000));
            return res.status(429).json({ success: false, message: 'Çok fazla istek gönderildi. Lütfen biraz bekleyin.' });
        }
        next();
    };
}
setInterval(() => {
    const now = Date.now();
    for (const [key, value] of rateBuckets) if (value.resetAt <= now) rateBuckets.delete(key);
}, 60000).unref();

function cleanEmail(value) {
    return typeof value === 'string' ? value.trim().toLowerCase() : '';
}
function validEmail(email) {
    return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function safeString(value, max = 4000) {
    return typeof value === 'string' ? value.trim().slice(0, max) : '';
}
function sha256(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}
function otpHash(email, code, purpose) {
    return crypto.createHmac('sha256', SIGNING_SECRET).update(`${purpose}:${email}:${code}`).digest('hex');
}
function safeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const aa = Buffer.from(a);
    const bb = Buffer.from(b);
    return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function generateOtp() {
    return crypto.randomInt(100000, 1000000).toString();
}
function createApiKey() {
    return `pt_live_${crypto.randomBytes(32).toString('hex')}`;
}
function sendError(res, status, message) {
    return res.status(status).json({ success: false, message });
}

// Brevo HTTPS Transactional Email API Entegrasyonu (Port engeline takılmaz)
async function sendMail({ to, subject, text }) {
    const apiKey = process.env.BREVO_API_KEY;
    if (!apiKey) {
        throw new Error('Brevo API anahtarı eksik. Render Environment içine BREVO_API_KEY ekleyin.');
    }

    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: {
            'accept': 'application/json',
            'api-key': apiKey,
            'content-type': 'application/json'
        },
        body: JSON.stringify({
            sender: { 
                email: process.env.MAIL_FROM_EMAIL || "muhammetegelioglum@gmail.com", 
                name: "PulseTrace Pro" 
            },
            to: [{ email: to }],
            subject: subject,
            textContent: text
        })
    });

    const data = await response.json();
    if (!response.ok) {
        throw new Error(data.message || 'Brevo API üzerinden e-posta gönderilemedi.');
    }
    return data;
}

function verifyJwtSession(req, res, next) {
    const authHeader = req.headers.authorization || '';
    if (!authHeader.startsWith('Bearer ')) return sendError(res, 401, 'Oturum tokenı bulunamadı.');
    try {
        const decoded = jwt.verify(authHeader.slice(7), SIGNING_SECRET);
        const user = db.prepare(`
            SELECT id, email, plan_type, monthly_error_count, error_limit, role, trial_ends_at, token_version
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

function issueToken(user) {
    return jwt.sign(
        { userId: user.id, email: user.email, tokenVersion: Number(user.token_version || 0) },
        SIGNING_SECRET,
        { expiresIn: '7d', issuer: 'pulsetrace-pro' }
    );
}

function resetMonthlyUsage(userId) {
    const month = new Date().toISOString().slice(0, 7);
    db.prepare(`
        UPDATE users SET monthly_error_count = 0, usage_month = ?
        WHERE id = ? AND (usage_month IS NULL OR usage_month <> ?)
    `).run(month, userId, month);
}

app.get('/api/health', (req, res) => {
    try {
        db.prepare('SELECT 1').get();
        res.json({ success: true, status: 'ok', timestamp: new Date().toISOString() });
    } catch {
        sendError(res, 503, 'Veritabanı sağlık kontrolü başarısız.');
    }
});

// Kayıt ve e-posta OTP (HTTPS API ile)
app.post('/api/auth/register', rateLimit({ max: 5, windowMs: 15 * 60 * 1000 }), async (req, res) => {
    const email = cleanEmail(req.body?.email);
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!validEmail(email) || password.length < 10 || password.length > 128) {
        return sendError(res, 400, 'Geçerli e-posta girin. Şifre 10-128 karakter olmalıdır.');
    }
    if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) {
        return sendError(res, 409, 'Bu e-posta adresi zaten kullanımda.');
    }

    const code = generateOtp();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    try {
        const passwordHash = await bcrypt.hash(password, 12);
        db.prepare(`
            INSERT INTO pending_registrations (email, password_hash, otp_code, expires_at, attempts, updated_at)
            VALUES (?, ?, ?, ?, 0, ?)
            ON CONFLICT(email) DO UPDATE SET
                password_hash = excluded.password_hash,
                otp_code = excluded.otp_code,
                expires_at = excluded.expires_at,
                attempts = 0,
                updated_at = excluded.updated_at
        `).run(email, passwordHash, otpHash(email, code, 'register'), expiresAt, new Date().toISOString());

        await sendMail({
            to: email,
            subject: 'PulseTrace Pro - Hesap doğrulama kodunuz',
            text: `PulseTrace Pro kayıt doğrulama kodunuz: ${code}. Kod 5 dakika geçerlidir.`
        });
        res.json({ success: true, message: 'Doğrulama kodu e-posta adresinize gönderildi.' });
    } catch (err) {
        console.error('Register/mail error:', err.message);
        db.prepare('DELETE FROM pending_registrations WHERE email = ?').run(email);
        sendError(res, 503, err.message || 'E-posta gönderilemedi.');
    }
});

app.post('/api/auth/verify-otp', rateLimit({ max: 10, windowMs: 10 * 60 * 1000 }), (req, res) => {
    const email = cleanEmail(req.body?.email);
    const code = safeString(req.body?.code, 6);
    if (!validEmail(email) || !/^\d{6}$/.test(code)) return sendError(res, 400, 'E-posta ve 6 haneli kod gereklidir.');

    const pending = db.prepare('SELECT * FROM pending_registrations WHERE email = ?').get(email);
    if (!pending) return sendError(res, 400, 'Kayıt isteği bulunamadı veya süresi doldu.');
    if (pending.attempts >= 5) {
        db.prepare('DELETE FROM pending_registrations WHERE email = ?').run(email);
        return sendError(res, 429, 'Çok fazla hatalı kod girildi. Yeniden kayıt isteği oluşturun.');
    }
    if (Date.now() > Date.parse(pending.expires_at)) {
        db.prepare('DELETE FROM pending_registrations WHERE email = ?').run(email);
        return sendError(res, 400, 'Kodun süresi doldu. Yeniden kayıt olun.');
    }
    if (!safeEqual(pending.otp_code, otpHash(email, code, 'register'))) {
        db.prepare('UPDATE pending_registrations SET attempts = attempts + 1 WHERE email = ?').run(email);
        return sendError(res, 400, 'Doğrulama kodu hatalı.');
    }

    try {
        const created = db.transaction(() => {
            const result = db.prepare(`
                INSERT INTO users (email, password_hash, plan_type, monthly_error_count, error_limit, role, trial_ends_at, usage_month)
                VALUES (?, ?, 'free', 0, 3000, 'user', ?, ?)
            `).run(email, pending.password_hash, new Date(Date.now() + 7 * 86400000).toISOString(), new Date().toISOString().slice(0, 7));
            const userId = Number(result.lastInsertRowid);
            const rawKey = createApiKey();
            db.prepare('INSERT INTO projects (user_id, name, api_key_hash, api_key_prefix) VALUES (?, ?, ?, ?)')
                .run(userId, 'Varsayılan Proje', sha256(rawKey), `${rawKey.slice(0, 14)}...`);
            db.prepare('DELETE FROM pending_registrations WHERE email = ?').run(email);
            return { id: userId, rawApiKey: rawKey };
        })();
        const user = db.prepare('SELECT id, email, role, token_version FROM users WHERE id = ?').get(created.id);
        res.json({
            success: true, token: issueToken(user), userId: user.id, email: user.email,
            role: user.role, rawApiKey: created.rawApiKey,
            message: 'Hesabınız oluşturuldu. API anahtarını şimdi güvenli bir yere kaydedin; tekrar gösterilmez.'
        });
    } catch (err) {
        console.error('OTP verification error:', err.message);
        sendError(res, 500, 'Hesap oluşturulamadı. E-posta zaten kullanılıyor olabilir.');
    }
});

app.post('/api/auth/login', rateLimit({ max: 10, windowMs: 15 * 60 * 1000 }), async (req, res) => {
    const email = cleanEmail(req.body?.email);
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!validEmail(email) || !password) return sendError(res, 400, 'E-posta ve şifre zorunludur.');
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
        return sendError(res, 401, 'E-posta veya şifre hatalı.');
    }
    resetMonthlyUsage(user.id);
    const freshUser = db.prepare('SELECT id, email, role, token_version, plan_type FROM users WHERE id = ?').get(user.id);
    res.json({
        success: true, token: issueToken(freshUser), userId: freshUser.id,
        email: freshUser.email, role: freshUser.role, plan: freshUser.plan_type
    });
});

app.post('/api/auth/forgot-password', rateLimit({ max: 5, windowMs: 15 * 60 * 1000 }), async (req, res) => {
    const email = cleanEmail(req.body?.email);
    if (!validEmail(email)) return sendError(res, 400, 'Geçerli bir e-posta girin.');
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    const genericMessage = 'Eğer bu e-posta kayıtlıysa sıfırlama kodu gönderilmiştir.';
    if (!user) return res.json({ success: true, message: genericMessage });

    const code = generateOtp();
    const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    db.prepare('UPDATE users SET reset_code = ?, reset_code_expires = ? WHERE id = ?')
        .run(otpHash(email, code, 'reset'), expires, user.id);
    try {
        await sendMail({
            to: email,
            subject: 'PulseTrace Pro - Şifre sıfırlama kodunuz',
            text: `Şifre sıfırlama kodunuz: ${code}. Kod 15 dakika geçerlidir.`
        });
        res.json({ success: true, message: genericMessage });
    } catch (err) {
        console.error('Reset mail error:', err.message);
        sendError(res, 503, err.message || 'E-posta gönderilemedi.');
    }
});

app.post('/api/auth/reset-password', rateLimit({ max: 5, windowMs: 15 * 60 * 1000 }), async (req, res) => {
    const email = cleanEmail(req.body?.email);
    const code = safeString(req.body?.code, 6);
    const newPassword = typeof req.body?.newPassword === 'string' ? req.body.newPassword : '';
    if (!validEmail(email) || !/^\d{6}$/.test(code) || newPassword.length < 10 || newPassword.length > 128) {
        return sendError(res, 400, 'E-posta, 6 haneli kod ve en az 10 karakterlik yeni şifre gereklidir.');
    }
    const user = db.prepare('SELECT id, reset_code, reset_code_expires FROM users WHERE email = ?').get(email);
    if (!user || !user.reset_code || Date.now() > Date.parse(user.reset_code_expires) ||
        !safeEqual(user.reset_code, otpHash(email, code, 'reset'))) {
        return sendError(res, 400, 'Kod geçersiz veya süresi dolmuş.');
    }
    try {
        const hash = await bcrypt.hash(newPassword, 12);
        db.prepare(`
            UPDATE users SET password_hash = ?, reset_code = NULL, reset_code_expires = NULL,
            token_version = token_version + 1 WHERE id = ?
        `).run(hash, user.id);
        res.json({ success: true, message: 'Şifreniz değiştirildi. Güvenlik için yeniden giriş yapın.' });
    } catch (err) {
        console.error('Password reset error:', err.message);
        sendError(res, 500, 'Şifre güncellenemedi.');
    }
});

app.get('/api/user/subscription', verifyJwtSession, (req, res) => {
    resetMonthlyUsage(req.user.id);
    const user = db.prepare(`
        SELECT email, plan_type, monthly_error_count, error_limit, role, trial_ends_at
        FROM users WHERE id = ?
    `).get(req.user.id);
    res.json({
        ...user,
        trialExpired: Boolean(user.trial_ends_at && Date.now() > Date.parse(user.trial_ends_at))
    });
});

app.get('/api/projects', verifyJwtSession, (req, res) => {
    const projects = db.prepare(`
        SELECT id, name, api_key_prefix AS apiKey, status, created_at
        FROM projects WHERE user_id = ? AND revoked_at IS NULL ORDER BY id DESC
    `).all(req.user.id);
    res.json(projects);
});

app.post('/api/projects', verifyJwtSession, (req, res) => {
    const name = safeString(req.body?.name, 80);
    if (!name) return sendError(res, 400, 'Proje adı zorunludur.');
    const projectCount = db.prepare('SELECT COUNT(*) AS n FROM projects WHERE user_id = ? AND revoked_at IS NULL').get(req.user.id).n;
    const maxProjects = req.user.plan_type === 'free' ? 3 : 50;
    if (projectCount >= maxProjects) return sendError(res, 403, `Paketiniz en fazla ${maxProjects} proje oluşturabilir.`);

    const rawKey = createApiKey();
    try {
        const result = db.prepare(`
            INSERT INTO projects (user_id, name, api_key_hash, api_key_prefix)
            VALUES (?, ?, ?, ?)
        `).run(req.user.id, name, sha256(rawKey), `${rawKey.slice(0, 14)}...`);
        res.status(201).json({
            success: true,
            project: { id: Number(result.lastInsertRowid), name, apiKey: rawKey, status: 'Aktif' },
            warning: 'Bu API anahtarı yalnızca şimdi gösterilir. Güvenli biçimde saklayın.'
        });
    } catch (err) {
        console.error('Project create error:', err.message);
        sendError(res, 500, 'Proje oluşturulamadı.');
    }
});

app.post('/api/projects/:id/rotate-key', verifyJwtSession, (req, res) => {
    const projectId = Number(req.params.id);
    const project = db.prepare('SELECT id FROM projects WHERE id = ? AND user_id = ? AND revoked_at IS NULL')
        .get(projectId, req.user.id);
    if (!project) return sendError(res, 404, 'Proje bulunamadı.');
    const rawKey = createApiKey();
    db.prepare('UPDATE projects SET api_key_hash = ?, api_key_prefix = ? WHERE id = ?')
        .run(sha256(rawKey), `${rawKey.slice(0, 14)}...`, projectId);
    res.json({ success: true, apiKey: rawKey, message: 'Yeni anahtar oluşturuldu. Eski anahtar artık geçersiz.' });
});

app.delete('/api/projects/:id', verifyJwtSession, (req, res) => {
    const projectId = Number(req.params.id);
    const result = db.prepare('UPDATE projects SET revoked_at = ?, status = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL')
        .run(new Date().toISOString(), 'Pasif', projectId, req.user.id);
    if (!result.changes) return sendError(res, 404, 'Proje bulunamadı.');
    res.json({ success: true });
});

// SDK / harici uygulamalar buraya olay gönderir.
app.post('/api/errors', rateLimit({ max: 120, windowMs: 60000 }), (req, res) => {
    const rawKey = safeString(req.get('x-api-key') || (req.get('authorization') || '').replace(/^Bearer\s+/i, ''), 200);
    if (!rawKey.startsWith('pt_live_')) return sendError(res, 401, 'Proje API anahtarı gerekli.');
    const project = db.prepare(`
        SELECT p.id, p.user_id, p.status, p.revoked_at, u.error_limit, u.monthly_error_count, u.usage_month
        FROM projects p JOIN users u ON u.id = p.user_id
        WHERE p.api_key_hash = ?
    `).get(sha256(rawKey));
    if (!project || project.revoked_at || project.status !== 'Aktif') return sendError(res, 401, 'API anahtarı geçersiz veya iptal edilmiş.');

    resetMonthlyUsage(project.user_id);
    const owner = db.prepare('SELECT monthly_error_count, error_limit FROM users WHERE id = ?').get(project.user_id);
    if (owner.monthly_error_count >= owner.error_limit) return sendError(res, 429, 'Aylık hata raporu kotanız doldu.');

    const message = safeString(req.body?.message, 4000);
    if (!message) return sendError(res, 400, 'message alanı zorunludur.');
    const stack = safeString(req.body?.stack || req.body?.stackTrace, 12000);
    const url = safeString(req.body?.url, 2000);
    const levelInput = safeString(req.body?.level || 'error', 20).toLowerCase();
    const level = ['fatal', 'critical', 'error', 'warning', 'info'].includes(levelInput)
        ? (['fatal', 'critical'].includes(levelInput) ? 'Kritik' : (levelInput === 'warning' ? 'Uyari' : 'Hata'))
        : 'Hata';
    const environment = safeString(req.body?.environment || 'production', 40);
    const release = safeString(req.body?.release, 100);
    const clientUuid = safeString(req.body?.userId || req.body?.user_id || req.body?.clientId || '', 128);
    const browser = safeString(req.body?.browser || req.get('user-agent') || '', 500);
    const ip = safeString(req.ip || '', 64);
    const fingerprint = sha256(`${project.id}|${message}|${stack.split('\n')[0]}|${url}`).slice(0, 48);
    const now = new Date().toISOString();

    try {
        const result = db.transaction(() => {
            let existing = db.prepare(`
                SELECT id FROM errors WHERE project_id = ? AND fingerprint = ? AND status = 'Aktif'
            `).get(project.id, fingerprint);
            let errorId;
            if (existing) {
                errorId = existing.id;
                db.prepare(`
                    UPDATE errors SET count = count + 1, last_seen = ?, level = ?,
                    message = ?, stack = ?, url = ?, ip = ?, browser = ?,
                    environment = ?, release = ? WHERE id = ?
                `).run(now, level, message, stack, url, ip, browser, environment, release, errorId);
            } else {
                const inserted = db.prepare(`
                    INSERT INTO errors
                    (project_id, level, status, message, stack, url, ip, browser, fingerprint,
                     count, affected_users, first_seen, last_seen, timestamp, environment, release)
                    VALUES (?, ?, 'Aktif', ?, ?, ?, ?, ?, ?, 1, 0, ?, ?, ?, ?, ?)
                `).run(project.id, level, message, stack, url, ip, browser, fingerprint, now, now, now, environment, release);
                errorId = Number(inserted.lastInsertRowid);
            }

            if (clientUuid) {
                db.prepare('INSERT OR IGNORE INTO error_clients (error_id, client_uuid) VALUES (?, ?)')
                    .run(errorId, clientUuid);
            }
            const uniqueUsers = db.prepare('SELECT COUNT(*) AS n FROM error_clients WHERE error_id = ?').get(errorId).n;
            db.prepare('UPDATE errors SET affected_users = ? WHERE id = ?').run(uniqueUsers, errorId);
            db.prepare('UPDATE users SET monthly_error_count = monthly_error_count + 1 WHERE id = ?').run(project.user_id);
            return { errorId, grouped: Boolean(existing), occurrenceCount: existing
                ? db.prepare('SELECT count FROM errors WHERE id = ?').get(errorId).count : 1 };
        })();
        res.status(202).json({ success: true, message: 'Hata olayı alındı.', ...result });
    } catch (err) {
        console.error('Error ingestion failed:', err.message);
        sendError(res, 500, 'Hata olayı kaydedilemedi.');
    }
});

app.get('/api/errors', verifyJwtSession, (req, res) => {
    const requestedLimit = Number.parseInt(req.query.limit, 10);
    const limit = Number.isFinite(requestedLimit) ? Math.min(Math.max(requestedLimit, 1), 500) : 200;
    const beforeId = Number.parseInt(req.query.beforeId, 10);
    const projectId = req.query.projectId ? Number.parseInt(req.query.projectId, 10) : null;

    let sql = `
        SELECT e.*, p.name AS project
        FROM errors e JOIN projects p ON p.id = e.project_id
        WHERE p.user_id = ? AND p.revoked_at IS NULL
    `;
    const params = [req.user.id];
    if (projectId !== null) {
        if (!Number.isInteger(projectId)) return sendError(res, 400, 'Geçersiz proje ID.');
        sql += ' AND e.project_id = ?';
        params.push(projectId);
    }
    if (Number.isInteger(beforeId)) {
        sql += ' AND e.id < ?';
        params.push(beforeId);
    }
    sql += ' ORDER BY e.id DESC LIMIT ?';
    params.push(limit);
    res.json(db.prepare(sql).all(...params));
});

app.patch('/api/errors/:id/resolve', verifyJwtSession, (req, res) => {
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return sendError(res, 400, 'Geçersiz hata ID.');
    const result = db.prepare(`
        UPDATE errors SET status = 'Çözüldü'
        WHERE id = ? AND project_id IN (
            SELECT id FROM projects WHERE user_id = ? AND revoked_at IS NULL
        )
    `).run(id, req.user.id);
    if (!result.changes) return sendError(res, 404, 'Hata bulunamadı veya işlem yetkiniz yok.');
    res.json({ success: true });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.use((err, req, res, next) => {
    console.error('Unhandled request error:', err.message);
    if (res.headersSent) return next(err);
    const status = err.type === 'entity.too.large' ? 413 : 500;
    sendError(res, status, status === 413 ? 'İstek boyutu çok büyük.' : 'Sunucu hatası.');
});

app.listen(PORT, () => {
    console.log(`[PulseTrace Pro] Sunucu aktif: http://localhost:${PORT}`);
    console.log(`[PulseTrace Pro] Veritabanı: ${DB_PATH}`);
});

process.on('SIGINT', () => {
    try { db.close(); } catch {}
    process.exit(0);
});
process.on('SIGTERM', () => {
    try { db.close(); } catch {}
    process.exit(0);
});