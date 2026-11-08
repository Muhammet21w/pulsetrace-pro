require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'pulsetrace_super_secure_enterprise_secret_2026';

app.use(cors());
app.use(express.json());

// SQLite Veritabanı ve Foreign Key Aktifleştirme
const db = new Database('pulsetrace_enterprise.db');
db.pragma('foreign_keys = ON');

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        plan_type TEXT DEFAULT 'free',
        monthly_error_count INTEGER DEFAULT 0,
        error_limit INTEGER DEFAULT 3000,
        role TEXT DEFAULT 'user',
        trial_ends_at DATETIME,
        reset_code TEXT,
        reset_code_expires DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Geçici OTP Doğrulama Tablosu
    CREATE TABLE IF NOT EXISTS pending_registrations (
        email TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        otp_code TEXT NOT NULL,
        expires_at DATETIME NOT NULL
    );

    CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT NOT NULL,
        api_key_hash TEXT UNIQUE NOT NULL,
        api_key_prefix TEXT NOT NULL,
        status TEXT DEFAULT 'Aktif',
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
        affected_users INTEGER DEFAULT 1,
        first_seen TEXT,
        last_seen TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
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
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
`);

// Brevo SMTP Aktarıcısı
const transporter = nodemailer.createTransport({
    host: 'smtp-relay.brevo.com',
    port: 587,
    auth: {
        user: process.env.BREVO_USER,
        pass: process.env.BREVO_SMTP_KEY
    }
});

function verifyJwtSession(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, message: "Oturum token'ı bulunamadı." });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = db.prepare('SELECT id, email, plan_type, monthly_error_count, error_limit, role, trial_ends_at FROM users WHERE id = ?').get(decoded.userId);
        if (!user) return res.status(401).json({ success: false, message: "Geçersiz oturum kullanıcısı." });
        
        req.user = user;
        next();
    } catch (err) {
        return res.status(403).json({ success: false, message: "Oturum süresi doldu veya geçersiz token." });
    }
}

// 1. AŞAMA: Kayıt Talebi ve E-postaya OTP Kodu Gönderme
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: "E-posta ve şifre zorunludur." });

    if (password.length < 6) {
        return res.status(400).json({ success: false, message: "Şifre en az 6 karakter uzunluğunda olmalıdır!" });
    }

    const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existingUser) {
        return res.status(400).json({ success: false, message: "Bu e-posta adresi zaten kullanımda." });
    }

    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    try {
        const saltRounds = 12;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        db.prepare(`
            INSERT OR REPLACE INTO pending_registrations (email, password_hash, otp_code, expires_at) 
            VALUES (?, ?, ?, ?)
        `).run(email, passwordHash, otpCode, expiresAt);

        await transporter.sendMail({
            from: '"PulseTrace Pro" <noreply@pulsetrace.com>',
            to: email,
            subject: 'PulseTrace Pro - Hesap Doğrulama Kodunuz',
            text: `Merhaba, PulseTrace Pro kayıt işleminizi tamamlamak için doğrulama kodunuz: ${otpCode}. Bu kod 5 dakika geçerlidir.`
        });

        res.json({ success: true, message: "Doğrulama kodu e-posta adresinize gönderildi. Lütfen kodu girin." });
    } catch (err) {
        console.error("Kayıt ve E-posta Gönderme Hatası:", err);
        res.status(500).json({ success: false, message: "E-posta gönderilemedi. Lütfen Brevo SMTP ayarlarını kontrol edin." });
    }
});

// 2. AŞAMA: OTP Kodunu Doğrulama ve Hesabı Açma
app.post('/api/auth/verify-otp', async (req, res) => {
    const { email, code } = req.body;
    if (!email || !code) {
        return res.status(400).json({ success: false, message: "E-posta ve doğrulama kodu gereklidir." });
    }

    const pending = db.prepare('SELECT * FROM pending_registrations WHERE email = ?').get(email);
    if (!pending) {
        return res.status(400).json({ success: false, message: "Bu e-posta için kayıt talebi bulunamadı." });
    }

    if (new Date() > new Date(pending.expires_at)) {
        db.prepare('DELETE FROM pending_registrations WHERE email = ?').run(email);
        return res.status(400).json({ success: false, message: "Doğrulama kodunun süresi doldu. Lütfen tekrar kayıt olun." });
    }

    if (pending.otp_code !== code) {
        return res.status(400).json({ success: false, message: "Hatalı doğrulama kodu." });
    }

    const planType = 'free';
    const limit = 3000;
    const trialEndsAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    try {
        const result = db.transaction(() => {
            const info = db.prepare('INSERT INTO users (email, password_hash, plan_type, error_limit, role, trial_ends_at) VALUES (?, ?, ?, ?, ?, ?)')
                .run(email, pending.password_hash, planType, limit, 'user', trialEndsAt);
            
            const rawKey = "pt_live_" + crypto.randomBytes(16).toString('hex');
            const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
            const keyPrefix = rawKey.substring(0, 10) + "...";
            
            db.prepare('INSERT INTO projects (user_id, name, api_key_hash, api_key_prefix) VALUES (?, ?, ?, ?)')
                .run(info.lastInsertRowid, 'Varsayılan Proje', keyHash, keyPrefix);

            db.prepare('DELETE FROM pending_registrations WHERE email = ?').run(email);

            return { userId: info.lastInsertRowid, rawApiKey: rawKey };
        })();

        const token = jwt.sign({ userId: result.userId, email }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, token, userId: result.userId, email, rawApiKey: result.rawApiKey, role: 'user', message: "Hesabınız başarıyla doğrulandı!" });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Giriş Yap
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: "E-posta ve şifre zorunludur." });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(401).json({ success: false, message: "Hatalı e-posta veya şifre." });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ success: false, message: "Hatalı e-posta veya şifre." });

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, userId: user.id, email: user.email, plan: user.plan_type, role: user.role });
});

// Şifre Sıfırlama İstemi
app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: "E-posta adresi gereklidir." });

    const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (!user) {
        return res.json({ success: true, message: "Eğer bu e-posta adresi sistemimizde kayıtlıysa sıfırlama kodu gönderilmiştir." });
    }

    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    db.prepare('UPDATE users SET reset_code = ?, reset_code_expires = ? WHERE id = ?').run(resetCode, expiresAt, user.id);

    try {
        await transporter.sendMail({
            from: '"PulseTrace Pro" <noreply@pulsetrace.com>',
            to: email,
            subject: 'PulseTrace Pro - Şifre Sıfırlama Kodunuz',
            text: `Şifre sıfırlama doğrulama kodunuz: ${resetCode}. Bu kod 15 dakika geçerlidir.`
        });
        res.json({ success: true, message: "Şifre sıfırlama doğrulama kodu e-posta adresinize gönderildi." });
    } catch (err) {
        console.error("Şifre Sıfırlama E-posta Hatası:", err);
        res.status(500).json({ success: false, message: "E-posta gönderilemedi." });
    }
});

// Şifre Güncelleme
app.post('/api/auth/reset-password', async (req, res) => {
    const { email, code, newPassword } = req.body;
    if (!email || !code || !newPassword) {
        return res.status(400).json({ success: false, message: "Tüm alanları doldurmalısınız." });
    }

    if (newPassword.length < 6) {
        return res.status(400).json({ success: false, message: "Yeni şifre en az 6 karakter olmalıdır." });
    }

    const user = db.prepare('SELECT id, reset_code, reset_code_expires FROM users WHERE email = ?').get(email);
    if (!user || !user.reset_code || user.reset_code !== code) {
        return res.status(400).json({ success: false, message: "Geçersiz veya hatalı doğrulama kodu." });
    }

    if (new Date() > new Date(user.reset_code_expires)) {
        return res.status(400).json({ success: false, message: "Doğrulama kodunun süresi dolmuş." });
    }

    try {
        const passwordHash = await bcrypt.hash(newPassword, 12);
        db.prepare('UPDATE users SET password_hash = ?, reset_code = NULL, reset_code_expires = NULL WHERE id = ?').run(passwordHash, user.id);
        res.json({ success: true, message: "Şifreniz başarıyla değiştirildi. Yeni şifrenizle giriş yapabilirsiniz." });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/user/subscription', verifyJwtSession, (req, res) => {
    const user = db.prepare('SELECT email, plan_type, monthly_error_count, error_limit, role, trial_ends_at FROM users WHERE id = ?').get(req.user.id);
    let trialExpired = false;
    if (user.trial_ends_at) {
        trialExpired = new Date() > new Date(user.trial_ends_at);
    }
    res.json({ ...user, trialExpired });
});

app.get('/api/projects', verifyJwtSession, (req, res) => {
    const projects = db.prepare('SELECT id, name, api_key_prefix as apiKey, status FROM projects WHERE user_id = ?').all(req.user.id);
    res.json(projects);
});

app.post('/api/projects', verifyJwtSession, (req, res) => {
    const projectName = req.body.name;
    if (!projectName) return res.status(400).json({ success: false, message: "Proje adı zorunludur." });

    const rawKey = "pt_live_" + crypto.randomBytes(16).toString('hex');
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
    const keyPrefix = rawKey.substring(0, 10) + "...";

    try {
        const info = db.prepare('INSERT INTO projects (user_id, name, api_key_hash, api_key_prefix) VALUES (?, ?, ?, ?)').run(req.user.id, projectName, keyHash, keyPrefix);
        res.json({ success: true, project: { id: info.lastInsertRowid, name: projectName, apiKey: rawKey, status: 'Aktif' } });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/errors', verifyJwtSession, (req, res) => {
    const projId = req.query.projectId;
    let query = `
        e.*, p.name as project 
        FROM errors e 
        JOIN projects p ON e.project_id = p.id 
        WHERE p.user_id = ?
    `;
    let params = [req.user.id];

    if (projId) {
        query += ` AND e.project_id = ?`;
        params.push(projId);
    }
    query += ` ORDER BY e.id DESC`;
    res.json(db.prepare(`SELECT ${query}`).all(...params));
});

app.patch('/api/errors/:id/resolve', verifyJwtSession, (req, res) => {
    const id = parseInt(req.params.id);
    const errorCheck = db.prepare(`
        SELECT e.id FROM errors e 
        JOIN projects p ON e.project_id = p.id 
        WHERE e.id = ? AND p.user_id = ?
    `).get(id, req.user.id);

    if (!errorCheck) return res.status(403).json({ success: false, message: "Yetkisiz işlem." });

    db.prepare("UPDATE errors SET status = 'Çözüldü' WHERE id = ?").run(id);
    res.json({ success: true });
});

// Arayüz (index.html sunumu)
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PulseTrace Pro - Multi-Tenant SaaS Enterprise</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0a0a0c;
            --card-bg: #121318;
            --border-color: #1e2029;
            --neon-green: #00ff66;
            --neon-green-glow: rgba(0, 255, 102, 0.2);
            --text-main: #f0f2f5;
            --text-muted: #8b949e;
            --danger: #ff3366;
            --warning: #ffaa00;
            --info: #00e5ff;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
        body { background-color: var(--bg-color); color: var(--text-main); min-height: 100vh; padding: 20px; }
        header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 20px; margin-bottom: 25px; flex-wrap: wrap; gap: 15px; }
        .logo-area { display: flex; align-items: center; gap: 12px; }
        .logo-icon { width: 12px; height: 12px; background: var(--neon-green); border-radius: 50%; box-shadow: 0 0 10px var(--neon-green); animation: pulse 2s infinite; }
        h1 { font-family: 'JetBrains Mono', monospace; font-size: 22px; font-weight: 700; color: var(--text-main); }
        h1 span { color: var(--neon-green); }
        .top-controls { display: flex; gap: 15px; align-items: center; flex-wrap: wrap; }
        select, input { background: var(--card-bg); border: 1px solid var(--border-color); color: var(--text-main); padding: 8px 12px; border-radius: 6px; font-family: 'JetBrains Mono', monospace; font-size: 13px; outline: none; }
        .status-indicator { display: flex; align-items: center; gap: 6px; font-size: 12px; font-family: 'JetBrains Mono'; color: var(--neon-green); background: rgba(0,255,102,0.1); padding: 4px 10px; border-radius: 4px; border: 1px solid rgba(0,255,102,0.3); }
        .status-dot { width: 8px; height: 8px; background: var(--neon-green); border-radius: 50%; box-shadow: 0 0 6px var(--neon-green); }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 25px; }
        .stat-card { background: var(--card-bg); border: 1px solid var(--border-color); padding: 20px; border-radius: 10px; position: relative; overflow: hidden; }
        .stat-card::after { content: ''; position: absolute; top: 0; left: 0; width: 3px; height: 100%; background: var(--neon-green); }
        .stat-title { font-size: 12px; color: var(--text-muted); margin-bottom: 8px; font-family: 'JetBrains Mono', monospace; }
        .stat-value { font-size: 26px; font-weight: 700; font-family: 'JetBrains Mono', monospace; color: var(--text-main); }
        .quota-widget { background: var(--card-bg); border: 1px solid var(--border-color); padding: 20px; border-radius: 10px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px; }
        .quota-info { display: flex; flex-direction: column; gap: 6px; }
        .quota-bar-bg { width: 250px; height: 8px; background: #1a1c26; border-radius: 4px; overflow: hidden; border: 1px solid var(--border-color); }
        .quota-bar-fill { height: 100%; background: var(--neon-green); width: 0%; transition: width 0.4s ease; }
        .plan-badge { background: rgba(0,229,255,0.1); border: 1px solid var(--info); color: var(--info); padding: 4px 10px; border-radius: 6px; font-family: 'JetBrains Mono'; font-size: 12px; font-weight: bold; text-transform: uppercase; }
        .analytics-box { background: var(--card-bg); border: 1px solid var(--border-color); padding: 20px; border-radius: 10px; margin-bottom: 25px; }
        .timeline-container { display: flex; align-items: flex-end; height: 80px; gap: 12px; margin-top: 15px; border-bottom: 1px solid var(--border-color); padding-bottom: 5px; overflow-x: auto; }
        .timeline-bar-wrapper { display: flex; flex-direction: column; align-items: center; gap: 4px; }
        .timeline-bar { width: 35px; background: rgba(0,255,102,0.2); border: 1px solid var(--neon-green); border-radius: 4px 4px 0 0; display: flex; justify-content: center; align-items: flex-start; font-size: 11px; font-family: 'JetBrains Mono'; color: var(--neon-green); padding-top: 4px; transition: 0.3s; }
        .filter-bar { display: flex; gap: 10px; margin-bottom: 15px; flex-wrap: wrap; align-items: center; }
        .filter-chip { background: #161821; border: 1px solid var(--border-color); color: var(--text-muted); padding: 6px 14px; border-radius: 20px; font-size: 12px; font-family: 'JetBrains Mono'; cursor: pointer; transition: 0.2s; }
        .filter-chip.active { background: rgba(0,255,102,0.1); border-color: var(--neon-green); color: var(--neon-green); }
        .btn { background: var(--neon-green); color: #000; border: none; padding: 10px 18px; font-weight: 600; border-radius: 6px; cursor: pointer; font-family: 'JetBrains Mono', monospace; transition: 0.2s; box-shadow: 0 0 15px var(--neon-green-glow); font-size: 13px; }
        .btn:hover { background: #00cc52; box-shadow: 0 0 25px var(--neon-green); }
        .btn-secondary { background: transparent; border: 1px solid var(--neon-green); color: var(--neon-green); box-shadow: none; }
        .btn-secondary:hover { background: rgba(0,255,102,0.1); }
        .btn-warning { background: var(--warning); color: #000; }
        .table-container { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 10px; overflow-x: auto; margin-bottom: 30px; }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; min-width: 700px; }
        th { background: #161821; color: var(--text-muted); padding: 14px 18px; font-family: 'JetBrains Mono', monospace; font-size: 12px; border-bottom: 1px solid var(--border-color); }
        td { padding: 14px 18px; border-bottom: 1px solid var(--border-color); font-family: 'JetBrains Mono', monospace; cursor: pointer; white-space: nowrap; }
        tr:hover td { background: rgba(0,255,102,0.02); }
        .level-kritik { color: var(--danger); font-weight: bold; }
        .level-uyari { color: var(--warning); font-weight: bold; }
        .status-aktif { color: var(--danger); background: rgba(255,51,102,0.1); padding: 4px 8px; border-radius: 4px; font-size: 11px; }
        .status-cozuldu { color: var(--neon-green); background: rgba(0,255,102,0.1); padding: 4px 8px; border-radius: 4px; font-size: 11px; }
        .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.85); backdrop-filter: blur(5px); justify-content: center; align-items: center; z-index: 1000; }
        .modal-content { background: var(--card-bg); border: 1px solid var(--neon-green); width: 480px; max-width: 90%; padding: 30px; border-radius: 12px; box-shadow: 0 0 30px var(--neon-green-glow); }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid var(--border-color); padding-bottom: 15px; }
        .modal-title { font-family: 'JetBrains Mono', monospace; font-size: 18px; color: var(--neon-green); }
        .modal-body { font-family: 'JetBrains Mono', monospace; font-size: 13px; display: flex; flex-direction: column; gap: 12px; }
        .modal-row { display: flex; justify-content: space-between; border-bottom: 1px solid var(--border-color); padding-bottom: 8px; }
        .modal-label { color: var(--text-muted); }
        .stack-trace { background: #050507; padding: 12px; border-radius: 6px; border: 1px solid var(--border-color); color: var(--danger); white-space: pre-wrap; font-size: 12px; margin-top: 5px; max-height: 150px; overflow-y: auto; word-break: break-all; }
        .project-section { background: var(--card-bg); border: 1px solid var(--border-color); padding: 20px; border-radius: 10px; margin-top: 20px; }
        .project-list { display: flex; gap: 15px; flex-wrap: wrap; margin-top: 15px; }
        .project-badge-card { background: #161821; border: 1px solid var(--border-color); padding: 15px; border-radius: 8px; font-family: 'JetBrains Mono', monospace; font-size: 13px; min-width: 280px; }
        .api-key-box { display: flex; align-items: center; gap: 8px; margin-top: 8px; background: #0a0a0c; padding: 6px 10px; border-radius: 4px; border: 1px solid var(--border-color); }
        .auth-tabs { display: flex; gap: 10px; margin-bottom: 15px; border-bottom: 1px solid var(--border-color); padding-bottom: 10px; }
        .auth-tab { background: none; border: none; color: var(--text-muted); font-family: 'JetBrains Mono'; font-size: 14px; cursor: pointer; padding-bottom: 5px; }
        .auth-tab.active { color: var(--neon-green); border-bottom: 2px solid var(--neon-green); }
        @keyframes pulse { 0% { transform: scale(0.95); opacity: 0.7; } 70% { transform: scale(1); opacity: 1; } 100% { transform: scale(0.95); opacity: 0.7; } }
    </style>
</head>
<body>
    <header>
        <div class="logo-area">
            <div class="logo-icon"></div>
            <h1>PulseTrace <span>Pro</span> Enterprise</h1>
        </div>
        <div class="top-controls">
            <div class="status-indicator"><div class="status-dot"></div><span>Güvenli JWT Bağlantısı</span></div>
            <input type="text" id="searchInput" placeholder="🔍 Hata ara..." oninput="filterAndRenderErrors()" style="width: 180px;">
            <select id="projectSelect" onchange="loadErrors()">
                <option value="">Tüm Projelerim</option>
            </select>
            <span id="userEmailDisplay" style="font-family: 'JetBrains Mono'; font-size: 12px; color: var(--neon-green);"></span>
            <button class="btn btn-secondary" style="padding: 6px 12px; font-size: 11px;" onclick="logoutUser()">Çıkış Yap</button>
        </div>
    </header>

    <div class="quota-widget">
        <div class="quota-info">
            <div style="display: flex; align-items: center; gap: 10px;">
                <span style="font-family: 'JetBrains Mono'; font-size: 14px; color: #fff;">📦 Aktif Abonelik Paketi:</span>
                <span class="plan-badge" id="planBadgeText">FREE</span>
            </div>
            <div style="font-size: 12px; color: var(--text-muted); font-family: 'JetBrains Mono';" id="quotaText">
                Aylık Kullanım: 0 / 3,000 Hata Raporu (7 Günlük Deneme Aktif)
            </div>
        </div>
        <div style="display: flex; flex-direction: column; gap: 6px; align-items: flex-end;">
            <div class="quota-bar-bg">
                <div class="quota-bar-fill" id="quotaBarFill"></div>
            </div>
            <span style="font-size: 11px; color: var(--text-muted); font-family: 'JetBrains Mono';" id="quotaPercentText">%0 Kullanıldı</span>
        </div>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-title">FİLTRELENEN / TOPLAM</div>
            <div class="stat-value"><span id="filteredCount">0</span> / <span id="totalCount">0</span></div>
        </div>
        <div class="stat-card" style="--neon-green: var(--danger);">
            <div class="stat-title">KRİTİK ÇÖKMELER</div>
            <div class="stat-value" id="criticalCount">0</div>
        </div>
        <div class="stat-card" style="--neon-green: var(--info);">
            <div class="stat-title">TEKİL KULLANICI (UUID)</div>
            <div class="stat-value" id="affectedCount">0</div>
        </div>
        <div class="stat-card" style="--neon-green: var(--warning);">
            <div class="stat-title">ÇÖZÜLEN HATA</div>
            <div class="stat-value" id="resolvedCount">0</div>
        </div>
    </div>

    <div class="analytics-box">
        <div style="font-family: 'JetBrains Mono'; font-size: 14px; color: var(--neon-green); margin-bottom: 5px;">📈 Gerçek Zamanlı Hata Çizelgesi</div>
        <div class="timeline-container" id="timelineContainer"></div>
    </div>

    <div class="filter-bar">
        <span style="font-family: 'JetBrains Mono'; font-size: 12px; color: var(--text-muted); margin-right: 5px;">Filtre:</span>
        <div class="filter-chip active" onclick="setSeverityFilter('Tumu', this)">Aktif Tümü</div>
        <div class="filter-chip" onclick="setSeverityFilter('Kritik', this)">Kritik</div>
        <div class="filter-chip" onclick="setSeverityFilter('Uyari', this)">Uyarı</div>
        <div class="filter-chip" onclick="setSeverityFilter('Cozuldu', this)">Çözüldü</div>
    </div>

    <div class="table-container">
        <table>
            <thead>
                <tr><th>ID</th><th>PROJE</th><th>SEVİYE</th><th>HATA MESAJI</th><th>TEKRAR</th><th>TEKİL KULLANICI</th><th>DURUM</th></tr>
            </thead>
            <tbody id="errorTableBody"></tbody>
        </table>
    </div>

    <div class="project-section">
        <h3 style="font-family: 'JetBrains Mono'; font-size: 15px; margin-bottom: 10px; color: var(--neon-green);">🏢 Projelerim & API Anahtarları</h3>
        <div style="display: flex; gap: 10px; margin-bottom: 15px; flex-wrap: wrap;">
            <input type="text" id="newProjectName" placeholder="Yeni Proje Adı" style="flex: 1; max-width: 300px;">
            <button class="btn btn-secondary" onclick="createProject()">+ Proje Oluştur</button>
        </div>
        <div class="project-list" id="projectListContainer"></div>
    </div>

    <!-- GİRİŞ / KAYIT / OTP DOĞRULAMA MODALI -->
    <div class="modal-overlay" id="authModal" style="display: flex;">
        <div class="modal-content" style="width: 420px;">
            <div class="auth-tabs">
                <button class="auth-tab active" id="tabLoginBtn" onclick="switchAuthTab('login')">Giriş Yap</button>
                <button class="auth-tab" id="tabRegisterBtn" onclick="switchAuthTab('register')">Kayıt Ol (OTP)</button>
            </div>
            
            <!-- GİRİŞ FORMU -->
            <div id="loginFormContainer" class="modal-body">
                <p style="color: var(--text-muted); font-size: 12px; margin-bottom: 5px;">E-posta Adresi:</p>
                <input type="email" id="loginEmail" placeholder="ornek@domain.com" style="width: 100%; padding: 10px;">
                <p style="color: var(--text-muted); font-size: 12px; margin-top: 10px; margin-bottom: 5px;">Şifre:</p>
                <input type="password" id="loginPassword" placeholder="••••••••" style="width: 100%; padding: 10px;">
                
                <div style="display: flex; justify-content: flex-end; margin-top: 5px;">
                    <a href="#" onclick="switchAuthTab('forgot')" style="color: var(--info); font-size: 11px; text-decoration: none;">Şifremi Unuttum?</a>
                </div>

                <button class="btn" style="width: 100%; margin-top: 15px;" onclick="handleLogin()">Giriş Yap</button>
            </div>

            <!-- KAYIT & OTP FORMU -->
            <div id="registerFormContainer" class="modal-body" style="display: none;">
                <div style="background: rgba(0,255,102,0.05); border: 1px solid rgba(0,255,102,0.2); padding: 10px; border-radius: 6px; margin-bottom: 5px; font-size: 11px; color: var(--neon-green);">
                    🟢 Kayıt olduğunuzda e-postanıza 6 haneli doğrulama kodu (OTP) gönderilir.
                </div>
                <p style="color: var(--text-muted); font-size: 12px; margin-bottom: 5px;">E-posta Adresi:</p>
                <input type="email" id="regEmail" placeholder="ornek@domain.com" style="width: 100%; padding: 10px;">
                <p style="color: var(--text-muted); font-size: 12px; margin-top: 10px; margin-bottom: 5px;">Şifre Belirle (En az 6 karakter):</p>
                <input type="password" id="regPassword" placeholder="En az 6 karakter" style="width: 100%; padding: 10px;">
                
                <button class="btn" style="width: 100%; margin-top: 20px;" onclick="handleRegister()">Doğrulama Kodu Gönder</button>
            </div>

            <!-- ŞİFREMİ UNUTTUM FORMU -->
            <div id="forgotFormContainer" class="modal-body" style="display: none;">
                <p style="color: var(--text-muted); font-size: 12px; margin-bottom: 5px;">Kayıtlı E-posta Adresiniz:</p>
                <input type="email" id="forgotEmail" placeholder="ornek@domain.com" style="width: 100%; padding: 10px;">
                <button class="btn btn-warning" style="width: 100%; margin-top: 15px;" onclick="handleForgotPassword()">Sıfırlama Kodu Gönder</button>
                <button class="btn btn-secondary" style="width: 100%; margin-top: 5px;" onclick="switchAuthTab('login')">Geri Dön</button>
            </div>

            <!-- ŞİFRE SIFIRLAMA ONAY FORMU -->
            <div id="resetFormContainer" class="modal-body" style="display: none;">
                <p style="color: var(--text-muted); font-size: 12px; margin-bottom: 5px;">6 Haneli Kod:</p>
                <input type="text" id="resetCode" placeholder="123456" style="width: 100%; padding: 10px; letter-spacing: 2px;">
                <p style="color: var(--text-muted); font-size: 12px; margin-top: 10px; margin-bottom: 5px;">Yeni Şifre:</p>
                <input type="password" id="newPassword" placeholder="••••••••" style="width: 100%; padding: 10px;">
                <button class="btn" style="width: 100%; margin-top: 15px;" onclick="handleResetPassword()">Şifreyi Değiştir</button>
            </div>
        </div>
    </div>

    <!-- HATA DETAY MODALI -->
    <div class="modal-overlay" id="errorModal">
        <div class="modal-content" style="width: 650px;">
            <div class="modal-header">
                <div class="modal-title" id="modalTitle">Hata Detayı</div>
                <button class="btn btn-secondary" style="padding: 2px 8px;" onclick="closeModal()">✕</button>
            </div>
            <div class="modal-body" id="modalBody"></div>
            <div class="modal-footer" style="margin-top: 25px; display: flex; justify-content: flex-end; gap: 10px;">
                <button class="btn btn-warning" id="resolveBtn">✔ Çözüldü Olarak İşaretle</button>
            </div>
        </div>
    </div>

    <script>
        let authToken = localStorage.getItem('pulsetrace_jwt') || "";
        let userEmail = localStorage.getItem('pulsetrace_email') || "";
        let userRole = localStorage.getItem('pulsetrace_role') || "user";
        let registeredEmailTemp = "";
        let resetEmailTarget = "";
        let currentErrors = [];
        let allProjects = [];
        let activeSeverityFilter = 'Tumu';

        function getAuthHeaders() {
            return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + authToken };
        }

        function checkSession() {
            if (!authToken) {
                document.getElementById('authModal').style.display = 'flex';
                return false;
            }
            document.getElementById('userEmailDisplay').innerText = \`👤 \${userEmail}\`;
            document.getElementById('authModal').style.display = 'none';
            return true;
        }

        function logoutUser() {
            localStorage.clear();
            authToken = "";
            userEmail = "";
            window.location.reload();
        }

        function switchAuthTab(tab) {
            document.getElementById('loginFormContainer').style.display = 'none';
            document.getElementById('registerFormContainer').style.display = 'none';
            document.getElementById('forgotFormContainer').style.display = 'none';
            document.getElementById('resetFormContainer').style.display = 'none';
            
            if (tab === 'login') {
                document.getElementById('tabLoginBtn').classList.add('active');
                document.getElementById('tabRegisterBtn').classList.remove('active');
                document.getElementById('loginFormContainer').style.display = 'flex';
            } else if (tab === 'register') {
                document.getElementById('tabRegisterBtn').classList.add('active');
                document.getElementById('tabLoginBtn').classList.remove('active');
                document.getElementById('registerFormContainer').style.display = 'flex';
            } else if (tab === 'forgot') {
                document.getElementById('forgotFormContainer').style.display = 'flex';
            } else if (tab === 'reset') {
                document.getElementById('resetFormContainer').style.display = 'flex';
            }
        }

        async function handleLogin() {
            const email = document.getElementById('loginEmail').value.trim();
            const password = document.getElementById('loginPassword').value.trim();
            if(!email || !password) return alert('Lütfen alanları doldurun!');

            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                const data = await res.json();
                if (data.success) {
                    authToken = data.token;
                    userEmail = data.email;
                    userRole = data.role;
                    localStorage.setItem('pulsetrace_jwt', authToken);
                    localStorage.setItem('pulsetrace_email', userEmail);
                    localStorage.setItem('pulsetrace_role', userRole);
                    document.getElementById('authModal').style.display = 'none';
                    init();
                } else { alert(data.message); }
            } catch (err) { alert('Giriş hatası.'); }
        }

        async function handleRegister() {
            const email = document.getElementById('regEmail').value.trim();
            const password = document.getElementById('regPassword').value.trim();
            if(!email || !password) return alert('Lütfen alanları doldurun!');
            if(password.length < 6) return alert('Şifre en az 6 karakter olmalıdır!');

            registeredEmailTemp = email;

            try {
                const res = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                const data = await res.json();
                if (data.success) {
                    alert(data.message);
                    document.getElementById('registerFormContainer').innerHTML = \`
                        <div style="color: var(--neon-green); font-size: 12px; margin-bottom: 10px;">
                            ✉️ E-postanıza gelen 6 haneli doğrulama kodunu girin:
                        </div>
                        <input type="text" id="otpCodeVerify" placeholder="123456" maxlength="6" style="width: 100%; padding: 10px; letter-spacing: 3px; text-align: center; font-size: 18px;">
                        <button class="btn" style="width: 100%; margin-top: 15px;" onclick="handleVerifyOtp()">Kodu Doğrula ve Kaydı Tamamla</button>
                    \`;
                } else { alert(data.message); }
            } catch (err) { alert('Kayıt isteği başarısız.'); }
        }

        async function handleVerifyOtp() {
            const code = document.getElementById('otpCodeVerify').value.trim();
            if (!code || code.length !== 6) return alert('Lütfen 6 haneli kodu eksiksiz girin!');

            try {
                const res = await fetch('/api/auth/verify-otp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: registeredEmailTemp, code })
                });
                const data = await res.json();
                if (data.success) {
                    authToken = data.token;
                    userEmail = data.email;
                    userRole = data.role;
                    localStorage.setItem('pulsetrace_jwt', authToken);
                    localStorage.setItem('pulsetrace_email', userEmail);
                    localStorage.setItem('pulsetrace_role', userRole);
                    alert(\`Hesabınız başarıyla doğrulandı!\\n\\nAPI Anahtarınız:\\n\${data.rawApiKey}\`);
                    document.getElementById('authModal').style.display = 'none';
                    init();
                } else { alert(data.message); }
            } catch (err) { alert('Doğrulama hatası.'); }
        }

        async function handleForgotPassword() {
            const email = document.getElementById('forgotEmail').value.trim();
            if(!email) return alert('E-posta girin!');
            resetEmailTarget = email;

            try {
                const res = await fetch('/api/auth/forgot-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email })
                });
                const data = await res.json();
                if (data.success) {
                    alert(data.message);
                    switchAuthTab('reset');
                } else { alert(data.message); }
            } catch (err) { alert('Hata oluştu.'); }
        }

        async function handleResetPassword() {
            const code = document.getElementById('resetCode').value.trim();
            const newPassword = document.getElementById('newPassword').value.trim();
            if(!code || !newPassword) return alert('Tüm alanları doldurun!');

            try {
                const res = await fetch('/api/auth/reset-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: resetEmailTarget, code, newPassword })
                });
                const data = await res.json();
                if (data.success) {
                    alert(data.message);
                    switchAuthTab('login');
                } else { alert(data.message); }
            } catch (err) { alert('İşlem başarısız.'); }
        }

        async function init() {
            if (!checkSession()) return;
            await loadSubscriptionInfo();
            await loadProjects();
            await loadErrors();
        }

        async function loadSubscriptionInfo() {
            try {
                const res = await fetch('/api/user/subscription', { headers: getAuthHeaders() });
                if (res.ok) {
                    const sub = await res.json();
                    document.getElementById('planBadgeText').innerText = sub.plan_type.toUpperCase();
                    document.getElementById('quotaText').innerText = \`Aylık Kullanım: \${sub.monthly_error_count} / \${sub.error_limit} Hata Raporu\`;
                    const percent = Math.min(Math.round((sub.monthly_error_count / sub.error_limit) * 100), 100);
                    document.getElementById('quotaBarFill').style.width = percent + '%';
                    document.getElementById('quotaPercentText').innerText = \`%\${percent} Kullanıldı\`;
                } else if(res.status === 401) { logoutUser(); }
            } catch (err) { console.error(err); }
        }

        async function loadProjects() {
            try {
                const res = await fetch('/api/projects', { headers: getAuthHeaders() });
                if(res.status === 401) { logoutUser(); return; }
                allProjects = await res.json();
                
                const select = document.getElementById('projectSelect');
                const container = document.getElementById('projectListContainer');
                let optionsHTML = '<option value="">Tüm Projelerim</option>';
                let cardsHTML = '';

                allProjects.forEach(p => {
                    optionsHTML += \`<option value="\${p.id}">\${escapeHtml(p.name)}</option>\`;
                    cardsHTML += \`
                        <div class="project-badge-card">
                            <div style="color: #fff; font-weight: bold; margin-bottom: 6px;">📂 \${escapeHtml(p.name)}</div>
                            <div style="color: var(--text-muted); font-size: 11px;">API Anahtarı (Maskelenmiş):</div>
                            <div class="api-key-box">
                                <input type="text" value="\${p.apiKey}" readonly style="border:none; background:transparent; color: var(--neon-green); width: 100%; font-size: 11px;">
                                <button class="btn btn-secondary" style="padding: 4px 8px; font-size: 10px;" onclick="navigator.clipboard.writeText('\${p.apiKey}'); alert('Kopyalandı!');">Kopyala</button>
                            </div>
                        </div>
                    \`;
                });

                select.innerHTML = optionsHTML;
                container.innerHTML = cardsHTML;
            } catch (err) { console.error(err); }
        }

        async function loadErrors() {
            if(!checkSession()) return;
            const selectedProj = document.getElementById('projectSelect').value;
            let url = '/api/errors';
            if (selectedProj) url += '?projectId=' + selectedProj;

            try {
                const res = await fetch(url, { headers: getAuthHeaders() });
                if(res.status === 401) { logoutUser(); return; }
                currentErrors = await res.json();
                filterAndRenderErrors();
                renderTimeline();
            } catch (err) { console.error(err); }
        }

        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
        }

        function setSeverityFilter(sev, el) {
            document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
            el.classList.add('active');
            activeSeverityFilter = sev;
            filterAndRenderErrors();
        }

        function filterAndRenderErrors() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            let totalActive = currentErrors.filter(e => e.status === 'Aktif').length;
            let criticals = currentErrors.filter(e => e.status === 'Aktif' && e.level === 'Kritik').length;
            let affected = currentErrors.filter(e => e.status === 'Aktif').reduce((acc, curr) => acc + curr.affected_users, 0);
            let resolved = currentErrors.filter(e => e.status === 'Çözüldü').length;

            document.getElementById('totalCount').innerText = totalActive;
            document.getElementById('criticalCount').innerText = criticals;
            document.getElementById('affectedCount').innerText = affected;
            document.getElementById('resolvedCount').innerText = resolved;

            let filtered = currentErrors.filter(item => 
                item.message.toLowerCase().includes(searchTerm) || 
                item.url.toLowerCase().includes(searchTerm)
            );

            if (activeSeverityFilter === 'Kritik') filtered = filtered.filter(e => e.level === 'Kritik' && e.status === 'Aktif');
            else if (activeSeverityFilter === 'Uyari') filtered = filtered.filter(e => e.level === 'Uyari' && e.status === 'Aktif');
            else if (activeSeverityFilter === 'Cozuldu') filtered = filtered.filter(e => e.status === 'Çözüldü');
            else if (activeSeverityFilter === 'Tumu') filtered = filtered.filter(e => e.status === 'Aktif');

            document.getElementById('filteredCount').innerText = filtered.length;
            const tbody = document.getElementById('errorTableBody');
            tbody.innerHTML = '';

            filtered.forEach(item => {
                const tr = document.createElement('tr');
                const levelClass = item.level === 'Kritik' ? 'level-kritik' : 'level-uyari';
                const statusBadge = item.status === 'Aktif' ? '<span class="status-aktif">Aktif</span>' : '<span class="status-cozuldu">Çözüldü</span>';
                
                tr.innerHTML = \`
                    <td>#\${escapeHtml(String(item.id))}</td>
                    <td>\${escapeHtml(item.project)}</td>
                    <td class="\${levelClass}">\${escapeHtml(item.level)}</td>
                    <td style="color: #fff;">\${escapeHtml(item.message)}</td>
                    <td><span style="color:var(--info); font-weight:bold;">\${escapeHtml(String(item.count))}x</span></td>
                    <td>\${escapeHtml(String(item.affected_users))} tekil</td>
                    <td>\${statusBadge}</td>
                \`;
                tr.onclick = () => openModal(item.id);
                tbody.appendChild(tr);
            });
        }

        function renderTimeline() {
            const container = document.getElementById('timelineContainer');
            container.innerHTML = '';
            const timeMap = {};
            currentErrors.forEach(e => {
                const hour = e.last_seen ? e.last_seen.substring(0, 5) : "00:00";
                timeMap[hour] = (timeMap[hour] || 0) + e.count;
            });
            const keys = Object.keys(timeMap).sort();
            if(keys.length === 0) {
                container.innerHTML = '<div style="color:var(--text-muted); font-size:12px; font-family:JetBrains Mono;">Henüz veri yok.</div>';
                return;
            }
            keys.forEach(h => {
                const count = timeMap[h];
                container.innerHTML += \`
                    <div class="timeline-bar-wrapper">
                        <div class="timeline-bar" style="height: \${Math.min(count * 15, 65)}px;" title="\${h} - \${count} hata">\${count}</div>
                        <span class="timeline-label" style="font-size:10px; color:var(--text-muted);">\${h}</span>
                    </div>
                \`;
            });
        }

        async function createProject() {
            const nameInput = document.getElementById('newProjectName');
            if(!nameInput.value.trim()) return alert('Proje adı girin!');
            
            const res = await fetch('/api/projects', {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify({ name: nameInput.value })
            });
            const data = await res.json();
            if(data.success) {
                nameInput.value = '';
                alert(\`Proje oluşturuldu!\\n\\nAPI Anahtarınız:\\n\${data.project.apiKey}\`);
                loadProjects();
            } else { alert(data.message); }
        }

        function openModal(id) {
            const err = currentErrors.find(e => e.id === id);
            if(!err) return;
            document.getElementById('modalTitle').innerText = 'Hata Detayı #' + err.id;
            
            const modalBody = document.getElementById('modalBody');
            modalBody.innerHTML = \`
                <div class="modal-row"><span class="modal-label">Seviye:</span><span>\${err.level}</span></div>
                <div class="modal-row"><span class="modal-label">Tekrar:</span><span>\${err.count} Kez</span></div>
                <div class="modal-row"><span class="modal-label">Endpoint:</span><span>\${err.url}</span></div>
                <div><span class="modal-label">Stack Trace:</span><div class="stack-trace">\${escapeHtml(err.stack)}</div></div>
            \`;

            const resolveBtn = document.getElementById('resolveBtn');
            if(err.status === 'Aktif') {
                resolveBtn.style.display = 'inline-block';
                resolveBtn.onclick = async () => {
                    await fetch('/api/errors/' + err.id + '/resolve', { method: 'PATCH', headers: getAuthHeaders() });
                    closeModal();
                    loadErrors();
                };
            } else { resolveBtn.style.display = 'none'; }
            document.getElementById('errorModal').style.display = 'flex';
        }

        function closeModal() { document.getElementById('errorModal').style.display = 'none'; }

        init();
        setInterval(loadErrors, 6000);
    </script>
</body>
</html>`);
});

app.listen(PORT, () => {
    console.log("[PulseTrace Enterprise] Sunucu aktif: http://localhost:" + PORT);
});