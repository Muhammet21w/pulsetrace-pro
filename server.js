require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'pulsetrace_super_secure_enterprise_secret_2026';

app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

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

// Kayıt Ol
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: "E-posta ve şifre zorunludur." });

    if (password.length < 6) {
        return res.status(400).json({ success: false, message: "Şifre en az 6 karakter uzunluğunda olmalıdır!" });
    }

    const planType = 'free';
    const limit = 3000;
    const trialEndsAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    try {
        const saltRounds = 12;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        const result = db.transaction(() => {
            const info = db.prepare('INSERT INTO users (email, password_hash, plan_type, error_limit, role, trial_ends_at) VALUES (?, ?, ?, ?, ?, ?)')
                .run(email, passwordHash, planType, limit, 'user', trialEndsAt);
            
            const rawKey = "pt_live_" + crypto.randomBytes(16).toString('hex');
            const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
            const keyPrefix = rawKey.substring(0, 10) + "...";
            
            db.prepare('INSERT INTO projects (user_id, name, api_key_hash, api_key_prefix) VALUES (?, ?, ?, ?)')
                .run(info.lastInsertRowid, 'Varsayılan Proje', keyHash, keyPrefix);

            return { userId: info.lastInsertRowid, rawApiKey: rawKey };
        })();

        const token = jwt.sign({ userId: result.userId, email }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, token, userId: result.userId, email, rawApiKey: result.rawApiKey, role: 'user' });
    } catch (err) {
        res.status(400).json({ success: false, message: "Bu e-posta adresi zaten kullanımda." });
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

// Şifre Sıfırlama Kodu İsteme (ForgotPassword)
app.post('/api/auth/forgot-password', (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: "E-posta adresi gereklidir." });

    const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (!user) {
        // Güvenlik açısından e-posta kayıtlı olmasa bile başarılı dönülebilir ama test için bilgi veriyoruz:
        return res.json({ success: true, message: "Eğer bu e-posta adresi sistemimizde kayıtlıysa sıfırlama kodu gönderilmiştir." });
    }

    // 6 haneli rastgele kod üret
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 dakika geçerli

    db.prepare('UPDATE users SET reset_code = ?, reset_code_expires = ? WHERE id = ?').run(resetCode, expiresAt, user.id);

    // Gerçek sistemde burada Nodemailer ile e-posta gönderilir. 
    // Yerel testlerde kolaylık olması için kodu yanıtta simüle ediyoruz:
    console.log(`[Şifre Sıfırlama] ${email} için doğrulama kodu: ${resetCode}`);

    res.json({ 
        success: true, 
        message: "Şifre sıfırlama doğrulama kodu e-posta adresinize gönderildi.",
        debugCode: resetCode // Test aşamasında kolaylık olması için gösteriliyor
    });
});

// Şifre Sıfırlama / Güncelleme (Reset Password)
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

app.post('/api/user/upgrade', verifyJwtSession, (req, res) => {
    const { plan } = req.body;
    if (!plan || (plan !== 'pro' && plan !== 'enterprise' && plan !== 'free')) {
        return res.status(400).json({ success: false, message: "Geçersiz paket seçimi." });
    }

    let limit = plan === 'pro' ? 50000 : (plan === 'enterprise' ? 999999 : 3000);

    try {
        db.prepare('UPDATE users SET plan_type = ?, error_limit = ? WHERE id = ?').run(plan, limit, req.user.id);
        res.json({ success: true, message: "Paket başarıyla güncellendi." });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/payment/notify', verifyJwtSession, (req, res) => {
    const { plan, amount, method, note } = req.body;
    if (!plan || !amount) return res.status(400).json({ success: false, message: "Eksik bilgi." });

    try {
        db.prepare('INSERT INTO payment_notifications (user_id, plan, amount, method, note) VALUES (?, ?, ?, ?, ?)')
            .run(req.user.id, plan, amount, method || 'Havale/EFT', note || '');
        res.json({ success: true, message: "Ödeme bildiriminiz alındı. Admin onayından sonra paketiniz aktif edilecektir." });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/admin/payments', verifyJwtSession, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: "Yetkisiz erişim." });
    
    const payments = db.prepare(`
        SELECT p.*, u.email as user_email 
        FROM payment_notifications p 
        JOIN users u ON p.user_id = u.id 
        ORDER BY p.id DESC
    `).all();
    res.json(payments);
});

app.post('/api/admin/payments/:id/approve', verifyJwtSession, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: "Yetkisiz erişim." });
    
    const paymentId = parseInt(req.params.id);
    const payment = db.prepare('SELECT * FROM payment_notifications WHERE id = ?').get(paymentId);
    if (!payment) return res.status(404).json({ success: false, message: "Bildirim bulunamadı." });

    let limit = payment.plan === 'pro' ? 50000 : (payment.plan === 'enterprise' ? 999999 : 3000);

    try {
        db.transaction(() => {
            db.prepare('UPDATE users SET plan_type = ?, error_limit = ? WHERE id = ?').run(payment.plan, limit, payment.user_id);
            db.prepare("UPDATE payment_notifications SET status = 'Onaylandı' WHERE id = ?").run(paymentId);
        })();
        res.json({ success: true, message: "Ödeme onaylandı ve kullanıcının paketi yükseltildi." });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
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

app.post('/api/report', async (req, res) => {
    const rawApiKey = req.headers['x-api-key'];
    if (!rawApiKey) return res.status(401).json({ success: false, message: "API Key eksik." });

    const apiKeyHash = crypto.createHash('sha256').update(rawApiKey).digest('hex');
    const project = db.prepare('SELECT * FROM projects WHERE api_key_hash = ?').get(apiKeyHash);
    if (!project) return res.status(401).json({ success: false, message: "Geçersiz API Key!" });

    const user = db.prepare('SELECT id, monthly_error_count, error_limit, trial_ends_at, plan_type FROM users WHERE id = ?').get(project.user_id);
    
    if (user.plan_type === 'free' && user.trial_ends_at && new Date() > new Date(user.trial_ends_at)) {
        return res.status(403).json({ success: false, message: "7 günlük deneme süreniz dolmuştur. Lütfen paketinizi yükseltin." });
    }

    if (user.monthly_error_count >= user.error_limit) {
        return res.status(429).json({ success: false, message: "Aylık hata raporlama limiti doldu (429 Too Many Requests)." });
    }

    const errorMsg = req.body.message || "Bilinmeyen hata";
    const errorStack = req.body.stack || "Stack trace yok";
    const level = req.body.level || "Kritik";
    const url = req.body.url || "/";
    const clientUuid = req.body.clientUuid || "anonim-user-" + Math.random();
    const fingerprint = crypto.createHash('md5').update(errorMsg + errorStack).digest('hex');
    const nowTime = new Date().toLocaleTimeString();

    try {
        const result = db.transaction(() => {
            db.prepare('UPDATE users SET monthly_error_count = monthly_error_count + 1 WHERE id = ?').run(user.id);

            const existingError = db.prepare('SELECT * FROM errors WHERE project_id = ? AND fingerprint = ? AND status = ?').get(project.id, fingerprint, 'Aktif');

            if (existingError) {
                const clientExists = db.prepare('SELECT * FROM error_clients WHERE error_id = ? AND client_uuid = ?').get(existingError.id, clientUuid);
                let newAffectedCount = existingError.affected_users;

                if (!clientExists) {
                    db.prepare('INSERT INTO error_clients (error_id, client_uuid) VALUES (?, ?)').run(existingError.id, clientUuid);
                    newAffectedCount += 1;
                }

                db.prepare('UPDATE errors SET count = count + 1, affected_users = ?, last_seen = ? WHERE id = ?')
                    .run(newAffectedCount, nowTime, existingError.id);

                return { errorId: existingError.id, action: "updated" };
            }

            const info = db.prepare(`
                INSERT INTO errors (project_id, level, status, message, stack, url, ip, browser, fingerprint, count, affected_users, first_seen, last_seen)
                VALUES (?, ?, 'Aktif', ?, ?, ?, ?, ?, ?, 1, 1, ?, ?)
            `).run(project.id, level, errorMsg, errorStack, url, req.ip || "127.0.0.1", req.body.browser || "SDK", fingerprint, nowTime, nowTime);

            db.prepare('INSERT INTO error_clients (error_id, client_uuid) VALUES (?, ?)').run(info.lastInsertRowid, clientUuid);

            return { errorId: info.lastInsertRowid, action: "created" };
        })();

        res.json({ success: true, ...result });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
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

app.listen(PORT, () => {
    console.log("[PulseTrace Enterprise] Şifre Sıfırlama Modüllü Sunucu aktif: http://localhost:" + PORT);
});