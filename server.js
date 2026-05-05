const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const forge = require('node-forge');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const {
  verifyCadesBes, checkOcsp,
  certThumbprintSha1, extractCertsFromCms
} = require('./crypto-verify');

const app = express();
const db = new Database('auth.db');
const TRUSTED_CA = path.join(__dirname, 'ca', 'trusted-ca.pem');

db.exec(`
  CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thumbprint TEXT UNIQUE NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    valid_from TEXT, valid_to TEXT,
    status TEXT DEFAULT 'pending',
    is_admin INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    reviewed_at DATETIME, reviewed_by TEXT
  );
  CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY, nonce_hex TEXT NOT NULL, created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT, thumbprint TEXT, details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

app.use(bodyParser.json({ limit: '8mb' }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 3600_000 }
}));
app.use(express.static(path.join(__dirname, 'public')));

function audit(event, thumbprint, details) {
  db.prepare('INSERT INTO audit_log (event, thumbprint, details) VALUES (?,?,?)')
    .run(event, thumbprint || '', JSON.stringify(details || {}));
}

function parseCertInfo(pem) {
  const cert = forge.pki.certificateFromPem(pem);
  const subject = cert.subject.attributes
    .map(a => `${a.shortName || a.name}=${a.value}`).join(', ');
  const issuer = cert.issuer.attributes
    .map(a => `${a.shortName || a.name}=${a.value}`).join(', ');
  return {
    thumbprint: certThumbprintSha1(pem),
    subject, issuer,
    validFrom: cert.validity.notBefore.toISOString(),
    validTo: cert.validity.notAfter.toISOString()
  };
}

function normalizePem(pem) {
  const clean = pem.replace(/\r/g, '').trim();
  if (clean.includes('BEGIN CERTIFICATE')) return clean + '\n';
  return `-----BEGIN CERTIFICATE-----\n${clean.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
}

// --- auth ---

app.get('/api/auth/challenge', (req, res) => {
  const nonce = crypto.randomBytes(32);
  const id = crypto.randomUUID();
  db.prepare('INSERT INTO challenges (id, nonce_hex, created_at) VALUES (?,?,?)')
    .run(id, nonce.toString('hex'), Date.now());
  res.json({ id, nonce: nonce.toString('hex') });
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { challengeId, signatureCms, certificatePem } = req.body;
    if (!challengeId || !signatureCms || !certificatePem)
      return res.status(400).json({ error: 'Неполные данные' });

    const ch = db.prepare('SELECT * FROM challenges WHERE id=?').get(challengeId);
    if (!ch) return res.status(400).json({ error: 'Challenge не найден' });
    if (Date.now() - ch.created_at > 5 * 60 * 1000) {
      db.prepare('DELETE FROM challenges WHERE id=?').run(challengeId);
      return res.status(400).json({ error: 'Challenge просрочен' });
    }
    db.prepare('DELETE FROM challenges WHERE id=?').run(challengeId);

    const pem = normalizePem(certificatePem);
    const info = parseCertInfo(pem);

    const now = new Date();
    if (new Date(info.validFrom) > now || new Date(info.validTo) < now)
      return res.status(400).json({ error: 'Сертификат просрочен' });

    const data = Buffer.from(ch.nonce_hex, 'hex');
    const sigDer = Buffer.from(signatureCms, 'base64');

    // 1) Проверка подписи CAdES + цепочки
    const v = await verifyCadesBes(data, sigDer);
    if (!v.ok) {
      audit('verify_failed', info.thumbprint, { stderr: v.stderr.slice(0, 500) });
      return res.status(401).json({
        error: 'Подпись или цепочка не прошли проверку',
        details: v.stderr.split('\n').slice(0, 5).join(' | ')
      });
    }

    // 2) Сверка сертификата в CMS с присланным
    const cmsPems = await extractCertsFromCms(sigDer);
    const found = cmsPems.split(/(?=-----BEGIN CERTIFICATE-----)/g)
      .filter(Boolean)
      .some(c => certThumbprintSha1(c) === info.thumbprint);
    if (!found) {
      audit('cert_mismatch', info.thumbprint, {});
      return res.status(401).json({ error: 'Сертификат не соответствует подписи' });
    }

    // 3) Явная OCSP-проверка (дополнительно)
    const ocsp = await checkOcsp(pem);
    if (!ocsp.ok) {
      audit('ocsp_failed', info.thumbprint, { status: ocsp.status });
      return res.status(401).json({
        error: 'Сертификат не прошёл OCSP-проверку',
        status: ocsp.status
      });
    }

    audit('signature_ok', info.thumbprint, { ocsp: ocsp.status });

    // 4) Статус в БД
    const record = db.prepare('SELECT * FROM certificates WHERE thumbprint=?').get(info.thumbprint);
    if (!record) {
      db.prepare(`INSERT INTO certificates
        (thumbprint, subject, issuer, cert_pem, valid_from, valid_to, status)
        VALUES (?,?,?,?,?,?, 'pending')`)
        .run(info.thumbprint, info.subject, info.issuer, pem, info.validFrom, info.validTo);
      audit('cert_registered', info.thumbprint, { subject: info.subject });
      return res.json({ status: 'pending', message: 'Сертификат отправлен администратору' });
    }
    if (record.status === 'pending')
      return res.json({ status: 'pending', message: 'Ожидает подтверждения' });
    if (record.status === 'rejected')
      return res.status(403).json({ status: 'rejected', message: 'Доступ запрещён' });

    req.session.user = {
      thumbprint: info.thumbprint, subject: info.subject, isAdmin: !!record.is_admin
    };
    audit('login_ok', info.thumbprint, {});
    res.json({ status: 'approved', user: req.session.user });

  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Внутренняя ошибка', message: e.message });
  }
});

app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

// --- middleware ---

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Не авторизован' });
  const c = db.prepare('SELECT status, is_admin FROM certificates WHERE thumbprint=?')
    .get(req.session.user.thumbprint);
  if (!c || c.status !== 'approved') {
    req.session.destroy(() => {});
    return res.status(403).json({ error: 'Доступ отозван' });
  }
  req.session.user.isAdmin = !!c.is_admin;
  next();
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.session.user.isAdmin) return res.status(403).json({ error: 'Нет прав' });
    next();
  });
}

// --- admin API ---

app.get('/api/admin/certificates', requireAdmin, (req, res) => {
  res.json(db.prepare(`SELECT id, thumbprint, subject, issuer, valid_from, valid_to,
    status, is_admin, created_at FROM certificates ORDER BY created_at DESC`).all());
});

app.post('/api/admin/certificates/:id/approve', requireAdmin, (req, res) => {
  db.prepare(`UPDATE certificates SET status='approved',
    reviewed_at=CURRENT_TIMESTAMP, reviewed_by=? WHERE id=?`)
    .run(req.session.user.subject, req.params.id);
  audit('approve', '', { id: req.params.id, by: req.session.user.subject });
  res.json({ ok: true });
});

app.post('/api/admin/certificates/:id/reject', requireAdmin, (req, res) => {
  db.prepare(`UPDATE certificates SET status='rejected',
    reviewed_at=CURRENT_TIMESTAMP, reviewed_by=? WHERE id=?`)
    .run(req.session.user.subject, req.params.id);
  audit('reject', '', { id: req.params.id, by: req.session.user.subject });
  res.json({ ok: true });
});

app.get('/api/admin/audit', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 200').all());
});

app.get('/api/profile', requireAuth, (req, res) => res.json({ user: req.session.user }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ http://localhost:${PORT}`));
