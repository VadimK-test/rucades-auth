const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const CRYPTCP = process.env.CRYPTCP_BIN || '/opt/cprocsp/bin/amd64/cryptcp';
const CERTMGR = process.env.CERTMGR_BIN || '/opt/cprocsp/bin/amd64/certmgr';

function run(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const proc = spawn(cmd, args, { ...opts, env: { ...process.env, ...(opts.env || {}) } });
    let stdout = '', stderr = '';
    proc.stdout.on('data', d => stdout += d.toString('utf8'));
    proc.stderr.on('data', d => stderr += d.toString('utf8'));
    proc.on('close', code => resolve({ code, stdout, stderr }));
    proc.on('error', err => resolve({ code: -1, stdout: '', stderr: err.message }));
  });
}

/**
 * Проверка CAdES-BES (отсоединённой) подписи через cryptcp.
 * --- включает проверку цепочки (revocation online).
 * @param {Buffer} data         - исходные данные
 * @param {Buffer} sigDer       - CMS/CAdES подпись
 * @param {Object} opts         - { ocsp: true|false, crl: true|false }
 */
async function verifyCadesBes(data, sigDer, opts = {}) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cp-'));
  const dataFile = path.join(tmp, 'data.bin');
  const sigFile  = path.join(tmp, 'data.bin.sgn');
  fs.writeFileSync(dataFile, data);
  fs.writeFileSync(sigFile, sigDer);

  // cryptcp -vsignf  — проверка отсоединённой подписи
  // -nochain  — отключить проверку цепочки (нам нужна, НЕ ставим)
  // -errchain — завершать с ошибкой, если цепочка не проверяется
  // По умолчанию cryptcp проверяет отзывы по CRL; для OCSP нужен параметр -f с политикой
  const args = [
    '-vsignf',
    '-dir', tmp,
    '-nochain' in opts && opts.nochain ? '-nochain' : '-errchain',
    sigFile
  ].filter(Boolean);

  // Принудительно убеждаемся, что имя данных = имя подписи без .sgn
  const res = await run(CRYPTCP, args);

  const ok = res.code === 0 &&
             /Signature's verified|Подпись проверена/i.test(res.stdout + res.stderr);

  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
  return { ok, code: res.code, stdout: res.stdout, stderr: res.stderr };
}

/**
 * Явная OCSP-проверка сертификата через cryptcp -ocsp.
 */
async function checkOcsp(certPem) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ocsp-'));
  const certFile = path.join(tmp, 'cert.cer');
  fs.writeFileSync(certFile, certPem);

  // cryptcp -ocsp <cert>  — запрашивает OCSP-ответ у УЦ из AIA
  const res = await run(CRYPTCP, ['-ocsp', '-f', certFile, certFile]);
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}

  const text = res.stdout + res.stderr;
  const good = /Certificate status:\s*good|status:\s*good|good/i.test(text);
  const revoked = /revoked/i.test(text);

  return {
    ok: res.code === 0 && good && !revoked,
    status: revoked ? 'revoked' : (good ? 'good' : 'unknown'),
    raw: text
  };
}

/**
 * Импорт корневого/промежуточного сертификата в хранилище root/ca CSP.
 * Выполняется один раз при настройке системы.
 */
async function installRootCert(pemPath) {
  return run(CERTMGR, ['-inst', '-store', 'mRoot', '-file', pemPath]);
}

function certThumbprintSha1(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const der = Buffer.from(b64, 'base64');
  return crypto.createHash('sha1').update(der).digest('hex').toUpperCase();
}

/**
 * Извлечение сертификатов из CMS (через openssl - достаточно для парсинга).
 */
async function extractCertsFromCms(sigDer) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ext-'));
  const sigFile = path.join(tmp, 'sig.p7s');
  fs.writeFileSync(sigFile, sigDer);
  const res = await run('openssl', ['pkcs7', '-in', sigFile, '-inform', 'DER',
    '-print_certs', '-outform', 'PEM']);
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
  if (res.code !== 0) throw new Error(res.stderr);
  return res.stdout;
}

module.exports = {
  verifyCadesBes,
  checkOcsp,
  installRootCert,
  certThumbprintSha1,
  extractCertsFromCms
};
