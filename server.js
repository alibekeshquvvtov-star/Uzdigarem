// Ilova serveri: tashqi kutubxonasiz (faqat Node.js >= 18)
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = process.env.PORT || 3000;
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUB = __dirname;
fs.mkdirSync(DATA, { recursive: true });
const FILE = path.join(DATA, 'profiles.json');

let PASS = process.env.ADMIN_PASSWORD;
if (!PASS) { PASS = crypto.randomBytes(6).toString('hex'); console.log('ADMIN_PASSWORD berilmagan. Vaqtinchalik admin paroli: ' + PASS); }
const SECRET = crypto.randomBytes(32), TTL = 12 * 3600e3;

const sign = e => e + '.' + crypto.createHmac('sha256', SECRET).update(String(e)).digest('hex');
function isAdmin(req) {
  const t = (req.headers.authorization || '').replace(/^Bearer /, '');
  const [e] = t.split('.');
  if (!e || +e < Date.now()) return false;
  const x = sign(e);
  return t.length === x.length && crypto.timingSafeEqual(Buffer.from(t), Buffer.from(x));
}
function samePass(a) {
  const h = s => crypto.createHash('sha256').update(String(s)).digest();
  return crypto.timingSafeEqual(h(a), h(PASS));
}
const fails = {};
function tooMany(ip) { const f = fails[ip]; return f && f.n >= 5 && Date.now() - f.t < 10 * 60e3; }

function load() { try { return JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) { return []; } }
function save(a) { const t = FILE + '.tmp'; fs.writeFileSync(t, JSON.stringify(a)); fs.renameSync(t, FILE); }
const CFILE = path.join(DATA, 'contacts.json'), cHits = {};
function loadC() { try { return JSON.parse(fs.readFileSync(CFILE, 'utf8')); } catch (e) { return []; } }
function saveC(a) { const t = CFILE + '.tmp'; fs.writeFileSync(t, JSON.stringify(a)); fs.renameSync(t, CFILE); }
const AFILE = path.join(DATA, 'accounts.json'), aHits = {};
function loadA() { try { return JSON.parse(fs.readFileSync(AFILE, 'utf8')); } catch (e) { return {}; } }
function saveA(a) { const t = AFILE + '.tmp'; fs.writeFileSync(t, JSON.stringify(a)); fs.renameSync(t, AFILE); }
function clean(a) {
  if (!Array.isArray(a) || a.length > 5000) return null;
  const out = [];
  for (const p of a) {
    if (!p || typeof p.u !== 'string' || !/^[a-z0-9._]{1,30}$/.test(p.u)) return null;
    const o = { u: p.u, v: !!p.v };
    if (Number.isFinite(p.b) && p.b > 0) o.b = p.b;
    if (typeof p.ph === 'string' && /^\d{9}$/.test(p.ph)) o.ph = p.ph;
    out.push(o);
  }
  return out;
}
function body(req) {
  return new Promise((ok, no) => {
    let s = '';
    req.on('data', c => { s += c; if (s.length > 1e6) { no(new Error('big')); req.destroy(); } });
    req.on('end', () => { try { ok(JSON.parse(s || 'null')); } catch (e) { no(e); } });
  });
}
function send(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
}
function page(res, name) {
  fs.readFile(path.join(PUB, name), (e, d) => {
    if (e) return send(res, 404, { error: 'topilmadi' });
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff' });
    res.end(d);
  });
}

http.createServer(async (req, res) => {
  const url = req.url.split('?')[0], ip = req.socket.remoteAddress;
  try {
    if (req.method === 'GET' && url === '/') return page(res, 'index-v2.html');
    if (req.method === 'GET' && url === '/admin') return page(res, 'admin-v2.html');
    if (req.method === 'GET' && url === '/blok') return fs.readFile(path.join(PUB, 'index-v2.html'), 'utf8', (e, d) => {
      if (e) return send(res, 404, { error: 'topilmadi' });
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff' });
      res.end(d.replace('</body>', '<script>window.addEventListener("load",function(){setTimeout(function(){if(window.openAdm)openAdm()},300)})</script></body>'));
    });

    if (req.method === 'GET' && url === '/api/profiles') {
      const adm = isAdmin(req);
      return send(res, 200, load().map(p => adm ? p : { u: p.u, v: p.v, b: p.b }));
    }
    if (req.method === 'POST' && url === '/api/admin/login') {
      if (tooMany(ip)) return send(res, 429, { error: "Ko'p urinish. 10 daqiqadan keyin qayta urinib ko'ring." });
      const b = await body(req);
      if (b && typeof b.password === 'string' && samePass(b.password)) {
        delete fails[ip];
        return send(res, 200, { token: sign(Date.now() + TTL) });
      }
      const f = fails[ip] = fails[ip] || { n: 0, t: 0 }; f.n++; f.t = Date.now();
      return send(res, 401, { error: "Parol noto'g'ri" });
    }
    if (req.method === 'PUT' && url === '/api/profiles') {
      if (!isAdmin(req)) return send(res, 401, { error: 'Admin kerak' });
      const a = clean(await body(req));
      if (!a) return send(res, 400, { error: "Noto'g'ri ma'lumot" });
      save(a);
      return send(res, 200, { ok: true });
    }
    if (req.method === 'POST' && url === '/api/contact') {
      const now = Date.now(), h = (cHits[ip] = (cHits[ip] || []).filter(t => now - t < 3600e3));
      if (h.length >= 3) return send(res, 429, { error: "Ko'p so'rov" });
      const b = await body(req);
      if (!b || typeof b.phone !== 'string' || !/^\d{9}$/.test(b.phone)) return send(res, 400, { error: "Noto'g'ri raqam" });
      const user = typeof b.user === 'string' && /^[a-z0-9._]{1,30}$/.test(b.user) ? b.user : '';
      h.push(now);
      const c = loadC(); c.unshift({ id: now, phone: b.phone, user: user, ts: now });
      saveC(c.slice(0, 200));
      return send(res, 200, { ok: true });
    }
    if (req.method === 'GET' && url === '/api/contacts') {
      if (!isAdmin(req)) return send(res, 401, { error: 'Admin kerak' });
      return send(res, 200, loadC());
    }
    if (req.method === 'DELETE' && url.startsWith('/api/contacts/')) {
      if (!isAdmin(req)) return send(res, 401, { error: 'Admin kerak' });
      const id = +url.slice(14);
      saveC(loadC().filter(c => c.id !== id));
      return send(res, 200, { ok: true });
    }
    if (req.method === 'POST' && url === '/api/account') {
      const now = Date.now(), h = (aHits[ip] = (aHits[ip] || []).filter(t => now - t < 3600e3));
      if (h.length >= 60) return send(res, 429, { error: "Ko'p so'rov" });
      const b = await body(req);
      if (!b || typeof b.phone !== 'string' || !/^\d{9}$/.test(b.phone) || typeof b.u !== 'string' || !/^[a-z0-9._]{1,30}$/.test(b.u)) return send(res, 400, { error: "Noto'g'ri ma'lumot" });
      h.push(now);
      const A = loadA(); A[b.phone] = { u: b.u, n: typeof b.n === 'string' ? b.n.slice(0, 60) : '', ts: now };
      const ks = Object.keys(A); if (ks.length > 5000) delete A[ks[0]];
      saveA(A);
      return send(res, 200, { ok: true });
    }
    if (req.method === 'GET' && url.startsWith('/api/account/')) {
      if (!isAdmin(req)) return send(res, 401, { error: 'Admin kerak' });
      const x = loadA()[url.slice(13)];
      return x ? send(res, 200, x) : send(res, 404, { error: 'topilmadi' });
    }
    send(res, 404, { error: 'topilmadi' });
  } catch (e) { send(res, 400, { error: 'Xato so\'rov' }); }
}).listen(PORT, () => console.log('Server ishlayapti: http://localhost:' + PORT + '  (admin: /admin)'));
