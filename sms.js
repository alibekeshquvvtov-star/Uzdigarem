// SMS tasdiqlash moduli (Eskiz.uz). Express serveringizga ulang:
//   const sms = require('./sms'); app.use(express.json()); app.use('/api/sms', sms);
// Render > Environment: ESKIZ_EMAIL, ESKIZ_PASSWORD, (ixtiyoriy) SMS_TEXT
// Node 18+ kerak (global fetch).
const express = require('express');
const crypto = require('crypto');
const router = express.Router();

const TTL = 5 * 60 * 1000, RESEND_GAP = 60 * 1000, MAX_TRIES = 5, DAILY_MAX = 5;
// Eskiz matni oldindan tasdiqlangan shablon bo'lishi shart. {code} o'rniga kod qo'yiladi.
const TEXT = process.env.SMS_TEXT || 'Chiroy sekrobti tasdiqlash kodi: {code}';
const store = new Map();   // phone -> {hash, exp, tries, last}
const daily = new Map();   // phone -> {day, n}

let token = null, tokenAt = 0;
async function eskizToken(force) {
  if (!force && token && Date.now() - tokenAt < 20 * 24 * 3600 * 1000) return token;
  const body = new URLSearchParams({ email: process.env.ESKIZ_EMAIL, password: process.env.ESKIZ_PASSWORD });
  const r = await fetch('https://notify.eskiz.uz/api/auth/login', { method: 'POST', body });
  const d = await r.json();
  if (!d.data || !d.data.token) throw new Error('eskiz login');
  token = d.data.token; tokenAt = Date.now(); return token;
}
async function sendSms(phone, text, retry) {
  const t = await eskizToken(retry);
  const body = new URLSearchParams({ mobile_phone: '998' + phone, message: text, from: process.env.SMS_FROM || '4546' });
  const r = await fetch('https://notify.eskiz.uz/api/message/sms/send', {
    method: 'POST', headers: { Authorization: 'Bearer ' + t }, body });
  if (r.status === 401 && !retry) return sendSms(phone, text, true);
  if (!r.ok) throw new Error('eskiz send ' + r.status);
}
const hash = (phone, code) => crypto.createHash('sha256').update(phone + ':' + code + ':' + (process.env.ESKIZ_PASSWORD || '')).digest('hex');
const ok9 = p => /^\d{9}$/.test(p || '');

router.post('/send', async (req, res) => {
  const phone = String((req.body || {}).phone || '');
  if (!ok9(phone)) return res.status(400).json({ error: "Telefon raqam noto'g'ri." });
  const now = Date.now(), rec = store.get(phone);
  if (rec && now - rec.last < RESEND_GAP)
    return res.status(429).json({ error: 'Kodni qayta yuborish uchun ' + Math.ceil((RESEND_GAP - (now - rec.last)) / 1000) + ' soniya kuting.' });
  const day = new Date().toISOString().slice(0, 10), d = daily.get(phone);
  const n = d && d.day === day ? d.n : 0;
  if (n >= DAILY_MAX) return res.status(429).json({ error: "Bugun juda ko'p urinish bo'ldi. Ertaga urinib ko'ring." });
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  try { await sendSms(phone, TEXT.replace('{code}', code)); }
  catch (e) { console.error(e.message); return res.status(502).json({ error: "SMS yuborib bo'lmadi. Keyinroq urinib ko'ring." }); }
  store.set(phone, { hash: hash(phone, code), exp: now + TTL, tries: 0, last: now });
  daily.set(phone, { day, n: n + 1 });
  res.json({ ok: true });
});

router.post('/verify', (req, res) => {
  const { phone, code } = req.body || {};
  const rec = store.get(String(phone));
  if (!rec || Date.now() > rec.exp) return res.status(400).json({ error: 'Kod eskirgan. Qaytadan yuboring.' });
  if (rec.tries >= MAX_TRIES) { store.delete(String(phone)); return res.status(429).json({ error: "Juda ko'p xato. Yangi kod so'rang." }); }
  rec.tries++;
  const a = Buffer.from(hash(String(phone), String(code || '')));
  const b = Buffer.from(rec.hash);
  if (!crypto.timingSafeEqual(a, b)) return res.status(400).json({ error: "Kod noto'g'ri." });
  store.delete(String(phone));
  res.json({ ok: true });
});

setInterval(() => { const t = Date.now(); store.forEach((v, k) => { if (t > v.exp) store.delete(k); }); }, 60000).unref();
module.exports = router;
