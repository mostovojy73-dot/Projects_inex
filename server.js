import express from 'express';
import crypto from 'node:crypto';
import { google } from 'googleapis';

const { BOT_TOKEN, SHEET_ID, GOOGLE_CREDENTIALS, WEBAPP_URL, SELF_PING_URL } = process.env;
const ids = k => (process.env[k] || '').split(',').map(s => s.trim()).filter(Boolean);
const OWNERS = ids('OWNER_IDS'), VIEWERS = ids('VIEWER_IDS'); // OWNER_IDS: могут менять, VIEWER_IDS: только смотрят и скачивают
if (!BOT_TOKEN || !SHEET_ID || !GOOGLE_CREDENTIALS) { console.error('Заполните BOT_TOKEN, SHEET_ID и GOOGLE_CREDENTIALS'); process.exit(1); }

const T = { obj: 'Объекты', info: 'Инфо', doc: 'Файлы' };
const HEAD = { [T.obj]: ['Объект', 'Адрес', 'Статус'], [T.info]: ['Объект', 'Поле', 'Значение'],
  [T.doc]: ['ID', 'Объект', 'Раздел', 'Документ', 'Версия', 'Ссылка', 'Дата', 'Комментарий', 'Кто'] };
const auth = new google.auth.GoogleAuth({ credentials: JSON.parse(GOOGLE_CREDENTIALS),
  scopes: ['https://www.googleapis.com/auth/spreadsheets', 'https://www.googleapis.com/auth/drive.readonly'] });
const sheets = google.sheets({ version: 'v4', auth }), drive = google.drive({ version: 'v3', auth });
const q = t => `'${t}'`;

let ready;
const ensureTabs = () => (ready ||= (async () => {
  const meta = await sheets.spreadsheets.get({ spreadsheetId: SHEET_ID });
  const have = meta.data.sheets.map(s => s.properties.title), add = Object.values(T).filter(t => !have.includes(t));
  if (add.length) await sheets.spreadsheets.batchUpdate({ spreadsheetId: SHEET_ID,
    requestBody: { requests: add.map(title => ({ addSheet: { properties: { title } } })) } });
  for (const t of add) await sheets.spreadsheets.values.update({ spreadsheetId: SHEET_ID, range: `${q(t)}!A1`,
    valueInputOption: 'RAW', requestBody: { values: [HEAD[t]] } });
})().catch(e => { ready = null; throw e; }));

const text = (v, n) => String(v ?? '').trim().slice(0, n);
async function readAll() {
  await ensureTabs();
  const r = await sheets.spreadsheets.values.batchGet({ spreadsheetId: SHEET_ID, valueRenderOption: 'UNFORMATTED_VALUE',
    ranges: [`${q(T.obj)}!A2:C`, `${q(T.info)}!A2:C`, `${q(T.doc)}!A2:I`] });
  const [o, i, d] = r.data.valueRanges.map(v => v.values || []);
  return {
    objects: o.filter(r => r[0]).map(r => ({ name: String(r[0]), addr: String(r[1] ?? ''), status: String(r[2] ?? '') })),
    info: i.filter(r => r[0] && r[1]).map(r => ({ obj: String(r[0]), key: String(r[1]), val: String(r[2] ?? '') })),
    docs: d.filter(r => r[0]).map(r => ({ id: String(r[0]), obj: String(r[1]), section: String(r[2] || 'Прочее'), title: String(r[3]),
      ver: Number(r[4]) || 1, url: String(r[5]), date: String(r[6] ?? ''), note: String(r[7] ?? ''), who: String(r[8] ?? '') })),
  };
}
const append = (t, row) => sheets.spreadsheets.values.append({ spreadsheetId: SHEET_ID, range: `${q(t)}!A1`,
  valueInputOption: 'RAW', insertDataOption: 'INSERT_ROWS', requestBody: { values: [row] } });
const today = () => new Date().toLocaleDateString('sv-SE', { timeZone: process.env.TZ_NAME || 'Europe/Moscow' });
const same = (a, b) => String(a).trim().toLowerCase() === String(b).trim().toLowerCase();

function verify(initData) { // подпись Telegram: только настоящие данные из Mini App
  const p = new URLSearchParams(initData), hash = p.get('hash'); p.delete('hash');
  if (!hash) return null;
  const str = [...p.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => `${k}=${v}`).join('\n');
  const secret = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
  const a = Buffer.from(crypto.createHmac('sha256', secret).update(str).digest('hex')), b = Buffer.from(hash);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  if (Date.now() / 1000 - Number(p.get('auth_date')) > 86400) return null;
  try { return JSON.parse(p.get('user')); } catch { return null; }
}
const guard = (req, res, next) => {
  const h = req.get('authorization') || '', u = h.startsWith('tma ') ? verify(h.slice(4)) : null;
  if (!u) return res.status(401).json({ error: 'auth' });
  const id = String(u.id);
  req.role = OWNERS.includes(id) ? 'owner' : VIEWERS.includes(id) ? 'viewer' : null;
  if (!req.role) return res.status(403).json({ error: 'forbidden', id });
  req.who = u.first_name || id; next();
};
const owner = (req, res, next) => (req.role === 'owner' ? next() : res.status(403).json({ error: 'owner only' }));
const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e.message); res.status(500).json({ error: 'server' }); });

// Ссылки на скачивание живут 10 минут и подписаны сервером
const sign = s => crypto.createHmac('sha256', 'dl:' + BOT_TOKEN).update(s).digest('base64url');
const mkToken = id => { const b = Buffer.from(JSON.stringify({ id, exp: Date.now() + 600000 })).toString('base64url'); return `${b}.${sign(b)}`; };
function readToken(t) {
  const [b, s] = String(t).split('.');
  if (!b || !s || sign(b) !== s) return null;
  try { const j = JSON.parse(Buffer.from(b, 'base64url')); return j.exp > Date.now() ? j.id : null; } catch { return null; }
}

const app = express();
app.use(express.json({ limit: '20kb' }));
app.get('/health', (_, res) => res.send('ok'));
app.use(express.static('public', { setHeaders: (res, p) => res.setHeader('Cache-Control', p.endsWith('.html') ? 'no-cache' : 'public, max-age=86400') }));

app.get('/api/data', guard, wrap(async (req, res) => res.json({ ...(await readAll()), role: req.role })));

app.post('/api/object', guard, owner, wrap(async (req, res) => {
  const name = text(req.body.name, 80); if (!name) return res.status(400).json({ error: 'name' });
  if ((await readAll()).objects.some(o => same(o.name, name))) return res.status(409).json({ error: 'exists' });
  await append(T.obj, [name, text(req.body.addr, 200), text(req.body.status, 40) || 'В работе']); res.json({ ok: true });
}));

app.post('/api/info', guard, owner, wrap(async (req, res) => {
  const obj = text(req.body.obj, 80), key = text(req.body.key, 60), val = text(req.body.val, 500);
  if (!obj || !key) return res.status(400).json({ error: 'fields' });
  const rows = (await sheets.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range: `${q(T.info)}!A2:B` })).data.values || [];
  const i = rows.findIndex(r => same(r[0], obj) && same(r[1], key)); // такое поле уже есть: обновляем значение
  if (i >= 0) await sheets.spreadsheets.values.update({ spreadsheetId: SHEET_ID, range: `${q(T.info)}!C${i + 2}`,
    valueInputOption: 'RAW', requestBody: { values: [[val]] } });
  else await append(T.info, [obj, key, val]);
  res.json({ ok: true });
}));

// Новый документ или новая версия: если документ с таким названием уже есть, версия растёт, старые строки остаются
app.post('/api/doc', guard, owner, wrap(async (req, res) => {
  const obj = text(req.body.obj, 80), title = text(req.body.title, 120), url = text(req.body.url, 1000);
  if (!obj || !title || !/^https?:\/\//i.test(url)) return res.status(400).json({ error: 'fields' });
  const prev = (await readAll()).docs.filter(d => same(d.obj, obj) && same(d.title, title));
  const ver = prev.reduce((m, d) => Math.max(m, d.ver), 0) + 1;
  const section = prev[0]?.section || text(req.body.section, 40) || 'Прочее';
  await append(T.doc, [crypto.randomUUID(), obj, section, prev[0]?.title || title, ver, url, today(), text(req.body.note, 300), req.who]);
  res.json({ ok: true, ver });
}));

app.get('/api/link/:id', guard, wrap(async (req, res) => {
  const d = (await readAll()).docs.find(d => d.id === req.params.id);
  if (!d) return res.status(404).json({ error: 'nf' });
  res.json({ url: `/dl/${mkToken(d.id)}` });
}));

const driveId = u => (u.match(/\/d\/([\w-]{10,})/) || u.match(/[?&]id=([\w-]{10,})/) || [])[1];
app.get('/dl/:token', wrap(async (req, res) => {
  const id = readToken(req.params.token); if (!id) return res.status(403).send('Ссылка устарела. Нажмите «Скачать» в приложении ещё раз.');
  const d = (await readAll()).docs.find(d => d.id === id); if (!d) return res.status(404).send('Файл не найден');
  const url = d.url;
  if (/^https?:\/\/(disk\.yandex\.[a-z]+|yadi\.sk)\//i.test(url)) { // публичная ссылка Яндекс Диска
    try { const j = await (await fetch('https://cloud-api.yandex.net/v1/disk/public/resources/download?public_key=' + encodeURIComponent(url))).json();
      if (j.href) return res.redirect(j.href); } catch (e) { console.error('yadisk:', e.message); }
  }
  const fid = /google\.com/.test(url) && driveId(url);
  if (fid) try { // Google Диск: отдаём файл через сервис-аккаунт
    const m = (await drive.files.get({ fileId: fid, fields: 'name,mimeType', supportsAllDrives: true })).data;
    const native = m.mimeType.startsWith('application/vnd.google-apps.');
    const s = native ? await drive.files.export({ fileId: fid, mimeType: 'application/pdf' }, { responseType: 'stream' })
      : await drive.files.get({ fileId: fid, alt: 'media', supportsAllDrives: true }, { responseType: 'stream' });
    res.setHeader('Content-Type', native ? 'application/pdf' : m.mimeType);
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(native ? m.name + '.pdf' : m.name)}`);
    s.data.on('error', () => res.end()); return s.data.pipe(res);
  } catch (e) { console.error('drive:', e.message); }
  res.redirect(url); // папка или другая ссылка: просто открываем
}));

if (SELF_PING_URL) { const ping = () => fetch(SELF_PING_URL).catch(() => {}); setTimeout(ping, 30000); setInterval(ping, 600000); }
const port = process.env.PORT || 3000;
app.listen(port, async () => {
  console.log('Сервер запущен на порту', port);
  if (WEBAPP_URL) try {
    await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/setChatMenuButton`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ menu_button: { type: 'web_app', text: 'Объекты', web_app: { url: WEBAPP_URL } } }) });
  } catch (e) { console.error('Не удалось настроить кнопку меню:', e.message); }
});
