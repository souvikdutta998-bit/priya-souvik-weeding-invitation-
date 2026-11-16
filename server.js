require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const port = Number(process.env.PORT || 3000);
const adminPassword = process.env.ADMIN_PASSWORD;
const secret = process.env.SESSION_SECRET;
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
if (!adminPassword || !secret || !supabaseUrl || !supabaseServiceKey) {
  console.error('Set ADMIN_PASSWORD, SESSION_SECRET, SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.');
  process.exit(1);
}
const supabase = createClient(supabaseUrl, supabaseServiceKey, {
  auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false }
});
app.use(express.json({ limit: '12kb' }));
app.use(express.static(path.join(__dirname, 'public')));

function safeEqual(a, b) {
  const aa = Buffer.from(String(a)); const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function makeToken() {
  const payload = Buffer.from(JSON.stringify({ exp: Date.now() + 8 * 60 * 60 * 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function isAdmin(req) {
  const token = req.headers.cookie?.split(';').map(x => x.trim()).find(x => x.startsWith('ps_admin='))?.slice(9);
  if (!token) return false;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return false;
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  if (!safeEqual(sig, expected)) return false;
  try { return JSON.parse(Buffer.from(payload, 'base64url').toString()).exp > Date.now(); }
  catch { return false; }
}
function requireAdmin(req, res, next) {
  if (!isAdmin(req)) return res.status(401).json({ error: 'Please sign in again.' });
  next();
}

app.post('/api/blessings', async (req, res) => {
  const name = typeof req.body.name === 'string' ? req.body.name.trim().slice(0, 80) : '';
  const message = typeof req.body.message === 'string' ? req.body.message.trim() : '';
  if (!message) return res.status(400).json({ error: 'Please write a blessing before sending.' });
  if (message.length > 500) return res.status(400).json({ error: 'Blessings must be 500 characters or fewer.' });
  const { data, error } = await supabase.from('blessings').insert({ name: name || 'A well-wisher', message }).select('id').single();
  if (error) { console.error('Blessing save failed:', error.message); return res.status(500).json({ error: 'Could not save your blessing. Please try again.' }); }
  res.status(201).json({ ok: true, id: data.id });
});
app.post('/api/admin/login', (req, res) => {
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (!safeEqual(password, adminPassword)) return res.status(401).json({ error: 'That password is not correct.' });
  res.setHeader('Set-Cookie', `ps_admin=${makeToken()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
  res.json({ ok: true });
});
app.get('/api/admin/blessings', requireAdmin, async (req, res) => {
  const { data, error } = await supabase.from('blessings').select('id,name,message,created_at').order('id', { ascending: false });
  if (error) { console.error('Blessing read failed:', error.message); return res.status(500).json({ error: 'Could not load blessings.' }); }
  res.json({ blessings: data });
});
app.post('/api/admin/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'ps_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.json({ ok: true });
});
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(port, () => console.log(`Priya & Souvik invitation running on port ${port}`));
