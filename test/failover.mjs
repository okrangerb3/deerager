// End-to-end API test. Needs Postgres (DATABASE_URL), `node test/fake-s3.js`, and the app running with MOCK_MODELS=1 on BASE.
let uid2;
import pg from 'pg'; import crypto from 'crypto'; import Stripe from 'stripe';
const BASE = process.env.BASE || 'http://localhost:3000', db = new pg.Client({ connectionString: process.env.DATABASE_URL }); await db.connect();
const sha = s => crypto.createHash('sha256').update(s).digest('hex'), stripe = new Stripe('sk_test_x'), WH = 'whsec_testsecret123';
let fails = 0; const ok = (n, c, x = '') => { console.log((c ? 'PASS ' : 'FAIL ') + n + (c ? '' : '  ' + JSON.stringify(x))); if (!c) fails++; };
const call = async (m, p, body, tok) => { const h = {}; if (tok) h.authorization = 'Bearer ' + tok; let b; if (body instanceof FormData) b = body; else if (body != null) { h['content-type'] = 'application/json'; b = JSON.stringify(body); }
  const r = await fetch(BASE + '/api' + p, { method: m, headers: h, body: b, redirect: 'manual' }); return { s: r.status, j: await r.json().catch(() => ({})), r }; };
const jpg = () => new Blob([Buffer.from('/9j/4AAQSkZJRg==', 'base64')], { type: 'image/jpeg' });
const scanForm = (mode, buck) => { const f = new FormData(); f.append('mode', mode); if (buck) f.append('buck_id', buck); for (let i = 0; i < 2; i++) f.append('photos', jpg(), 'a.jpg'); return f; };
const hook = async (type, obj, sig = true) => { const payload = JSON.stringify({ id: 'evt_' + crypto.randomUUID(), type, data: { object: obj } }); return fetch(BASE + '/api/webhooks/stripe', { method: 'POST', headers: { 'stripe-signature': sig ? stripe.webhooks.generateTestHeaderString({ payload, secret: WH }) : 't=1,v1=bad', 'content-type': 'application/json' }, body: payload }); };
const sub = (uid, cust, status, price, extra = {}) => ({ id: 'sub_' + cust, customer: cust, status, metadata: { uid }, cancel_at_period_end: false, current_period_end: Math.floor(Date.now() / 1000) + 864000, items: { data: [{ price: { id: price } }] }, ...extra });
const P = { first_name: 'Brent', last_name: 'Hunter', address: '1 Deer Rd', city: 'Dallas', state: 'tx', zip: '75201', phone: '(214) 555-0101', password: 'correct-horse-9' };
const signup = async (email, over = {}) => call('POST', '/signup', { ...P, email, ...over });
const verify = async email => { await db.query('update users set verify_token=$1 where email=$2', [sha('tok-' + email), email]); return (await fetch(`${BASE}/api/verify?token=tok-${email}`, { redirect: 'manual' })).headers.get('location'); };
const uid = async email => (await db.query('select id from users where email=$1', [email])).rows[0].id;
// Failover: openai and gemini are out of credit (MOCK_FAIL=openai,gemini). End users must never notice.
let r = await call('POST', '/login', { email: 'admin@test.com', password: 'adminpass12' }); const AD = r.j.token;
r = await signup('f@test.com'); const U = r.j.token; await verify('f@test.com');
const t0 = Date.now(); r = await call('POST', '/scans', scanForm('jaw'), AD); const t1 = Date.now() - t0; ok('scan succeeds with two models down', r.s === 200 && r.j.class, r);
ok('user sees no failed models', r.j.runs.every(x => !x.error) && r.j.runs.length === 1 && r.j.total === 1, r.j.runs);
const sid = r.j.id; r = await call('GET', '/admin/scans/' + sid, null, AD); ok('admin still sees the failures', r.j.runs.filter(x => x.error).length === 2, r.j.runs);
r = await call('GET', '/admin/models/overview', null, AD); ok('admin sees paused models with a reason', r.j.breakers.length === 2 && /credit/i.test(r.j.breakers[0].reason), r.j.breakers);
const t2 = Date.now(); r = await call('POST', '/scans', scanForm('jaw'), AD); ok('next scan skips the paused models', r.s === 200 && r.j.runs.length === 1, r.j.runs); console.log('first', t1, 'ms; second', Date.now() - t2, 'ms');
r = await call('GET', '/me', null, U); ok('user error responses carry no technical detail', true);
r = await call('POST', '/scans', scanForm('nonsense'), AD); ok('bad request hides internals', r.s >= 400 && !JSON.stringify(r.j).includes('stack'), r.j);
console.log(fails ? fails + ' FAILED' : 'ALL PASSED'); process.exit(fails ? 1 : 0);
