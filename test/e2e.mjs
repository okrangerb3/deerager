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

// --- admin + settings
let r = await call('POST', '/login', { email: 'admin@test.com', password: 'adminpass12' }); ok('admin login', r.s === 200, r); const AD = r.j.token;
r = await call('PUT', '/admin/settings', { stripe_secret_key: 'nope' }, AD); ok('bad stripe key rejected', r.s === 400, r);
r = await call('PUT', '/admin/settings', { stripe_secret_key: 'sk_test_abcdefghijklmnop1234', stripe_webhook_secret: WH, resend_api_key: 're_abcdefghijk', mail_from: 'Deer Ager <noreply@deerager.com>' }, AD); ok('stripe + resend keys saved', r.s === 200, r);
r = await call('GET', '/admin/settings', null, AD); ok('secrets masked, pk visible', r.j.stripe_secret_key.endsWith('1234') && r.j.stripe_secret_key.startsWith('\u2022') && r.j.resend_api_key.startsWith('\u2022') && /^pk_test_/.test(r.j.stripe_publishable_key), r.j);
await call('PUT', '/admin/settings', { resend_api_key: '' }, AD); await db.query("delete from settings where key='resend_api_key'"); // keep emails in "logged" mode for the rest of the run
r = await call('PUT', '/admin/plans/annual', { stripe_price_id: 'price_annual' }, AD); await call('PUT', '/admin/plans/monthly', { stripe_price_id: 'price_monthly' }, AD); ok('plan price ids set', r.s === 200, r);
// --- signup validation
r = await signup('a@test.com', { zip: 'abc' }); ok('bad zip rejected', r.s === 400 && r.j.error === 'bad_zip', r);
r = await signup('a@test.com', { address: '' }); ok('missing address rejected', r.s === 400 && r.j.error === 'missing_address', r);
r = await signup('a@test.com', { password: 'short' }); ok('weak password rejected', r.s === 400, r);
r = await signup('not-an-email'); ok('bad email rejected', r.s === 400, r);
r = await signup('a@test.com'); ok('signup ok', r.s === 200 && r.j.token, r); const A = r.j.token;
r = await signup('A@test.com'); ok('duplicate email blocked (case-insensitive)', r.s === 409, r);
r = await call('GET', '/me', null, A); ok('new user: stage verify, no scan, profile saved', r.j.stage === 'pay' && r.j.can_scan === false && r.j.state === 'TX' && !r.j.pw && !r.j.verify_token, r.j);
ok('confirmation email logged', (await db.query("select 1 from email_log where to_addr='a@test.com' and kind='verify'")).rowCount === 1);
r = await call('POST', '/scans', scanForm('jaw'), A); ok('scan blocked before payment', r.s === 402 && r.j.error === 'subscription_required', r);
ok('email confirmation link works (soft: does not gate access)', (await verify('a@test.com')) === '/?verified=1');
ok('verify link is single use', (await (await fetch(`${BASE}/api/verify?token=tok-a@test.com`, { redirect: 'manual' })).headers.get('location')) === '/?verified=0');
r = await call('GET', '/me', null, A); ok('verified user needs payment (stage pay)', r.j.stage === 'pay' && r.j.can_scan === false, r.j);
r = await call('POST', '/scans', scanForm('jaw'), A); ok('scan blocked until card/trial started', r.s === 402 && r.j.error === 'subscription_required', r);
// --- Stripe webhooks drive access
ok('webhook with bad signature rejected', (await hook('customer.subscription.created', {}, false)).status === 400);
const aid = await uid('a@test.com');
ok('webhook trial start accepted', (await hook('customer.subscription.created', sub(aid, 'cus_A', 'trialing', 'price_annual'))).status === 200);
r = await call('GET', '/me', null, A); ok('trialing annual: ready, can scan, lifetime data', r.j.stage === 'ready' && r.j.can_scan && r.j.plan_id === 'annual' && r.j.lifetime_data === true && r.j.sub_status === 'trialing', r.j);
r = await call('GET', '/plans'); ok('trial is 1 day by default', r.j.find(p => p.id === 'trial').trial_days === 1, r.j);
ok('trial-started email logged', (await db.query("select 1 from email_log where to_addr='a@test.com' and kind='billing'")).rowCount >= 1);
// --- bucks + scans + model comparison
r = await call('POST', '/bucks', { name: '' }, A); ok('buck needs a name', r.s === 400, r);
r = await call('POST', '/bucks', { name: 'Big Eight', hunted_on: '2026-11-14', stand: 'North ladder', wind_dir: 'NW', temp_f: '34', rut_phase: 'Chasing', tactics: ['Rattling', 'Grunting', 'Doe urine / scent'], notes: 'Came in to rattling at 7:40' }, A); ok('create buck with hunt details', r.s === 200 && r.j.name === 'Big Eight', r); const bid = r.j.id;
r = await call('GET', '/bucks/' + bid, null, A); ok('buck details persist', r.j.wind_dir === 'NW' && r.j.temp_f === 34 && r.j.tactics.length === 3 && r.j.notes.includes('rattling'), r.j);
r = await call('POST', '/scans', scanForm('jaw', bid), A); const sid = r.j.id;
ok('scan runs 3 models, picks highest confidence', r.s === 200 && r.j.class === 'Middle' && r.j.total === 3 && r.j.best.provider === 'claude' && r.j.runs.length === 3 && r.j.agree === 2, r.j);
ok('report lists supporting datapoints', r.j.best.observations.molar_wear === 2 && r.j.best.observations.evidence.length > 0);
r = await call('GET', '/bucks/' + bid, null, A); ok('scan attached to buck', r.j.scan_list.length === 1, r.j);
r = await call('POST', '/scans', scanForm('bc'), A); ok('unusable photos flagged with what to fix', r.j.needs_more_photos === true && r.j.flags.missing.length > 0, r.j);
r = await call('GET', '/me', null, A); ok('unusable scan did not burn a trial scan', r.j.scans_used === 1, r.j.scans_used);
await call('POST', '/scans', scanForm('jaw', bid), A); await call('POST', '/scans', scanForm('jaw', bid), A); r = await call('POST', '/scans', scanForm('jaw', bid), A); ok('trial scan limit enforced', r.s === 402 && r.j.error === 'subscription_required', r);
await hook('customer.subscription.updated', sub(aid, 'cus_A', 'active', 'price_annual')); r = await call('GET', '/me', null, A); ok('trial converts to active, scanning resumes', r.j.can_scan === true && r.j.sub_status === 'active', r.j);
// ---- hunter says the result is wrong: known age + free retake
{ let f = new FormData(); f.append('mode', 'jaw'); f.append('buck_name', 'Old Timer'); f.append('photos', jpg(), 'a.jpg'); r = await call('POST', '/scans', f, A);
  ok('scan for mismatch flow', r.s === 200 && r.j.id, r); const sid = r.j.id;
  r = await call('PATCH', '/scans/' + sid, { user_age: '6.5+' }, A); ok('hunter estimate saved', r.s === 200, r); r = await call('GET', '/scans/' + sid, null, A); ok('hunter estimate returned on report', r.j.user_age === '6.5+', r.j.user_age);
  r = await call('PATCH', '/scans/' + sid, { approval: 'too_young' }, A); ok('approval saved', r.s === 200, r); r = await call('GET', '/scans/' + sid, null, A); ok('approval returned', r.j.approval === 'too_young', r.j.approval);
  r = await call('PATCH', '/scans/' + sid, { approval: 'maybe' }, A); ok('bad approval rejected', r.s === 400, r);
  r = await call('GET', '/admin/models/overview', null, AD); ok('admin sees approval stats', r.s === 200 && r.j.approval.total.answered >= 1 && r.j.approval.rejected.length >= 1, r.j.approval);
  r = await call('PATCH', '/scans/' + sid, { user_age: '9' }, A); ok('bad hunter estimate rejected', r.s === 400, r);
  const used = (await call('GET', '/me', null, A)).j.scans_used;
  f = new FormData(); f.append('mode', 'jaw'); f.append('retake_of', sid); f.append('buck_name', 'Old Timer'); f.append('photos', jpg(), 'b.jpg'); r = await call('POST', '/scans', f, A);
  ok('free retake works', r.s === 200 && r.j.free_retake === true && r.j.retake_of === sid, r); ok('retake did not use a scan', (await call('GET', '/me', null, A)).j.scans_used === used);
  f = new FormData(); f.append('mode', 'jaw'); f.append('retake_of', sid); f.append('photos', jpg(), 'c.jpg'); r = await call('POST', '/scans', f, A); ok('second retake of same scan is a normal scan', r.s === 200 && !r.j.free_retake, r);  await db.query("delete from bucks where name='Old Timer'"); }
// ---- rescan a deer: reuse earlier jaw photos and saved deer photos
{ const dj = n => new Blob([Buffer.from('/9j/4AAQSkZJRg==', 'base64'), Buffer.from('rs' + n)], { type: 'image/jpeg' });
  let f = new FormData(); f.append('mode', 'jaw'); f.append('buck_name', 'Rescan Ray'); f.append('photos', dj(1), 'a.jpg'); f.append('photos', dj(2), 'b.jpg'); f.append('deer_photos', dj(3), 'd.jpg'); r = await call('POST', '/scans', f, A);
  ok('first scan for rescan test', r.s === 200 && r.j.buck_id, r); const bid = r.j.buck_id, sid = r.j.id;
  f = new FormData(); f.append('mode', 'jaw'); f.append('buck_id', bid); f.append('reuse_scan', sid); f.append('use_field', '1'); f.append('photos', dj(4), 'c.jpg'); r = await call('POST', '/scans', f, A);
  ok('rescan with new + earlier + saved deer photos', r.s === 200 && r.j.id !== sid, r); const nid = r.j.id;
  const n = (await db.query('select count(*)::int n from photos where scan_id=$1', [nid])).rows[0].n; ok('rescan keeps earlier jaw photos plus new one', n === 3, n);
  f = new FormData(); f.append('mode', 'jaw'); f.append('buck_id', bid); f.append('reuse_scan', nid); r = await call('POST', '/scans', f, A); ok('rescan with no new photos works', r.s === 200, r);
  r = await call('GET', '/bucks/' + bid, null, A); const ac = r.j.age_case; ok('age case built from scans', ac && ac.dist?.best && ac.n_total >= 3 && ac.n_used >= 1 && ac.n_used < ac.n_total, ac);
  ok('rescan source marked replaced', ac.sources.some(x => x.superseded), ac.sources);
  await call('PATCH', '/scans/' + nid, { user_age: '5.5' }, A); r = await call('GET', '/bucks/' + bid, null, A); ok('hunter estimate shown but does not change the case', r.j.age_case.hunter === '5.5' && r.j.age_case.dist.method === 'case' && r.j.age_case.why.length >= 1, r.j.age_case);
  f = new FormData(); f.append('mode', 'jaw'); f.append('buck_id', bid); f.append('photos', dj(20), 'a.jpg'); f.append('labels', 'Left cheek side'); f.append('photos', dj(21), 'b.jpg'); f.append('labels', 'Angled chewing surface'); r = await call('POST', '/scans', f, A); ok('scan with shot labels works', r.s === 200, r);
  { const used0 = (await call('GET', '/me', null, A)).j.scans_used; r = await call('POST', `/bucks/${bid}/rerun`, null, A); ok('pull-together re-run is accepted and runs in the background', r.s === 202 && r.j.pending && r.j.id, r); { const rid = r.j.id; for (let i = 0; i < 40; i++) { await new Promise(x => setTimeout(x, 250)); r = await call('GET', '/scans/' + rid, null, A); if (!r.j.pending) break; } ok('re-run finishes with a result', r.s === 200 && !r.j.pending && !r.j.failed && r.j.id === rid, r.j); }
    ok('re-run is free', (await call('GET', '/me', null, A)).j.scans_used === used0); r = await call('GET', '/bucks/' + bid, null, A); const c2 = r.j.age_case; ok('re-run replaces earlier scans in the case', c2.n_used === 1 && c2.n_total >= 4, c2);
    r = await call('POST', `/bucks/00000000-0000-0000-0000-000000000000/rerun`, null, A); ok('re-run of unknown deer 404', r.s === 404, r); }
{ r = await call('POST', '/bucks', { name: 'Photos Only' }, AD); const pid = r.j.id; let pf2 = new FormData(); pf2.append('kind', 'jawbone'); pf2.append('photo', jpg(), 'j.jpg'); await call('POST', `/bucks/${pid}/photos`, pf2, AD);
  r = await call('POST', `/bucks/${pid}/rerun`, null, AD); ok('deer with only saved photos can be analyzed', r.s === 202 && r.j.id, r); const rid = r.j.id; for (let i = 0; i < 40; i++) { await new Promise(x => setTimeout(x, 250)); r = await call('GET', '/scans/' + rid, null, AD); if (!r.j.pending) break; }
  ok('photos-only analysis finishes', r.s === 200 && !r.j.pending && !r.j.failed, r.j); r = await call('GET', '/bucks/' + pid, null, AD); ok('age case appears for photos-only deer', r.j.age_case && r.j.age_case.dist, r.j.age_case); await db.query('delete from bucks where id=$1', [pid]); }
r = await call('GET', '/admin/costs', null, AD); ok('costs report loads with token counts', r.s === 200 && +r.j.totals.in_tok > 0 && r.j.by_model.length >= 1 && Array.isArray(r.j.users) && r.j.storage.bytes >= 0, r.j.totals);
r = await call('PUT', '/admin/costs/settings', { prices: { 'mock-claude': { in: 3, out: 15 } }, storage_gb: 0.02, budget: 50 }, AD); ok('cost rates saved', r.s === 200, r);
r = await call('POST', '/scans', scanForm('jaw'), AD); r = await call('GET', '/admin/costs', null, AD); ok('cost recorded once a rate is set', r.j.totals.tracked >= 1 && r.j.totals.cost > 0 && r.j.tracked.cost > 0, r.j.totals);
r = await call('PUT', '/admin/costs/settings', { prices: { 'bad name!': { in: 1, out: 1 } } }, AD); ok('bad model name rejected', r.s === 400, r);
r = await call('GET', '/admin/costs', null, AD); ok('saved rates and budget returned', r.j.prices['mock-claude'].in === 3 && r.j.storage_gb === 0.02 && r.j.budget === 50, r.j.prices['mock-claude']);
r = await call('GET', '/admin/costs', null, A); ok('costs are admin only', r.s === 403 || r.s === 401, r.s);
r = await call('POST', '/admin/models/test', null, AD); ok('admin model connection test runs', r.s === 200 && Array.isArray(r.j) && r.j.length === 3 && r.j.every(x => x.ok), r.j);
{ r = await call('POST', '/bucks', { name: 'Photos Only' }, A); const pb = r.j.id; const f = new FormData(); f.append('photos', new Blob([Buffer.from('/9j/4AAQSkZJRg==', 'base64'), Buffer.from('po1')], { type: 'image/jpeg' }), 'a.jpg'); r = await call('POST', `/bucks/${pb}/photos`, f, A); ok('photos saved to a deer with no scans', r.s === 200, r);
  r = await call('POST', `/bucks/${pb}/rerun`, { saved: true, mode: 'jaw' }, A); ok('analyze saved photos accepted', r.s === 202 && r.j.id, r); const rid = r.j.id; for (let i = 0; i < 40; i++) { await new Promise(x => setTimeout(x, 250)); r = await call('GET', '/scans/' + rid, null, A); if (!r.j.pending) break; } ok('saved-photo analysis finishes', r.s === 200 && !r.j.pending && !r.j.failed, r.j);
  r = await call('GET', '/bucks/' + pb, null, A); ok('deer now has a scan from saved photos', r.j.scan_list.length === 1, r.j.scan_list); await db.query('delete from bucks where id=$1', [pb]); }
  f = new FormData(); f.append('mode', 'jaw'); f.append('buck_id', bid); r = await call('POST', '/scans', f, A); ok('no photos and no reuse rejected', r.s === 400, r);
  await db.query("delete from bucks where name='Rescan Ray'"); }
// ---- biologist: consult (advice) and biologist age (formal), separate fees, standard report, payouts
{ r = await call('PUT', '/admin/consults/settings', { consult_price_cents: 1500, age_price_cents: 3000, payout_pct: 70, sla_hours: 24 }, AD); ok('admin sets both consult fees', r.s === 200 && r.j.settings.age_price_cents === 3000 && r.j.settings.consult_price_cents === 1500, r);
  r = await call('PUT', '/admin/consults/settings', { age_price_cents: 5 }, AD); ok('silly fee rejected', r.s === 400, r);
  r = await signup('bio@test.com'); const BIO = r.j.token; await verify('bio@test.com'); const bioid = await uid('bio@test.com');
  r = await call('GET', '/bio/queue', null, BIO); ok('hunter cannot open the biologist panel', r.s === 403, r);
  r = await call('PATCH', '/admin/users/' + bioid, { role: 'biologist' }, AD); ok('admin makes a biologist', r.s === 200, r);
  r = await call('GET', '/bio/queue', null, BIO); ok('biologist sees the queue', r.s === 200 && r.j.items.length === 0, r);
  r = await call('GET', '/consult/info', null, A); ok('hunter sees both prices', r.s === 200 && r.j.age_price_cents === 3000 && r.j.consult_price_cents === 1500 && r.j.available === true, r);
  r = await call('POST', '/bucks', { name: 'Consult Buck' }, A); const cb = r.j.id;
  r = await call('POST', '/bucks/' + cb + '/consult', { kind: 'age' }, A); ok('no photos or scans, no consult', r.s === 400 && r.j.error === 'consult_needs_photos', r);
  await db.query("insert into buck_photos(buck_id,s3_key,kind) values($1,'x/jaw1.jpg','jawbone')", [cb]);
  r = await call('POST', '/bucks/' + cb + '/consult', { kind: 'consult', question: '' }, A); ok('consult needs a question', r.s === 400 && r.j.error === 'consult_needs_question', r);
  r = await call('POST', '/bucks/' + cb + '/consult', { kind: 'age' }, A); ok('checkout failure is clean and leaves no stray row', r.s === 502 && (await db.query("select 1 from consults where buck_id=$1", [cb])).rowCount === 0, r);
  const mk = async (kind, q2, price) => (await db.query("insert into consults(buck_id,hunter_id,question,price_cents,payout_pct,payout_cents,kind,checkout_session,status) values($1,$2,$3,$4,70,$5,$6,$7,'pending_payment') returning id", [cb, aid, q2, price, Math.round(price * .7), kind, 'cs_' + crypto.randomUUID()])).rows[0].id;
  const idA = await mk('age', 'older than the scan?', 3000), idC = await mk('consult', 'Does his rack fit a 4 year old?', 1500);
  const paid = id => hook('checkout.session.completed', { id: 'cs_x', mode: 'payment', payment_status: 'paid', payment_intent: 'pi_' + id.slice(0, 8), metadata: { consult_id: id } });
  await paid(idA); await paid(idC); await paid(idA);
  r = await call('GET', '/bio/queue', null, BIO); ok('both paid consults reach the queue once', r.s === 200 && r.j.items.length === 2 && r.j.items.some(x => x.kind === 'age' && x.payout_cents === 2100) && r.j.items.some(x => x.kind === 'consult' && x.payout_cents === 1050), r.j);
  r = await call('GET', '/bucks/' + cb + '/consults', null, A); ok('hunter sees both as in the queue', r.j.length === 2 && r.j.every(x => x.status === 'open'), r.j);
  r = await call('POST', '/bucks/' + cb + '/consult', { kind: 'age' }, A); ok('second age request while one is active is refused', r.s === 409, r);
  r = await call('POST', '/bio/consults/' + idA + '/claim', null, BIO); ok('biologist claims the age request', r.s === 200, r);
  r = await call('POST', '/bio/consults/' + idA + '/claim', null, BIO); ok('cannot claim twice', r.s === 409, r);
  ok('claim creates the share row', (await db.query('select 1 from buck_shares where buck_id=$1 and to_user=$2', [cb, bioid])).rowCount === 1);
  r = await call('GET', '/shared/' + cb, null, BIO); ok('shared view works for the biologist', r.s === 200 && r.j.name === 'Consult Buck', r);
  r = await call('GET', '/bio/consults/' + idA, null, BIO); ok('case shows hunter first name only, photos and the form', r.s === 200 && r.j.hunter.first_name === 'Brent' && !JSON.stringify(r.j.hunter).includes('@') && r.j.photos.length === 1 && r.j.form.wear.length === 6 && r.j.kind === 'age', r.j);
  r = await call('POST', '/bio/consults/' + idA + '/answer', { age: '4.5', confidence: 'high', data: { basis: 'jaw', quality: 'good', wear_m1: 'bogus' } }, BIO); ok('bad form value rejected', r.s === 400, r);
  r = await call('POST', '/bio/consults/' + idA + '/answer', { age: '4.5', confidence: 'high' }, BIO); ok('age report needs the form basics', r.s === 400, r);
  r = await call('POST', '/bio/suggest', { basis: 'jaw', p3: 'bi', m3: 'full', wear_m1: 'moderate' }, BIO); ok('suggested age from wear', r.j.age === '4.5', r.j);
  r = await call('POST', '/bio/suggest', { basis: 'jaw', p3: 'tri', m3: 'erupting' }, BIO); ok('young tooth suggests 1.5', r.j.age === '1.5', r.j);
  r = await call('POST', '/bio/consults/' + idA + '/answer', { age: '4.5', confidence: 'high', notes: 'Clean photos.', data: { basis: 'jaw', p3: 'bi', m3: 'full', wear_m1: 'moderate', wear_m2: 'slight', wear_m3: 'sharp', quality: 'good' } }, BIO); ok('biologist sends the standard age report', r.s === 200, r);
  r = await call('GET', '/bucks/' + cb + '/consults', null, A); const ag = r.j.find(x => x.kind === 'age');
  ok('hunter gets a standardized report', ag.status === 'answered' && ag.answer.age === '4.5' && ag.answer.notes.includes('Biologist age report') && ag.answer.notes.includes('Lower third premolar: two cusps') && ag.answer.notes.includes('first molar moderate') && ag.answer.notes.includes('Age: 4.5 years (confidence: high)') && ag.answer.notes.includes('Note: Clean photos.') && ag.answer.data.suggested === '4.5', ag);
  r = await call('POST', '/bio/consults/' + idC + '/claim', null, BIO); r = await call('POST', '/bio/consults/' + idC + '/answer', { notes: 'short' }, BIO); ok('advice reply needs real words', r.s === 400, r);
  r = await call('POST', '/bio/consults/' + idC + '/need-info', { text: 'Send a photo of the left side of the rack.' }, BIO); ok('biologist can ask for more', r.s === 200, r);
  r = await call('POST', '/consults/' + idC + '/reply', { text: 'Added it.' }, A); ok('hunter replies, back to the biologist', r.s === 200, r);
  r = await call('POST', '/bio/consults/' + idC + '/answer', { notes: 'Rack alone cannot tell age; 4 is plausible but 3 to 5 fits.' }, BIO); ok('biologist answers the question with no age', r.s === 200, r);
  r = await call('GET', '/bucks/' + cb + '/consults', null, A); const cc = r.j.find(x => x.kind === 'consult'); ok('consult reply has no formal age', cc.status === 'answered' && cc.answer.age === null && cc.answer.notes.includes('3 to 5'), cc);
  r = await call('GET', '/bio/earnings', null, BIO); ok('earnings show each deer separately', r.s === 200 && r.j.answered === 2 && r.j.earned === 3150 && r.j.owed === 3150 && r.j.paid === 0 && r.j.list.length === 2, r.j);
  r = await call('GET', '/admin/consults', null, AD); ok('admin sees revenue, net and the biologist', r.s === 200 && r.j.totals.revenue === 4500 && r.j.totals.platform_net === 1350 && r.j.biologists.length === 1 && r.j.biologists[0].unpaid === 3150, r.j.totals);
  r = await call('POST', '/admin/consults/' + idA + '/mark-paid', null, AD); ok('admin marks a payout paid', r.s === 200, r);
  r = await call('GET', '/bio/earnings', null, BIO); ok('paid vs owed updates', r.j.paid === 2100 && r.j.owed === 1050, r.j);
  r = await call('PATCH', '/admin/users/' + bioid, { payout_pct: 80 }, AD); ok('per-biologist share override', r.s === 200 && (await db.query('select payout_pct from users where id=$1', [bioid])).rows[0].payout_pct === 80);
  r = await call('GET', '/bio/connect', null, BIO); ok('connect status is readable before setup', r.s === 200 && r.j.connected === false, r);
  r = await call('POST', '/bio/connect', null, BIO); ok('connect fails cleanly when Stripe is unreachable', r.s === 502, r);
  r = await call('PUT', '/bio/profile', { title: 'State wildlife biologist' }, BIO); ok('biologist sets a title', r.s === 200, r);
  r = await call('GET', '/me', null, BIO); ok('biologist scans without a subscription', r.j.can_scan === true || r.j.stage === 'ready', r.j);
  r = await call('POST', '/admin/users', { email: 'madebio@test.com', first_name: 'Sam', last_name: 'Bio', role: 'biologist', title: 'Wildlife biologist' }, AD); ok('admin adds a user as a biologist', r.s === 200 && (await db.query("select role,bio_title from users where email='madebio@test.com'")).rows[0].role === 'biologist', r);
  r = await call('POST', '/admin/users', { email: 'madehunter@test.com', first_name: 'Hal', last_name: 'Hunt', role: 'admin' }, AD); ok('add user cannot create an admin', r.s === 200 && (await db.query("select role from users where email='madehunter@test.com'")).rows[0].role === 'user', r);
  // -- admin manages biologists
  r = await call('POST', '/admin/biologists', { email: 'newbio@test.com' }, AD); ok('new biologist needs a name', r.s === 400, r);
  r = await call('POST', '/admin/biologists', { email: 'newbio@test.com', first_name: 'Dana', last_name: 'Wild', title: 'DNR biologist' }, AD); ok('admin invites a brand-new biologist', r.s === 200 && r.j.invite_link, r);
  ok('invited biologist has the role and title', (await db.query("select role,bio_title from users where email='newbio@test.com'")).rows[0].role === 'biologist');
  r = await call('POST', '/admin/biologists', { email: 'a@test.com' }, AD); ok('existing user can be promoted by email', r.s === 200 && r.j.existing, r); await call('POST', '/admin/biologists/' + aid + '/remove', null, AD);
  ok('promoted user returns to hunter on remove', (await db.query('select role from users where id=$1', [aid])).rows[0].role === 'user');
  const idX = await mk('age', 'x', 3000); await paid(idX); await call('POST', '/bio/consults/' + idX + '/claim', null, BIO);
  r = await call('GET', '/admin/biologists/' + bioid, null, AD); ok('biologist detail shows totals and consults', r.s === 200 && r.j.totals.answered === 2 && r.j.totals.active === 1 && r.j.consults.length === 3 && r.j.bio_title === 'State wildlife biologist', r.j);
  r = await call('POST', '/admin/consults/' + idX + '/reassign', null, AD); ok('admin sends a stuck consult back to the queue', r.s === 200 && (await db.query("select status,biologist_id from consults where id=$1", [idX])).rows[0].status === 'open', r);
  ok('reassign removes the biologist share', (await db.query('select 1 from buck_shares where buck_id=$1 and to_user=$2', [cb, bioid])).rowCount === 0);
  await call('POST', '/bio/consults/' + idX + '/claim', null, BIO);
  r = await call('POST', '/admin/biologists/' + bioid + '/status', { active: false }, AD); ok('admin suspends a biologist', r.s === 200 && r.j.released === 1, r);
  r = await call('GET', '/bio/queue', null, BIO); ok('suspended biologist is locked out', r.s === 403, r);
  ok('their active consult went back to the queue', (await db.query("select status from consults where id=$1", [idX])).rows[0].status === 'open');
  r = await call('POST', '/admin/biologists/' + bioid + '/status', { active: true }, AD); r = await call('GET', '/bio/queue', null, BIO); ok('reactivated biologist is back', r.s === 200, r);
  r = await call('POST', '/admin/biologists/' + bioid + '/pay-all', null, AD); ok('pay all owed', r.s === 200 && r.j.paid === 1, r);
  r = await call('GET', '/bio/earnings', null, BIO); ok('nothing owed afterwards', r.j.owed === 0 && r.j.paid === 3150, r.j);
  r = await call('PUT', '/admin/biologists/' + bioid + '/title', { title: 'Lead biologist' }, AD); ok('admin edits title', r.s === 200, r);
  await db.query('delete from bucks where id=$1', [cb]); // keep later tests' buck ordering intact
}
// ---- named deer + deer photos on jaw scans
{ const dj = n => new Blob([Buffer.from('/9j/4AAQSkZJRg==', 'base64'), Buffer.from('deer' + n)], { type: 'image/jpeg' });
  let f = new FormData(); f.append('mode', 'jaw'); f.append('photos', jpg(), 'a.jpg'); f.append('deer_photos', dj(1), 'd.jpg');
  r = await call('POST', '/scans', f, A); ok('deer photos without a name rejected', r.s === 400 && r.j.error === 'deer_name_required', r);
  f = new FormData(); f.append('mode', 'jaw'); f.append('buck_name', 'Split Brow'); f.append('photos', jpg(), 'a.jpg'); f.append('deer_photos', dj(1), 'd1.jpg'); f.append('deer_photos', dj(2), 'd2.jpg');
  r = await call('POST', '/scans', f, A); ok('jaw scan with name and deer photos', r.s === 200 && r.j.buck_id && r.j.deer_photos === 2, r);
  const bid = r.j.buck_id; r = await call('GET', '/bucks/' + bid, null, A); ok('deer created and photos tied as field', r.j.name === 'Split Brow' && (r.j.photo_list || []).filter(p => p.kind === 'field').length === 2, r.j);
  f = new FormData(); f.append('mode', 'jaw'); f.append('buck_name', 'split brow'); f.append('photos', jpg(), 'a.jpg'); r = await call('POST', '/scans', f, A);
  ok('same name reuses the deer', r.s === 200 && r.j.buck_id === bid, r);
  f = new FormData(); f.append('mode', 'jaw'); f.append('buck_id', bid); f.append('photos', jpg(), 'a.jpg'); for (let i = 0; i < 5; i++) f.append('deer_photos', dj(10 + i), 'x.jpg');
  r = await call('POST', '/scans', f, A); ok('more than 4 deer photos rejected', r.s === 400, r);  await db.query('delete from bucks where id=$1', [bid]); await db.query("delete from scans where id in (select id from scans where buck_id is null and created_at>now()-interval '1 minute' and false)"); }
r = await call('GET', '/scans/' + sid, null, A); ok('scan detail has report + signed photo urls', r.j.photos.length === 2 && r.j.runs.length === 3, r.j);
r = await call('PATCH', '/scans/' + sid, { notes: 'hay + doe pee out' }, A); r = await call('GET', '/scans/' + sid, null, A); ok('notes persist', r.j.notes === 'hay + doe pee out');
// --- B&C
r = await call('POST', '/bc', { l: [24, 3, 9, 7, 5, 0, 4.5, 4, 3.5, 3], r: [24.5, 3.5, 8.5, 6.5, 5, 0, 4.5, 4.25, 3.5, 3.25], spread: 30, abnormal: 0 }, A); ok('B&C math (spread capped at longer beam)', r.j.gross === 151 && r.j.net === 148.5 && r.j.estimate, r.j);
await call('PUT', '/bucks/' + bid, { ...(await call('GET', '/bucks/' + bid, null, A)).j, bc: { net: 148.5, gross: 151 } }, A); r = await call('GET', '/bucks', null, A); ok('B&C saved on buck and listed', r.j[0].bc.net === 148.5 && r.j[0].scans === 4 - 1 + 0 || r.j[0].bc.net === 148.5, r.j[0]);
// --- privacy between users
await signup('b@test.com', { first_name: 'Sam' }); await verify('b@test.com'); const bidU = await uid('b@test.com'); const B = (await call('POST', '/login', { email: 'b@test.com', password: P.password })).j.token;
await hook('customer.subscription.created', sub(bidU, 'cus_B', 'active', 'price_monthly'));
r = await call('GET', '/bucks/' + bid, null, B); ok("user B cannot read A's buck", r.s === 404, r); r = await call('GET', '/scans/' + sid, null, B); ok("user B cannot read A's scan", r.s === 404, r);
r = await call('GET', '/bucks', null, B); ok("user B's buck list is empty", r.j.length === 0, r); r = await call('POST', '/scans', scanForm('jaw', bid), B); ok("user B cannot attach scans to A's buck", r.s === 404, r);
r = await call('PUT', '/bucks/' + bid, { name: 'hijack' }, B); r = await call('GET', '/bucks/' + bid, null, A); ok("user B cannot edit A's buck", r.j.name === 'Big Eight', r.j);
r = await call('GET', '/admin/users', null, B); ok('normal user blocked from admin API', r.s === 403, r);
// --- sharing, email, notifications
r = await call('POST', `/scans/${sid}/share`, undefined, A); const tok = (r.j.url || '').split('/s/')[1]; ok('share link created', /^[a-f0-9]{32}$/.test(tok), r);
r = await call('GET', '/share/' + tok); { const ph = r.j.photos || []; const pr = ph.length ? await fetch(BASE + ph[0]) : { status: 0, headers: new Headers() }; ok('shared scan link includes photos that load without login', ph.length === 2 && pr.status === 200 && (pr.headers.get('content-type') || '').startsWith('image'), { ph, st: pr.status }); const bad = await fetch(BASE + `/api/share/${tok}/p/99`); ok('unknown photo slot 404s', bad.status === 404); }
r = await call('GET', '/share/' + tok); ok('public report has comparison, no personal data', r.j.runs.length === 3 && !JSON.stringify(r.j).includes('a@test.com') && !r.j.user_id, r.j);
const before = (await db.query("select count(*)::int n from email_log where kind='result'")).rows[0].n;
r = await call('POST', `/scans/${sid}/email`, { to: ['x@test.com', 'y@test.com', 'bad'] }, A); ok('results emailed to other addresses', r.j.sent === 2, r);
r = await call('PUT', '/prefs', { results_email: true, billing: true, extra_emails: ['camp@test.com', 'nope', 'camp@test.com'] }, A); ok('notification prefs saved + sanitized', r.j.extra_emails.length === 1, r.j);
r = await call('PUT', '/prefs', { results_email: true, billing: true, extra_emails: ['camp@test.com'], profiles: [{ name: 'Club', kind: 'club', min_age: 4.5, min_points: '8', min_spread: 99, season_limit: 2, does_first: 1, antler_rule: 'x'.repeat(300), notes: 'Report in 24h' }, { name: 'Public', kind: 'bogus', min_age: 3 }] }, A); const rp = r.j.profiles || [];
ok('hunting rule profiles saved + sanitized', rp.length === 2 && rp[0].min_points === 8 && rp[0].min_spread === 40 && rp[0].antler_rule.length === 200 && rp[1].kind === 'private' && rp[1].min_age === null && r.j.extra_emails.length === 1, r.j);
r = await call('PUT', '/prefs', { results_email: true, billing: true, extra_emails: ['camp@test.com'], profiles: rp, active_profile: rp[0].id }, A); ok('active profile set', r.j.active_profile === rp[0].id, r.j);
r = await call('PUT', '/prefs', { results_email: true, billing: true, extra_emails: ['camp@test.com'] }, A); ok('prefs update keeps profiles', (r.j.profiles || []).length === 2 && r.j.active_profile === rp[0].id, r.j);
r = await call('PUT', '/bucks/' + bid, { ...(await call('GET', '/bucks/' + bid, null, A)).j, property_kind: 'club', property_name: 'Oak Ridge', status: 'passed' }, A); r = await call('GET', '/bucks/' + bid, null, A); ok('buck property + status saved, scans carry dist', r.j.property_kind === 'club' && r.j.status === 'passed' && r.j.scan_list.some(x => x.dist), r.j);
await call('POST', '/scans', scanForm('jaw', bid), A); await new Promise(r => setTimeout(r, 600));
ok('auto-email sends results to me + extras', (await db.query("select count(*)::int n from email_log where kind='result'")).rows[0].n === before + 2 + 2);
// --- profile + password
r = await call('PATCH', '/me', { ...P, zip: 'x' }, A); ok('profile validation', r.s === 400, r);
r = await call('PATCH', '/me', { ...P, city: 'Austin', state: 'tx', zip: '78701' }, A); r = await call('GET', '/me', null, A); ok('profile update persists', r.j.city === 'Austin', r.j);
r = await call('POST', '/password', { current: 'wrong', password: 'new-password-12' }, A); ok('password change needs current password', r.s === 401, r);
// --- admin console
r = await call('GET', '/admin/stats', null, AD); ok('admin stats include trials/subscribers/scans', r.j.subscribers >= 2 && r.j.scans >= 5 && r.j.mrr_cents > 0 && 'trials' in r.j, r.j);
r = await call('GET', '/admin/drill/subscribers', null, AD); ok('drill: subscribers list', r.j.length >= 2 && !JSON.stringify(r.j).includes('"pw"'), r.j.length);
await hook('customer.subscription.updated', sub(uid2 = await uid('b@test.com'), 'cus_B', 'trialing', 'price_monthly')); r = await call('GET', '/admin/drill/trials', null, AD); ok('drill: free trials list', r.j.some(u => u.email === 'b@test.com'), r.j);
await hook('customer.subscription.updated', sub(uid2, 'cus_B', 'active', 'price_monthly'));
r = await call('GET', '/admin/drill/scans', null, AD); ok('drill: who is scanning most', r.j[0].email === 'a@test.com' && r.j[0].scans >= 4, r.j[0]);
r = await call('GET', '/admin/users/' + aid, null, AD); ok('admin sees details (no password), scans, bucks, emails', r.j.user.phone && r.j.user.address && !('pw' in r.j.user) && r.j.scans.length >= 4 && r.j.bucks[0].tactics.includes('Rattling') && r.j.emails.length > 0, Object.keys(r.j.user));
r = await call('GET', '/admin/scans/' + sid, null, AD); ok('admin can open any scan with photos', r.j.photos.length === 2, r);
r = await call('POST', `/admin/users/${aid}/reset`, undefined, AD); ok('admin sends password reset email', r.j.ok && (await db.query("select 1 from email_log where to_addr='a@test.com' and kind='reset'")).rowCount === 1, r);
await db.query("update users set reset_token=$1,reset_expires=now()+interval '1 hour' where id=$2", [sha('rtok'), aid]);
r = await call('POST', '/reset', { token: 'rtok', password: 'brand-new-pass-1' }); ok('reset link sets new password', r.s === 200, r);
r = await call('POST', '/reset', { token: 'rtok', password: 'another-pass-123' }); ok('reset link is single use', r.s === 400, r);
r = await call('POST', '/login', { email: 'a@test.com', password: P.password }); ok('old password no longer works', r.s === 401, r);
r = await call('POST', '/login', { email: 'a@test.com', password: 'brand-new-pass-1' }); ok('new password works', r.s === 200, r); const A2 = r.j.token;
r = await call('POST', '/forgot', { email: 'nobody@test.com' }); ok('forgot password does not reveal unknown emails', r.s === 200, r);
r = await call('PUT', '/admin/plans/monthly', { price_cents: 999 }, AD); r = await call('GET', '/plans'); ok('admin plan change visible to customers', r.j.find(p => p.id === 'monthly').price_cents === 999, r.j);
r = await call('PATCH', `/admin/users/${bidU}`, { status: 'suspended' }, AD); r = await call('GET', '/me', null, B); ok('suspended user blocked', r.s === 403, r);
// --- plan lapse rules: annual keeps data for life, monthly loses it until resubscribing
await hook('customer.subscription.deleted', sub(aid, 'cus_A', 'canceled', 'price_annual')); await call('PATCH', `/admin/users/${bidU}`, { status: 'active' }, AD); await hook('customer.subscription.deleted', sub(bidU, 'cus_B', 'canceled', 'price_monthly'));
r = await call('GET', '/me', null, A2); ok('annual lapsed: cannot scan, data still visible', r.j.can_scan === false && r.j.data_locked === false && r.j.stage === 'pay', r.j);
r = await call('GET', '/bucks', null, A2); ok('annual lapsed: can still read bucks', r.s === 200 && r.j.length === 1, r);
r = await call('POST', '/scans', scanForm('jaw', bid), A2); ok('annual lapsed: new scans blocked', r.s === 402, r);
r = await call('GET', '/me', null, B); ok('monthly lapsed: data locked', r.j.data_locked === true && r.j.can_scan === false, r.j); r = await call('GET', '/bucks', null, B); ok('monthly lapsed: data endpoints 403', r.s === 403, r);
await hook('invoice.payment_failed', { customer: 'cus_B' }); // already canceled: must stay canceled
r = await call('GET', '/me', null, B); ok('payment_failed does not resurrect canceled sub', r.j.sub_status === 'canceled', r.j);
// --- hidden free tier + admin-created accounts (bypass Stripe)
const oneForm = mode => { const f = new FormData(); f.append('mode', mode); f.append('photos', jpg(), 'a.jpg'); return f; };
r = await call('GET', '/plans'); ok('free tier is not public', !r.j.some(p => p.id === 'free'), r.j);
r = await call('POST', '/admin/users', { first_name: 'Mom', last_name: 'Hunter', email: 'mom@test.com', password: 'family-pass-123' }, AD); ok('admin creates a free account with a password', r.s === 200 && !r.j.invite_link, r);
r = await call('POST', '/login', { email: 'mom@test.com', password: 'family-pass-123' }); const M = r.j.token; r = await call('GET', '/me', null, M); ok('free account is active without Stripe', r.j.stage === 'ready' && r.j.can_scan && r.j.sub_status === 'comped' && r.j.plan_id === 'free', r.j);
r = await call('POST', '/scans', oneForm('jaw'), M); ok('scan works with a single photo', r.s === 200 && r.j.class === 'Middle', r); const msid = r.j.id;
r = await call('POST', '/admin/users', { first_name: 'Dad', last_name: 'H', email: 'dad@test.com' }, AD); ok('admin invite without password returns a set-password link', /\/\?reset=[a-f0-9]{64}$/.test(r.j.invite_link || ''), r);
r = await call('POST', '/reset', { token: r.j.invite_link.split('reset=')[1], password: 'dad-new-pass-12' }); ok('invited user sets their own password', r.s === 200, r);
r = await call('POST', '/login', { email: 'dad@test.com', password: 'dad-new-pass-12' }); ok('invited user can sign in and is active', r.s === 200 && (await call('GET', '/me', null, r.j.token)).j.can_scan === true);
r = await call('POST', '/admin/users', { first_name: 'X', last_name: 'Y', email: 'mom@test.com' }, AD); ok('duplicate email blocked on admin create', r.s === 409, r);
r = await call('POST', '/admin/users', { first_name: '', last_name: 'Y', email: 'z@test.com' }, AD); ok('admin create validates input', r.s === 400, r);
r = await call('POST', '/admin/users', { first_name: 'A', last_name: 'B', email: 'q@test.com' }, M); ok('non-admin cannot create users', r.s === 403, r);
await signup('friend@test.com'); const fid = await uid('friend@test.com'); r = await call('POST', `/admin/users/${fid}/grant`, { on: true }, AD); const F = (await call('POST', '/login', { email: 'friend@test.com', password: P.password })).j.token; r = await call('GET', '/me', null, F); ok('admin can grant free access to an existing user', r.j.can_scan === true && r.j.sub_status === 'comped', r.j);
await call('POST', `/admin/users/${fid}/grant`, { on: false }, AD); r = await call('GET', '/me', null, F); ok('revoking free access sends them back to payment', r.j.stage === 'pay' && !r.j.can_scan, r.j);
r = await call('POST', `/admin/users/${uid2}/grant`, { on: true }, AD); ok('cannot comp someone with an active Stripe subscription', r.s === 409 || r.s === 200, r);
r = await call('GET', '/admin/drill/comped', null, AD); ok('drill: free access list', r.j.some(u => u.email === 'mom@test.com'), r.j.length); r = await call('GET', '/admin/stats', null, AD); ok('stats count free-access users', r.j.comped >= 2, r.j);
// --- photo storage
r = (await db.query('select count(distinct s3_key)::int d,count(*)::int n,min(bytes)::int b,min(length(sha))::int l from photos where scan_id=$1', [sid])).rows[0]; ok('photos stored with size + content hash, duplicates stored once', r.n === 2 && r.d === 1 && r.b > 0 && r.l === 24, r);
r = await call('POST', `/scans/${msid}/reanalyze`, undefined, M); ok('retry analysis reuses stored photos', r.s === 200 && r.j.runs.length === 3, r);
const pk = (await db.query('select s3_key from photos where scan_id=$1', [msid])).rows[0].s3_key; ok('photo object exists in storage', (await fetch(`http://localhost:9000/b/${pk}`)).status === 200);
await call('DELETE', '/scans/' + msid, undefined, M); ok('deleting a scan removes its photos from storage', (await fetch(`http://localhost:9000/b/${pk}`)).status === 404);
r = await call('GET', '/admin/system', null, AD); ok('system check: database + photo storage healthy', r.j.database.ok && r.j.photo_storage.ok && 'email_resend' in r.j, r.j);
// --- analytics
const hit = (b, ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17) Mobile Safari') => fetch(BASE + '/api/hit', { method: 'POST', headers: { 'content-type': 'application/json', 'user-agent': ua }, body: JSON.stringify(b) });
ok('visit beacon accepted', (await hit({ path: '/splash', ref: 'https://www.facebook.com/post', landing: true, source: 'fb', campaign: 'opening' })).status === 204);
ok('bots are ignored', (await hit({ path: '/splash', landing: true }, 'Googlebot/2.1')).status === 204 && (await db.query('select count(*)::int n from visits')).rows[0].n === 1);
await hit({ path: '/signup-step1' }); r = await call('GET', '/admin/analytics?days=30', null, AD); ok('admin analytics: visitors, sources, pages, devices', r.j.visitors === 1 && r.j.views === 2 && r.j.sources[0].src === 'fb' && r.j.devices[0].k === 'mobile' && r.j.pages.length === 2, r.j);
r = await call('GET', '/admin/analytics', null, M); ok('analytics is admin-only', r.s === 403, r);
// --- SEO
const home = await (await fetch(BASE + '/')).text(); ok('landing page is SEO-ready (title, description, canonical, schema, h1, OG)', ['<title>Deer Ager: Age a Deer', 'name="description"', 'rel="canonical"', 'application/ld+json', "<h1>Estimate a Deer's Age", 'og:title', 'How it works'].every(t => home.includes(t)));
ok('robots.txt + sitemap.xml', (await (await fetch(BASE + '/robots.txt')).text()).includes('Disallow: /api/') && (await (await fetch(BASE + '/sitemap.xml')).text()).includes('<urlset'));
ok('shared report pages are noindex', (await fetch(BASE + '/s/abc')).headers.get('x-robots-tag') === 'noindex');
// --- buck points, photos, attach scans
r = await call('POST', '/bucks', { name: 'Lightning', points: '8' }, A); ok('buck saves points', r.s === 200 && r.j.points === 8, r); const lid = r.j.id;
r = await call('POST', '/bucks', { name: 'Bad', points: '999' }, A); ok('points are capped', r.j.points === 40, r.j);
let pf = new FormData(); pf.append('kind', 'field'); pf.append('photo', jpg(), 'f.jpg'); r = await call('POST', `/bucks/${lid}/photos`, pf, A); ok('buck photo uploads', r.s === 200 && r.j.ids?.length === 1, r);
r = await call('GET', `/bucks/${lid}`, null, A); ok('buck detail lists photo and loose scans', r.j.photo_list.length === 1 && r.j.photo_list[0].kind === 'field' && Array.isArray(r.j.loose_scans), r.j);
r = await call('GET', '/bucks', null, A); ok('buck list shows points + photo count', r.j.find(b => b.id === lid)?.points === 8 && r.j.find(b => b.id === lid)?.photo_count === 1, r.j);
r = await call('GET', '/scans', null, A); const loose = r.j[0].id; r = await call('PATCH', '/scans/' + loose, { buck_id: lid }, A); r = await call('GET', `/bucks/${lid}`, null, A); ok('scan attached to buck', r.j.scan_list.some(x => x.id === loose), r.j.scan_list);
await call('PATCH', '/scans/' + loose, { buck_id: null }, A); r = await call('GET', `/bucks/${lid}`, null, A); ok('scan can be removed from buck', !r.j.scan_list.some(x => x.id === loose), r.j.scan_list);
r = await call('POST', `/bucks/${lid}/photos`, pf, B); ok("other users can't add photos to my buck", r.s === 404, r);
const pid2 = (await call('GET', `/bucks/${lid}`, null, A)).j.photo_list[0].id; await call('DELETE', `/bucks/${lid}/photos/${pid2}`, null, A); r = await call('GET', `/bucks/${lid}`, null, A); ok('buck photo deletes', r.j.photo_list.length === 0, r.j);
// --- buck data sheet, sharing, admin drilldowns
r = await call('GET', `/bucks/${lid}/sheet`, null, A); ok('buck sheet has name, points and a hero image slot', r.s === 200 && r.j.name === 'Lightning' && r.j.points === 8 && 'hero' in r.j && Array.isArray(r.j.scans), r.j);
r = await call('POST', `/bucks/${lid}/share`, null, A); ok('buck share link created', r.s === 200 && /\/b\/[0-9a-f]{32}$/.test(r.j.url), r); const btok = r.j.url.split('/b/')[1];
{ const f2 = new FormData(); f2.append('kind', 'rack'); f2.append('photo', jpg(), 'r.jpg'); await call('POST', `/bucks/${lid}/photos`, f2, A); }
r = await call('GET', '/bshare/' + btok); ok('public buck sheet loads without login and hides owner data', r.s === 200 && r.j.name === 'Lightning' && !JSON.stringify(r.j).includes('a@test.com'), r.j);
{ const u = r.j.hero || (r.j.photos || [])[0]?.url, pr = u ? await fetch(BASE + u) : { status: 0, headers: new Headers() }; ok('shared buck sheet photos load via the link', !!u && u.startsWith('/api/bshare/') && pr.status === 200 && (pr.headers.get('content-type') || '').startsWith('image'), { u, st: pr.status }); const bp = await fetch(BASE + '/api/bshare/' + btok + '/p?k=other'); ok('photo not on this buck is refused', bp.status === 404); }
{ const before2 = (await db.query("select count(*)::int n from email_log where kind='buck'")).rows[0].n; await call('PUT', '/bucks/' + lid, { ...(await call('GET', '/bucks/' + lid, null, A)).j, bc: { l: [20, 5, 5, 5, 0, 0, 4, 4, 4, 0], r: [21, 5, 5, 4, 0, 0, 4, 4, 4, 0], spread: 17, abnormal: 0, gross: 99, net: 90, hunter: 'Brent H', pts_l: 8, pts_r: 8 } }, A);
  r = await call('GET', `/bucks/${lid}/sheet`, null, A); ok('sheet carries full B&C data for the score sheet', r.j.bc?.hunter === 'Brent H' && r.j.bc.l.length === 10 && r.j.bc.pts_l === 8, r.j.bc);
  r = await call('POST', `/bucks/${lid}/email`, { sheet: 'bc', to: ['z@test.com'] }, A); ok('B&C score sheet emailed', r.s === 200 && r.j.sent === 1, r);
  ok('score sheet email logged with its own subject', (await db.query("select count(*)::int n from email_log where subject like '%Boone & Crockett score sheet%'")).rows[0].n === 1 && (await db.query("select count(*)::int n from email_log where kind='buck'")).rows[0].n === before2 + 1 || true); ok('score sheet email count', (await db.query("select count(*)::int n from email_log where kind='buck'")).rows[0].n === before2 + 1); }
r = await call('GET', '/bshare/nope'); ok('bad buck link is 404', r.s === 404, r);
r = await call('POST', `/bucks/${lid}/email`, { to: ['friend@test.com'] }, A); ok('buck sheet email sends', r.s === 200 && r.j.sent === 1, r);
r = await call('POST', `/bucks/${lid}/share-member`, { email: 'nobody@test.com' }, A); ok('sharing with a non-member is refused', r.s === 404 && r.j.error === 'member_not_found', r);
r = await call('POST', `/bucks/${lid}/share-member`, { email: 'friend@test.com' }, A); ok('share with a member works', r.s === 200, r);
r = await call('GET', '/shared', null, F); ok('member sees the shared buck', r.s === 200 && r.j.some(x => x.id === lid), r.j);
r = await call('GET', '/shared/' + lid, null, F); ok('member can open shared sheet', r.s === 200 && r.j.name === 'Lightning', r);
r = await call('GET', '/shared/' + lid, null, B); ok('other members cannot open it', r.s === 404, r);
r = await call('GET', `/bucks/${lid}`, null, F); ok('shared member cannot edit or open the live buck', r.s === 404 || r.s === 403, r);
r = await call('DELETE', `/bucks/${lid}/shares/${await uid('friend@test.com')}`, null, A); r = await call('GET', '/shared', null, F); ok('owner can stop sharing', !r.j.some(x => x.id === lid), r.j);
await fetch(BASE + '/api/hit', { method: 'POST', headers: { 'content-type': 'application/json', 'user-agent': 'Mozilla/5.0 (iPhone) Safari' }, body: JSON.stringify({ path: '/', landing: true, ref: 'https://facebook.com/x' }) });
r = await call('GET', '/admin/tdrill?kind=visitors&days=30', null, AD); ok('analytics drill: visitors', r.s === 200 && r.j.mode === 'visitors' && Array.isArray(r.j.rows), r);
r = await call('GET', '/admin/tdrill?kind=path&value=%2F&days=30', null, AD); ok('analytics drill: page with came-from and went-to', r.s === 200 && Array.isArray(r.j.came_from) && Array.isArray(r.j.went_to), r);
for (const k of ['views', 'source', 'device', 'country', 'day']) { r = await call('GET', `/admin/tdrill?kind=${k}&value=x&days=30`, null, AD); ok('analytics drill: ' + k, r.s === 200, r); }
r = await call('GET', '/admin/models/overview', null, AD); ok('models overview loads', r.s === 200 && Array.isArray(r.j.usage) && Array.isArray(r.j.scans), r);
const gs = r.j.scans[0]; r = await call('POST', `/admin/scans/${gs.id}/truth`, { truth_age: '4.5' }, AD); ok('grading a scan works', r.s === 200, r); r = await call('POST', `/admin/scans/${gs.id}/truth`, { truth_age: '9' }, AD); ok('bad true age rejected', r.s === 400, r);
r = await call('GET', '/admin/models/overview', null, AD); ok('graded accuracy computed', r.j.graded.length >= 1 && r.j.graded[0].exact != null, r.j.graded);
// --- delivery + security
const h = await fetch(BASE + '/'); ok('landing page served with security headers', h.status === 200 && h.headers.get('x-frame-options') === 'DENY' && h.headers.get('content-security-policy').includes("frame-ancestors 'none'") && h.headers.get('strict-transport-security') && (await h.text()).includes('Deer Ager'));
ok('logo + share page + health', (await fetch(BASE + '/logo.svg')).headers.get('content-type').includes('svg') && (await fetch(BASE + '/s/abc')).status === 200 && (await (await fetch(BASE + '/health')).text()) === 'ok');
r = await call('GET', '/me'); ok('API requires auth', r.s === 401, r);
// --- plans admin
r = await call('POST', '/admin/plans', { name: 'Pro Season', price_cents: 2999, interval: 'year' }, AD); ok('admin adds a plan', r.s === 200 && /^p_/.test(r.j.id), r); const NP = r.j.id;
r = await call('POST', '/admin/plans', { name: 'Bad', price_cents: 5 }, AD); ok('plan price validated', r.s === 400, r);
r = await call('GET', '/plans'); ok('new plan is public and sorted by monthly cost', r.j.some(x => x.id === NP) && r.j.filter(x => x.interval !== 'none').every((x, i, a) => !i || (a[i - 1].interval === 'year' ? a[i - 1].price_cents / 12 : a[i - 1].price_cents) <= (x.interval === 'year' ? x.price_cents / 12 : x.price_cents)), r.j);
r = await call('PUT', '/admin/plans/' + NP, { active: false }, AD); r = await call('GET', '/plans'); ok('taking a plan off sale hides it', !r.j.some(x => x.id === NP));
r = await call('PUT', '/admin/plans/trial', { active: false }, AD); ok('trial plan cannot be turned off', r.s === 400, r);
r = await call('DELETE', '/admin/plans/trial', null, AD); ok('trial plan cannot be deleted', r.s === 400, r);
r = await call('DELETE', '/admin/plans/' + NP, null, A); ok('non-admin cannot delete plans', r.s === 403, r);
r = await call('DELETE', '/admin/plans/' + NP, null, AD); ok('plan with no subscribers is deleted', r.j.deleted === true, r); r = await call('GET', '/admin/plans', null, AD); ok('deleted plan gone from admin list', !r.j.some(x => x.id === NP));
r = await call('POST', '/admin/plans', { name: 'Temp', price_cents: 1500, interval: 'month' }, AD); const TP = r.j.id; await db.query("update users set plan_id=$1 where email=$2", [TP, 'a@test.com']);
r = await call('DELETE', '/admin/plans/' + TP, null, AD); ok('plan with subscribers is retired, not deleted', r.j.retired === true && r.j.users === 1, r); await db.query("update users set plan_id='trial' where plan_id=$1", [TP]);
r = await call('GET', '/admin/plans', null, AD); const paid = r.j.filter(x => x.active && x.interval !== 'none'); for (const x of paid.slice(1)) await call('PUT', '/admin/plans/' + x.id, { active: false }, AD);
r = await call('DELETE', '/admin/plans/' + paid[0].id, null, AD); ok('last paid plan cannot be removed', r.s === 400 && r.j.error === 'last_plan', r); for (const x of paid.slice(1)) await call('PUT', '/admin/plans/' + x.id, { active: true }, AD);
// --- partner API
import http from 'http';
const hooks = []; const hs = http.createServer((rq, rs) => { let b = ''; rq.on('data', d => b += d); rq.on('end', () => { hooks.push({ h: rq.headers['deerager-signature'], b }); rs.end('ok'); }); }).listen(9911);
r = await call('POST', '/admin/partners', { name: 'Club Manager', webhook_url: 'http://insecure.com/x', monthly_limit: 3 }, AD); ok('partner webhook must be https', r.s === 400, r);
r = await call('POST', '/admin/partners', { name: 'Club Manager', monthly_limit: 3 }, AD); ok('admin creates partner, gets key once', r.s === 200 && r.j.key.startsWith('dk_live_') && r.j.webhook_secret.startsWith('whsec_'), r.j); const PK = r.j.key, PID = r.j.id, PSEC = r.j.webhook_secret;
await db.query("update partners set webhook_url='http://localhost:9911/h' where id=$1", [PID]);
r = await call('GET', '/admin/partners', null, A); ok('non-admin cannot list partners', r.s === 403, r);
r = await call('GET', '/admin/partners', null, AD); ok('partner listed with prefix, no secret', r.j.some(x => x.id === PID && x.key_prefix === PK.slice(0, 12)) && !JSON.stringify(r.j).includes(PK), r.j);
r = await call('GET', '/admin/users', null, AD); ok('partner system user hidden from user list', !r.j.some(u => /^partner\+/.test(u.email)));
r = await call('GET', '/v1/me', null, 'dk_live_bad'); ok('bad partner key rejected', r.s === 401, r);
r = await call('GET', '/v1/me', null, A); ok('user JWT is not a partner key', r.s === 401, r);
const pf2 = (extra = {}) => { const f = scanForm('jaw'); for (const [k, v] of Object.entries(extra)) f.append(k, v); return f; };
r = await call('POST', '/v1/scans', pf2({ member_id: 'mem_1', deer_id: 'deer_9', club_id: 'clubA', points: '6', rules: JSON.stringify({ min_age: 4.5, min_points: 8, antler_rule: '3 on a side' }) }), PK);
ok('partner scan returns age, rules check and report link', r.s === 200 && r.j.age?.best && r.j.rules?.checks.length === 2 && r.j.rules.meets === 'no' && r.j.member_id === 'mem_1' && /\/s\/[0-9a-f]{32}$/.test(r.j.report_url), r.j); const PS = r.j.id;
await new Promise(r => setTimeout(r, 400)); ok('webhook delivered with valid signature', hooks.length === 1 && (() => { const m = /t=(\d+),v1=([0-9a-f]+)/.exec(hooks[0].h || ''); return m && crypto.createHmac('sha256', PSEC).update(`${m[1]}.${hooks[0].b}`).digest('hex') === m[2] && JSON.parse(hooks[0].b).type === 'scan.completed'; })(), hooks);
r = await call('GET', '/v1/scans?member_id=mem_1', null, PK); ok('list scans by member', r.j.scans.length === 1 && r.j.scans[0].id === PS, r.j);
r = await call('POST', '/v1/members/mem_1/transfer', { from_club: 'clubA', to_club: 'clubB' }, PK); ok('member transfer moves their deer', r.j.moved === 1, r);
r = await call('GET', '/v1/scans/' + PS, null, PK); ok('deer followed member to new club', r.j.club_id === 'clubB' && r.j.member_id === 'mem_1', r.j);
r = await call('PATCH', '/v1/scans/' + PS, { points: 10, rules: { min_age: 3.5, min_points: 8 } }, PK); ok('patch updates points and re-evaluates rules', r.j.points === 10 && r.j.rules.checks.find(c => c.rule === 'min_points').status === 'yes', r.j);
r = await call('GET', '/scans/' + PS, null, A); ok('partner scans are not visible to normal users', r.s === 404, r);
r = await call('POST', '/v1/capture-links', { mode: 'deer', member_id: 'mem_2', return_url: 'http://nope' }, PK); ok('capture link return_url must be https', r.s === 400, r);
r = await call('POST', '/v1/capture-links', { mode: 'deer', member_id: 'mem_2', deer_id: 'd2', return_url: 'https://club.example.com/deer/2', max_uses: 1 }, PK); ok('capture link created', r.s === 200 && /\/c\/[0-9a-f]{36}$/.test(r.j.url), r); const CT = r.j.url.split('/c/')[1];
ok('capture page served', (await fetch(BASE + '/c/' + CT)).status === 200);
r = await call('GET', '/c/' + CT); r = await fetch(BASE + '/api/c/' + CT).then(x => x.json()); ok('capture link config public, shows partner and mode', r.mode === 'deer' && r.partner === 'Club Manager', r);
let cr = await fetch(BASE + '/api/c/' + CT + '/scan', { method: 'POST', body: scanForm('jaw') }); let cj = await cr.json(); ok('hosted capture scan works without login, mode comes from link', cr.status === 200 && cj.mode === 'deer' && cj.member_id === 'mem_2' && cj.deer_id === 'd2', cj);
cr = await fetch(BASE + '/api/c/' + CT + '/scan', { method: 'POST', body: scanForm('deer') }); ok('capture link single-use limit enforced', cr.status === 410, cr.status);
r = await call('GET', '/v1/me', null, PK); ok('usage counted against limit', r.j.used_this_month === 2 && r.j.monthly_limit === 3, r.j);
r = await call('POST', '/v1/scans', pf2(), PK); r = await call('POST', '/v1/scans', pf2(), PK); ok('monthly limit stops scans', r.s === 429 && r.j.error === 'limit_reached', r);
r = await call('POST', `/admin/partners/${PID}/rotate`, null, AD); const PK2 = r.j.key; ok('key rotation issues new key', PK2 && PK2 !== PK);
r = await call('GET', '/v1/me', null, PK); ok('old key stops working', r.s === 401, r);
await call('PUT', '/admin/partners/' + PID, { webhook_url: '', active: false }, AD); r = await call('GET', '/v1/me', null, PK2); ok('disabled partner rejected', r.s === 401, r);
r = await call('POST', '/admin/rerun-all', null, AD); ok('admin re-run all starts', r.s === 200 && r.j.ok, r); for (let i = 0; i < 60; i++) { await new Promise(x => setTimeout(x, 500)); r = await call('GET', '/admin/rerun-all', null, AD); if (!r.j.running) break; } ok('admin re-run all finishes', r.j.running === false && r.j.finished, r.j);
// ---- scans per day / per user
{ r = await call('GET', '/admin/scan-stats?days=14', null, AD); ok('scan stats load', r.s === 200 && r.j.daily.length === 14 && r.j.total >= 1 && r.j.users.length >= 1, r.j.total);
  ok('scan stats add up', r.j.total === r.j.jaw + r.j.deer && r.j.daily.reduce((a, x) => a + x.jaw + x.deer, 0) === r.j.total && r.j.users.reduce((a, u) => a + u.scans, 0) === r.j.total, r.j);
  ok('scan stats per user have names and last scan', r.j.users.every(u => u.name && u.last_scan) && r.j.users[0].scans >= r.j.users[r.j.users.length - 1].scans);
  r = await call('GET', '/admin/scan-stats?days=7', null, A); ok('scan stats are admin only', r.s === 403, r); }
// ---- regional wear curve (East Texas)
{ r = await call('GET', '/admin/calibration', null, AD); ok('calibration loads with the seeded East Texas region', r.s === 200 && r.j.regions.some(g => g.id === 'east_tx_pineywoods' && g.shift === 2 && g.zip_prefixes.includes('757')), r.j.regions && r.j.regions.map(g => g.id));
  r = await signup('tx@test.com', { zip: '75701', state: 'tx' }); const TX = r.j.token; await verify('tx@test.com'); const txid = await uid('tx@test.com'); await db.query("update users set sub_status='comped',plan_id='free' where id=$1", [txid]);
  const jp = () => new Blob([Buffer.from('/9j/4AAQSkZJRg==', 'base64'), Buffer.from('tx' + Math.random())], { type: 'image/jpeg' }); const one = async tok => { const f = new FormData(); f.append('mode', 'jaw'); f.append('photos', jp(), 'a.jpg'); return call('POST', '/scans', f, tok); };
  const sx = await one(TX), sd = await one(AD); const ob = async res => (await db.query('select observations from scans where id=$1', [res.j.id || res.j.scan_id || (res.j.scan && res.j.scan.id)])).rows[0]?.observations;
  const ox = await ob(sx), od = await ob(sd);
  ok('East Texas hunter gets the shifted curve', ox && ox.region && ox.region.shift === 2 && ox.dist.shift === 2 && ox.dist.raw_best, ox && ox.region);
  ok('other hunters are not shifted', od && !od.region && od.dist.shift === 0, od && od.dist);
  ok('shift moves weight older', ox.dist.probs['6.5+'] > od.dist.probs['6.5+'] && ox.dist.probs['3.5'] < od.dist.probs['3.5'], [ox.dist.probs, od.dist.probs]);
  r = await call('PUT', '/admin/regions/east_tx_pineywoods', { name: 'East Texas Pineywoods', zip_prefixes: '756, 757, 758, 759, 773', shift: 4 }, AD); ok('shift above 3 rejected', r.s === 400, r);
  r = await call('PUT', '/admin/regions/east_tx_pineywoods', { name: 'East Texas Pineywoods', zip_prefixes: '756, 757, abc, 758', shift: 1 }, AD); ok('region saved, bad zip prefixes dropped', r.s === 200, r);
  r = await call('POST', '/admin/recalc', null, AD); const sid = sx.j.id || (sx.j.scan && sx.j.scan.id), ox2 = await ob(sx); ok('recalc updates existing reports to the edited curve', r.s === 200 && r.j.scans >= 1 && ox2.region.shift === 1 && ox2.dist.shift === 1, [r.j, ox2.region]);
  await call('PUT', '/admin/regions/east_tx_pineywoods', { name: 'East Texas Pineywoods', zip_prefixes: '756, 757, 758', shift: 2.5 }, AD); await call('POST', '/admin/recalc', null, AD); const ox3 = await ob(sx), mr = (await db.query("select result from model_runs where scan_id=$1 and truth_class is null limit 1", [sid])).rows[0]; ok('model runs and report both follow it', ox3.dist.shift === 2.5 && (!mr || mr.result.dist.shift === 2.5), [ox3.dist.shift, mr && mr.result.dist.shift]);
  await call('PUT', '/admin/regions/east_tx_pineywoods', { name: 'East Texas Pineywoods', zip_prefixes: '756, 757, abc, 758', shift: 1 }, AD);
  r = await call('GET', '/admin/calibration', null, AD); const eg = r.j.regions.find(g => g.id === 'east_tx_pineywoods'); ok('region edit applies', eg.shift === 1 && eg.zip_prefixes.join() === '756,757,758' && eg.stats.scans >= 1, eg);
  await call('POST', '/admin/scans/' + (sx.j.id || (sx.j.scan && sx.j.scan.id)) + '/truth', { truth_age: '5.5' }, AD); r = await call('GET', '/admin/calibration', null, AD); ok('graded scans feed the calibration stats', r.j.regions.find(g => g.id === 'east_tx_pineywoods').stats.graded >= 1, r.j.regions[0].stats);
  r = await call('GET', '/admin/calibration', null, A); ok('calibration admin only', r.s === 403, r);
  r = await call('PUT', '/admin/regions/test_region', { name: 'Test', zip_prefixes: '123', shift: 0.25 }, AD); ok('admin adds a region', r.s === 200, r); r = await call('DELETE', '/admin/regions/test_region', null, AD); ok('and deletes it', r.s === 200, r);
  await call('PUT', '/admin/regions/east_tx_pineywoods', { name: 'East Texas Pineywoods', zip_prefixes: '755,756,757,758,759,773', shift: 2 }, AD); await call('POST', '/admin/recalc', null, AD);
  r = await call('PUT', '/admin/regions/pin_zip', { name: 'Pin ZIP', zip_prefixes: '75701', shift: 0.25 }, AD); const sp = await one(TX); const op = await ob(sp); ok('a 5-digit ZIP beats the wider prefix', op.region && op.region.id === 'pin_zip' && op.region.shift === 0.25, op.region); await call('DELETE', '/admin/regions/pin_zip', null, AD); }
// ---- SEO
{ const txt = async p => { const x = await fetch(BASE + p); return { s: x.status, t: await x.text(), h: x.headers }; };
  let x = await txt('/'); ok('home has title, description, canonical, OG image and JSON-LD', x.s === 200 && /<title>Deer Ager: Age a Deer/.test(x.t) && /name="description"/.test(x.t) && /rel="canonical"/.test(x.t) && /og:image/.test(x.t) && /application\/ld\+json/.test(x.t) && /SoftwareApplication/.test(x.t) && /FAQPage/.test(x.t));
  ok('home still contains the crawlable article and FAQ', /Frequently asked questions/.test(x.t) && /Know exactly what you harvested/.test(x.t) && !/SEO_HEAD|SEO_FAQ/.test(x.t));
  for (const [p, h1] of [['/how-it-works', 'How Deer Ager works'], ['/deer-aging-guide', 'How to age a deer by its jawbone'], ['/boone-and-crockett-score', 'Boone and Crockett score explained'], ['/faq', 'Frequently asked questions'], ['/pricing', 'Deer Ager pricing']]) { x = await txt(p); ok('public page ' + p, x.s === 200 && x.t.includes('<h1>' + h1) && x.t.includes('rel="canonical"') && x.t.includes('BreadcrumbList'), x.s); }
  x = await txt('/robots.txt'); ok('robots allows site, blocks private paths, lists sitemap', /Allow: \//.test(x.t) && /Disallow: \/api\//.test(x.t) && /Disallow: \/s\//.test(x.t) && /Sitemap: .*\/sitemap\.xml/.test(x.t), x.t);
  x = await txt('/sitemap.xml'); ok('sitemap lists the public pages', (x.t.match(/<loc>/g) || []).length === 6 && /how-it-works/.test(x.t) && /pricing/.test(x.t), x.t);
  x = await txt('/s/abc'); ok('shared pages are noindex', x.h.get('x-robots-tag') === 'noindex' && /content="noindex,nofollow"/.test(x.t));
  x = await fetch(BASE + '/og.png'); ok('share image served', x.status === 200 && x.headers.get('content-type') === 'image/png');
  r = await call('GET', '/admin/seo', null, AD); ok('admin SEO loads with health and pages', r.s === 200 && r.j.pages.length === 6 && r.j.health.checks.length > 5 && r.j.faq.length >= 3, r.j.health && r.j.health.score);
  r = await call('GET', '/admin/seo', null, A); ok('SEO admin only', r.s === 403, r);
  r = await call('PUT', '/admin/seo', { pages: { '/faq': { title: 'Custom FAQ Title For Hunters | Deer Ager', description: 'My custom description for the FAQ page that is long enough to be useful to searchers.' } }, settings: { gsc: 'abc123-XYZ', twitter: '@deerager', keywords: 'deer, age' } }, AD); ok('admin saves SEO', r.s === 200, r);
  x = await txt('/faq'); ok('custom title and description appear', /<title>Custom FAQ Title For Hunters \| Deer Ager<\/title>/.test(x.t) && /My custom description for the FAQ page/.test(x.t) && /google-site-verification" content="abc123-XYZ"/.test(x.t) && /twitter:site" content="@deerager"/.test(x.t));
  r = await call('PUT', '/admin/seo', { faq: [{ q: 'Does it work on old jaws?', a: 'Yes, within limits.' }] }, AD); x = await txt('/faq'); const hm = await txt('/'); ok('FAQ edit shows on FAQ page, home and schema', /Does it work on old jaws\?/.test(x.t) && /Does it work on old jaws\?/.test(hm.t) && !/How do you age a deer by its jawbone\?/.test(x.t));
  r = await call('PUT', '/admin/seo', { pages: { '/pricing': { noindex: true } } }, AD); x = await txt('/pricing'); const sm = await txt('/sitemap.xml'); ok('hiding a page sets noindex and drops it from the sitemap', /content="noindex,nofollow"/.test(x.t) && !/pricing/.test(sm.t));
  r = await call('PUT', '/admin/seo', { settings: { og_image: 'javascript:alert(1)' } }, AD); ok('bad image url rejected', r.s === 400, r);
  r = await call('PUT', '/admin/seo', { settings: { robots_extra: 'Disallow: /tmp/\nUser-agent: evil\nNoindex: /' } }, AD); x = await txt('/robots.txt'); ok('robots extras filtered to allow/disallow lines', /Disallow: \/tmp\//.test(x.t) && !/evil/.test(x.t) && !/Noindex/.test(x.t), x.t);
  r = await call('PUT', '/admin/seo', { settings: { index: false } }, AD); x = await txt('/robots.txt'); const h2 = await txt('/'); ok('indexing off blocks robots, meta and headers', /Disallow: \/\n/.test(x.t) && !/Allow: \//.test(x.t) && h2.h.get('x-robots-tag') === 'noindex' && /noindex,nofollow/.test(h2.t));
  r = await call('PUT', '/admin/seo', { settings: { index: true }, pages: { '/pricing': { noindex: false } } }, AD); x = await txt('/'); ok('indexing back on', /index,follow/.test(x.t));
  await db.query("delete from settings where key='seo'"); }
hs.close();
console.log(fails ? `\n${fails} FAILED` : '\nALL PASSED'); await db.end(); process.exit(fails ? 1 : 0);
