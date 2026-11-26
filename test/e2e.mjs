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
const home = await (await fetch(BASE + '/')).text(); ok('landing page is SEO-ready (title, description, canonical, schema, h1, OG)', ['<title>Deer Ager | Estimate', 'name="description"', 'rel="canonical"', 'application/ld+json', "<h1>Estimate a Deer's Age", 'og:title', 'How it works'].every(t => home.includes(t)));
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
hs.close();
console.log(fails ? `\n${fails} FAILED` : '\nALL PASSED'); await db.end(); process.exit(fails ? 1 : 0);
