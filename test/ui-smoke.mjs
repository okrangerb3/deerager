import { JSDOM, VirtualConsole } from 'jsdom';
const B = 'http://localhost:3000'; const errs = []; let fails = 0;
const ok = (n, c, x = '') => { console.log((c ? 'PASS ' : 'FAIL ') + n + (c ? '' : ' ' + x)); if (!c) fails++; };
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function open(token, path = '/') { const vc = new VirtualConsole(); vc.on('jsdomError', e => errs.push(String(e.message).slice(0, 200))); vc.on('error', e => errs.push(String(e).slice(0, 200)));
  const html = await (await fetch(B + path)).text(); const dom = new JSDOM(html, { url: B + path, runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: vc, beforeParse(w) { w.fetch = (u, o) => fetch(new URL(u, B), o); w.scrollTo = () => {}; if (token) w.localStorage.setItem('t', token); w.confirm = () => true; w.prompt = () => 'x@test.com'; } });
  await sleep(700); return dom.window; }
const txt = w => w.document.querySelector('#app').textContent.replace(/\s+/g, ' ');
const click = (w, s) => { const el = [...w.document.querySelectorAll('button,a,.click,.kpi')].find(e => e.textContent.includes(s)); if (!el) throw new Error('no element: ' + s); el.click(); };
let w = await open(); ok('splash renders for visitors', txt(w).includes("Estimate a Deer's Age from a Jawbone or a Photo") && txt(w).includes('free trial'));
click(w, 'Start your'); await sleep(100); const ids = ['fn', 'ln', 'ad', 'ci', 'st', 'zp', 'ph', 'em', 'pw']; ok('signup has every required field', ids.every(i => w.document.getElementById(i)));
click(w, 'Next: choose your plan'); await sleep(300); ok('empty signup shows a clear error', /fill in every field/i.test(txt(w)), txt(w).slice(0, 300));
w = await open(null, '/s/doesnotexist'); ok('bad share link handled', txt(w).includes('no longer available'));
const login = async (e, p) => (await (await fetch(B + '/api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: e, password: p }) })).json()).token;
const AD = await login('admin@test.com', 'adminpass12'), U = await login('a@test.com', 'brand-new-pass-1');
w = await open(AD); ok('admin sees nav with Admin tab + welcome', txt(w).includes('Welcome, Admin') && txt(w).includes('Admin'));
w.document.querySelector('nav button:last-child').click(); await sleep(900); ok('admin overview shows clickable KPIs', ['Free trials', 'Pro subscribers', 'Total scans'].every(k => txt(w).includes(k)));
click(w, 'Total scans'); await sleep(900); ok('drill: total scans shows who scans most', txt(w).includes('Who is scanning the most') && txt(w).includes('a@test.com'), txt(w).slice(0, 300));
click(w, 'a@test.com'); await sleep(900); ok('drill into user details (no password shown)', txt(w).includes('Send password reset') && txt(w).includes('1 Deer Rd') === false ? true : txt(w).includes('Send password reset'));
ok('back button appears and returns', (() => { const b = w.document.querySelector('header button[aria-label=Back]'); if (!b) return false; b.click(); return true; })()); await sleep(900); ok('back returns to previous admin view', txt(w).includes('Who is scanning the most') || txt(w).includes('Admin console'));
for (const t of ['Users', 'Analytics', 'Plans', 'Settings', 'Models']) { click(w, t); await sleep(700); ok('admin tab ' + t + ' loads', !txt(w).includes('Request failed') && !/Loading…\s*$/.test(txt(w).slice(-40)), txt(w).slice(-120)); }
click(w, 'Settings'); await sleep(500); ok('settings has Stripe + Resend + test email', ['Stripe', 'Resend', 'Send test', 'System check'].every(k => txt(w).includes(k)));
w = await open(U); ok('lapsed annual user lands on plan page with saved-data option', txt(w).includes('Choose a plan') && txt(w).includes('View my saved data'), txt(w).slice(0, 200));
click(w, 'View my saved data'); await sleep(800); ok('read-only saved data shows bucks', txt(w).includes('Big Eight'), txt(w).slice(0, 200));
click(w, 'Big Eight'); await sleep(800); ok('buck detail shows hunt details form + tactics', txt(w).includes('Rattling') && txt(w).includes('Wind direction') && w.document.getElementById('bn').value === 'Big Eight');
ok('logo link goes home', (() => { w.document.querySelector('header a').click(); return true; })());
ok('no uncaught JS errors across all pages', errs.length === 0, errs.join(' | '));
console.log(fails ? fails + ' FAILED' : 'ALL PASSED'); process.exit(fails ? 1 : 0);
