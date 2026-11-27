import { createRequire } from 'module'; const { chromium } = createRequire(import.meta.url)(process.env.PW || 'playwright');
const BASE = process.env.BASE || 'http://localhost:3000'; let fails = 0; const ok = (n, c) => { console.log((c ? 'PASS ' : 'FAIL ') + n); if (!c) fails++; };
const tok = async (email, password) => (await (await fetch(BASE + '/api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, password }) })).json()).token;
import pg from 'pg'; const db = new pg.Client({ connectionString: process.env.DATABASE_URL }); await db.connect();
const b = await chromium.launch(), errs = [];
const T = await tok('bio@test.com', 'correct-horse-9'), H = await tok('admin@test.com', 'adminpass12');
// hunter side: two separate asks on a deer
{ const p = await (await b.newContext({ viewport: { width: 420, height: 900 } })).newPage(); p.on('pageerror', e => errs.push(e.message));
  await p.goto(BASE); await p.evaluate(t => localStorage.setItem('t', JSON.stringify(t)), H).catch(() => {}); await p.evaluate(t => localStorage.setItem('t', t), H); await p.reload();
  await p.waitForSelector('nav'); await p.click('nav >> text=Bucks'); await p.waitForTimeout(800);
  const first = p.locator('.card.click, .click').first(); await first.click().catch(() => {}); await p.waitForTimeout(1200);
  const t = await p.textContent('body'); ok('hunter sees Consult a biologist', /Consult a biologist/.test(t)); ok('hunter sees Biologist age as its own option', /Have a biologist age this deer/.test(t)); }
// biologist side
{ const p = await (await b.newContext({ viewport: { width: 420, height: 900 } })).newPage(); p.on('pageerror', e => errs.push(e.message));
  await p.goto(BASE); await p.evaluate(t => localStorage.setItem('t', t), T); await p.reload(); await p.waitForSelector('nav');
  ok('biologist has the Biologist nav item', await p.locator('nav >> text=Biologist').count() === 1);
  await p.click('nav >> text=Biologist'); await p.waitForTimeout(800);
  for (const tab of ['My consults', 'Earnings', 'Payout setup']) { await p.click(`.tabs >> text=${tab}`); await p.waitForTimeout(600); ok('tab ' + tab + ' renders', !(await p.textContent('#bio')).includes('Loading')); }
  await p.click('.tabs >> text=Earnings'); await p.waitForTimeout(500); ok('earnings shows totals', /Total earned/.test(await p.textContent('#bio'))); }

// the tap-to-pick aging form
{ const bio = (await db.query("select id from users where email='bio@test.com'")).rows[0].id, hu = (await db.query("select id from users where email='admin@test.com'")).rows[0].id;
  const bk = (await db.query("insert into bucks(user_id,name) values($1,'Form Buck') returning id", [hu])).rows[0].id; await db.query("insert into buck_photos(buck_id,s3_key,kind) values($1,'x/f.jpg','jawbone')", [bk]);
  const cid = (await db.query("insert into consults(buck_id,hunter_id,biologist_id,status,kind,price_cents,payout_pct,payout_cents,paid_at,claimed_at) values($1,$2,$3,'claimed','age',3000,70,2100,now(),now()) returning id", [bk, hu, bio])).rows[0].id;
  const p = await (await b.newContext({ viewport: { width: 420, height: 900 } })).newPage(); p.on('pageerror', e => errs.push(e.message));
  await p.goto(BASE); await p.evaluate(t => localStorage.setItem('t', t), T); await p.reload(); await p.waitForSelector('nav');
  await p.evaluate(id => bioOpen(id), cid); await p.waitForSelector('#bform'); await p.waitForTimeout(500);
  ok('form lists tooth questions', /Lower third premolar/.test(await p.textContent('#bform')) && /First molar wear/.test(await p.textContent('#bform')));
  await p.click('#bform >> text=Two cusps'); await p.click('#bform >> text=Fully erupted'); await p.click('#bform >> text=Moderate, dentine'); await p.click('#bform >> text=Clear, enough');
  ok('suggestion appears and fills age', /4\.5 years/.test(await p.textContent('#bform')) && (await p.inputValue('#ba')) === '4.5');
  await p.click('#bform >> text=Live or whole-deer'); ok('deer basis swaps the questions', /Body/.test(await p.textContent('#bform')) && !/First molar wear/.test(await p.textContent('#bform')));
  await p.click('#bform >> text=Jawbone teeth'); await p.click('text=Send report'); await p.waitForSelector('#okgo', { state: 'visible' }); await p.click('#okgo'); await p.waitForTimeout(1200); const r = (await db.query('select status,answer_age,answer_notes from consults where id=$1', [cid])).rows[0];
  ok('report sent from the form', r.status === 'answered' && r.answer_age === '4.5' && /Biologist age report/.test(r.answer_notes), r);
  await db.query('delete from bucks where id=$1', [bk]); }

// admin manages a biologist
{ const p = await (await b.newContext({ viewport: { width: 900, height: 900 } })).newPage(); p.on('pageerror', e => errs.push(e.message));
  await p.goto(BASE); await p.evaluate(t => localStorage.setItem('t', t), H); await p.reload(); await p.waitForSelector('nav');
  await p.evaluate(() => { S.tab = 'consults'; openAdmin(); }); await p.waitForSelector('text=Add biologist'); ok('admin Consults tab has biologist management', /Manage/.test(await p.textContent('#adm')));
  await p.click('#adm tr.click >> nth=0'); await p.waitForSelector('text=Their consults'); const t = await p.textContent('#adm');
  ok('biologist detail shows controls', /Suspend/.test(t) && /Remove biologist role/.test(t) && /Answered/.test(t)); }

// buttons on the age report (top and bottom) open the ask dialog
{ const hu = (await db.query("select id from users where email='admin@test.com'")).rows[0].id;
  const sid = (await db.query("insert into scans(user_id,mode,class,range,confidence,flags,observations) values($1,'jaw','4.5','4.5-5.5',70,'{\"usable\":true}','{}') returning id", [hu])).rows[0].id;
  const p = await (await b.newContext({ viewport: { width: 420, height: 900 } })).newPage(); p.on('pageerror', e => errs.push(e.message));
  await p.goto(BASE); await p.evaluate(t => localStorage.setItem('t', t), H); await p.reload(); await p.waitForSelector('nav');
  await p.evaluate(id => openScan(id), sid); await p.waitForSelector('text=Want a biologist');
  ok('top-right buttons on the age report', await p.locator('button:has-text("Consult a biologist")').count() >= 2 && await p.locator('button:has-text("Biologist age")').count() >= 1);
  const top = await p.locator('button:has-text("Biologist age")').first().boundingBox(); ok('top button is in the upper right', top.y < 250 && top.x > 200, top);
  ok('bottom buttons too', await p.locator('text=Have a biologist age my deer').count() === 1);
  await p.locator('button:has-text("Biologist age")').first().click(); await p.waitForSelector('#bdgo'); ok('dialog opens with price button', /Continue to payment/.test(await p.textContent('#bdgo')));
  await p.click('#bdgo'); ok('asks to name a new deer', /Name the deer/.test(await p.textContent('#bde')));
  await p.fill('#bdname', 'Report Buck'); await p.click('#bdgo'); await p.waitForTimeout(1500);
  const bk = (await db.query("select b.id from bucks b join scans s on s.buck_id=b.id where s.id=$1 and b.name='Report Buck'", [sid])).rows; ok('new deer created and scan attached', bk.length === 1);
  ok('payment failure shows a friendly message, dialog stays', /payment|snag|try again/i.test(await p.textContent('#bde')), await p.textContent('#bde'));
  await db.query('delete from scans where id=$1', [sid]); await db.query("delete from bucks where name='Report Buck'"); }
ok('no js errors', errs.length === 0); if (errs.length) console.log(errs); await b.close(); process.exit(fails ? 1 : 0);
