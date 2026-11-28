// DeerAger: API + web app (Bun + Hono + Postgres + S3 + Stripe + Resend)
import { AsyncLocalStorage } from 'node:async_hooks'; import { Hono } from 'hono'; import bcrypt from 'bcryptjs'; import jwt from 'jsonwebtoken'; import crypto from 'crypto'; import Stripe from 'stripe'; import pg from 'pg'; import { mountSeo } from './seo'; import { compress } from 'hono/compress';
const env = process.env;
const asset = (n: string) => Bun.file(new URL('../public/' + n, import.meta.url)).text();
const HTML = await asset('index.html'), LOGO = await asset('logo.svg'), LOGOFULL = await asset('logo-full.svg');

// ---------- database, settings, schema
const db = new pg.Pool({ connectionString: env.DATABASE_URL, max: 10 });
const q = (t: string, p: any[] = []) => db.query(t, p).then(r => r.rows);
const audit = (actor: any, action: string, detail: any = {}) => q('insert into audit(actor,action,detail) values($1,$2,$3)', [actor, action, detail]);
const sha = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
const skey = () => crypto.createHash('sha256').update(env.SETTINGS_KEY || env.JWT_SECRET || 'dev').digest();
const enc = (v: string) => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', skey(), iv), d = Buffer.concat([c.update(v, 'utf8'), c.final()]); return 'v1:' + Buffer.concat([iv, c.getAuthTag(), d]).toString('base64'); };
const dec = (s: string) => { const b = Buffer.from(s.slice(3), 'base64'), d = crypto.createDecipheriv('aes-256-gcm', skey(), b.subarray(0, 12)); d.setAuthTag(b.subarray(12, 28)); return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8'); };
const SECRETS = ['stripe_secret_key', 'stripe_webhook_secret', 'resend_api_key'];
const SETTING_KEYS = ['stripe_publishable_key', 'stripe_secret_key', 'stripe_webhook_secret', 'resend_api_key', 'mail_from', 'compare_all', 'analysis_samples'];
async function getSetting(k: string) { const [r] = await q('select value,secret from settings where key=$1', [k]); if (!r) return env[k.toUpperCase()] || null; return r.secret ? dec(r.value) : r.value; }
async function setSetting(k: string, v: string, by: any) { const s = SECRETS.includes(k); await q('insert into settings(key,value,secret,updated_by) values($1,$2,$3,$4) on conflict(key) do update set value=excluded.value,secret=excluded.secret,updated_at=now(),updated_by=excluded.updated_by', [k, s ? enc(v) : v, s, by]); }

const SCHEMA = `create extension if not exists pgcrypto;
create table if not exists plans(id text primary key,name text,price_cents int,interval text,trial_days int default 0,trial_scans int default 0,stripe_price_id text,active bool default true,created_at timestamptz default now());
insert into plans values('trial','Free trial',0,'none',1,3,null,true),('free','Family & friends (free)',0,'none',0,0,null,false),('monthly','Pro Monthly',799,'month',0,0,null,true),('annual','Pro Annual',4999,'year',0,0,null,true),('lapsed','Lapsed',0,'none',0,0,null,false) on conflict do nothing;
update plans set active=false where id='pro';
create table if not exists users(id uuid primary key default gen_random_uuid(),email text unique not null,pw text not null,role text default 'user',status text default 'active',plan_id text references plans(id) default 'trial',stripe_customer text,trial_start timestamptz default now(),scans_used int default 0,created_at timestamptz default now());
create table if not exists bucks(id uuid primary key default gen_random_uuid(),user_id uuid references users(id) on delete cascade,name text not null,hunted_on date,location text,stand text,wind_dir text,temp_f int,rut_phase text,tactics jsonb default '[]',notes text,bc jsonb,created_at timestamptz default now());
create table if not exists scans(id uuid primary key default gen_random_uuid(),user_id uuid references users(id) on delete cascade,mode text not null,class text,range text,confidence int,observations jsonb,flags jsonb,model text,share_token text unique,notes text,created_at timestamptz default now());
create table if not exists photos(id uuid primary key default gen_random_uuid(),scan_id uuid references scans(id) on delete cascade,s3_key text not null,slot int);
create table if not exists model_runs(id bigserial primary key,scan_id uuid references scans(id) on delete cascade,provider text,model text,result jsonb,class text,latency_ms int,error text,truth_class text,created_at timestamptz default now());
create table if not exists audit(id bigserial primary key,actor uuid,action text,detail jsonb,at timestamptz default now());
create table if not exists settings(key text primary key,value text not null,secret bool default false,updated_at timestamptz default now(),updated_by uuid);
create table if not exists email_log(id bigserial primary key,to_addr text,subject text,kind text,status text,error text,at timestamptz default now());
create table if not exists visits(id bigserial primary key,at timestamptz default now(),path text,ref text,utm_source text,utm_medium text,utm_campaign text,visitor text,device text,country text,landing bool default false);
create index if not exists visits_at on visits(at);
create index if not exists scans_user on scans(user_id,created_at desc);`;
await db.query(SCHEMA);
const cols = ['first_name text', 'last_name text', 'address text', 'city text', 'state text', 'zip text', 'phone text', 'email_verified_at timestamptz', 'verify_token text', 'reset_token text', 'reset_expires timestamptz', "sub_status text default 'none'", 'stripe_sub text', 'lifetime_data bool default false', 'cancel_at_end bool default false', 'period_end timestamptz', `prefs jsonb default '{"results_email":false,"billing":true,"extra_emails":[]}'`];
for (const c of cols) await db.query(`alter table users add column if not exists ${c}`);
await db.query('alter table scans add column if not exists buck_id uuid references bucks(id) on delete set null');
await db.query('alter table model_runs add column if not exists confidence int');
await db.query('alter table bucks add column if not exists points int'); await db.query('alter table bucks add column if not exists kill_zip text'); await db.query('alter table bucks add column if not exists known_score numeric'); await db.query('alter table bucks add column if not exists share_token text'); await db.query('alter table plans add column if not exists created_at timestamptz default now()');
await db.query("create table if not exists partners(id uuid primary key default gen_random_uuid(),name text not null,key_hash text unique not null,key_prefix text,user_id uuid,webhook_url text,webhook_secret text,monthly_limit int default 500,active bool default true,created_at timestamptz default now())");
await db.query("create table if not exists capture_links(token text primary key,partner_id uuid references partners(id) on delete cascade,mode text,ext jsonb,return_url text,expires_at timestamptz,used int default 0,max_uses int default 3,created_at timestamptz default now())");
await db.query("create table if not exists consults(id uuid primary key default gen_random_uuid(),buck_id uuid references bucks(id) on delete cascade,hunter_id uuid references users(id) on delete cascade,biologist_id uuid references users(id),status text default 'pending_payment',question text,price_cents int,payout_pct int,payout_cents int,checkout_session text,payment_intent text,charge_id text,answer_age text,answer_conf text,answer_notes text,need_info text,hunter_reply text,payout_status text default 'unpaid',transfer_id text,payout_paid_at timestamptz,created_at timestamptz default now(),paid_at timestamptz,claimed_at timestamptz,answered_at timestamptz,refunded_at timestamptz)");
await db.query("alter table consults add column if not exists kind text default 'age'"); await db.query('alter table users add column if not exists stripe_connect_id text'); await db.query('alter table users add column if not exists bio_title text'); await db.query('alter table consults add column if not exists answer_data jsonb'); await db.query('create table if not exists regions(id text primary key,name text not null,zip_prefixes text[] default \'{}\',shift numeric default 0,note text,created_at timestamptz default now())'); await db.query("insert into regions(id,name,zip_prefixes,shift,note) values('east_tx_pineywoods','East Texas Pineywoods','{755,756,757,758,759,773}',3,'Three years older. East Texas results have run well over two years young, and southeastern studies find tooth wear tends to under-age older deer. Tune it with graded scans in Admin > Calibration.') on conflict do nothing");
await db.query("update regions set shift=1,note='One year older. East Texas results have run at least a year young, and southeastern studies find tooth wear tends to under-age older deer. Tune it with graded scans in Admin > Calibration.' where id='east_tx_pineywoods' and shift=0.5 and note like 'Starting value%'");
await db.query("update regions set shift=2,note='Two years older. East Texas results have run well over a year young, and southeastern studies find tooth wear tends to under-age older deer. Tune it with graded scans in Admin > Calibration.' where id='east_tx_pineywoods' and shift=1 and note like 'One year older%'");
await db.query("update regions set shift=3,note='Three years older. East Texas results have run well over two years young, and southeastern studies find tooth wear tends to under-age older deer. Tune it with graded scans in Admin > Calibration.' where id='east_tx_pineywoods' and shift=2 and note like 'Two years older%'");
await db.query('create table if not exists analysis_cache(key text primary key,provider text,result jsonb,created_at timestamptz default now())'); await db.query('alter table users add column if not exists payout_pct int');
await db.query('alter table model_runs add column if not exists in_tokens int'); await db.query('alter table model_runs add column if not exists out_tokens int'); await db.query('alter table model_runs add column if not exists cost_usd numeric(12,6)'); await db.query('alter table scans add column if not exists reuse_of uuid'); await db.query('alter table scans add column if not exists rollup boolean default false'); await db.query('alter table scans add column if not exists user_age text'); await db.query('alter table scans add column if not exists approval text'); await db.query('alter table scans add column if not exists approval_at timestamptz'); await db.query('alter table scans add column if not exists retake_of uuid'); await db.query('alter table scans add column if not exists partner_id uuid'); await db.query('alter table scans add column if not exists ext jsonb'); await db.query('create index if not exists scans_partner on scans(partner_id,created_at)'); await db.query('alter table bucks add column if not exists property_kind text'); await db.query('alter table bucks add column if not exists property_name text'); await db.query("alter table bucks add column if not exists status text default 'watching'"); await db.query('alter table scans add column if not exists truth_age text'); await db.query('create table if not exists buck_shares(buck_id uuid references bucks(id) on delete cascade,to_user uuid references users(id) on delete cascade,created_at timestamptz default now(),primary key(buck_id,to_user))'); await db.query("create table if not exists buck_photos(id uuid primary key default gen_random_uuid(),buck_id uuid references bucks(id) on delete cascade,s3_key text not null,kind text default 'other',caption text,bytes int,created_at timestamptz default now())");
await db.query('alter table buck_photos add column if not exists view text'); await db.query('alter table buck_photos add column if not exists side text');
await db.query('alter table photos add column if not exists bytes int'); await db.query('alter table photos add column if not exists sha text'); await db.query('alter table scans add column if not exists counted bool default false');
if ((await q("insert into settings(key,value) values('migr_trial_1day','1') on conflict do nothing returning key")).length) await q("update plans set trial_days=1 where id='trial'"); // one-time: 1-day trial
if (env.ADMIN_EMAIL && env.ADMIN_PASSWORD) await db.query("insert into users(email,pw,role,first_name,last_name,email_verified_at) values($1,$2,'admin','Admin','User',now()) on conflict(email) do update set role='admin',email_verified_at=coalesce(users.email_verified_at,now())", [env.ADMIN_EMAIL.toLowerCase(), bcrypt.hashSync(env.ADMIN_PASSWORD, 12)]);
if (env.STRIPE_PUBLISHABLE_KEY) await db.query("insert into settings(key,value) values('stripe_publishable_key',$1) on conflict do nothing", [env.STRIPE_PUBLISHABLE_KEY]);

// ---------- domain logic
const classify = (o: any) => {
  if (!o || o.usable === false) return { cls: null, range: null, rule: null };
  if (o.premolar3_temporary === true) return { cls: 'Fawn', range: 'Under 1 year', rule: 'The 3rd premolar is still a baby (temporary) tooth, which only fawns have, so this is a fawn.' };
  const w = Number(o.molar_wear); if (o.molar_wear == null || !Number.isFinite(w)) return { cls: null, range: null, rule: null };
  if (w <= 0) return { cls: 'Yearling', range: 'About 1.5 years', rule: 'Permanent teeth with almost no molar wear (grade 0, just erupted) means a yearling, about 1.5 years.' };
  if (w === 1) return { cls: '2.5', range: 'About 2.5 years', rule: 'Light molar wear (grade 1) means about 2.5 years, though light wear is easy to misjudge, so he could be older.' };
  if (w === 2) return { cls: 'Middle', range: 'About 3.5-5.5 years', rule: 'Moderate molar wear (grade 2, dentine wider than enamel) means middle-aged, about 3.5 to 5.5 years.' };
  return { cls: 'Old', range: '6+ years (wear aging is unreliable here)', rule: 'Heavy molar wear (grade 3) means an older deer, 6+ years. Wear is the least reliable way to age deer at this stage.' };
};
const bc = ({ l, r, spread = 0, abnormal = 0 }: any) => {
  const sum = (a: any[]) => a.reduce((x, y) => x + (+y || 0), 0);
  const gross = sum(l) + sum(r) + Math.min(+spread || 0, Math.max(+l[0] || 0, +r[0] || 0)); // spread credit capped at the longer main beam
  const deductions = l.reduce((a: number, v: any, i: number) => a + Math.abs((+v || 0) - (+r[i] || 0)), 0) + (+abnormal || 0);
  return { gross, deductions, net: gross - deductions, estimate: true };
};
const PROMPT: any = {
  sheet: 'You read a photographed Boone and Crockett whitetail score sheet, printed or handwritten. Copy exactly what is written, never calculate or guess. Answer with ONLY this JSON: {"usable":bool,"right":[12 numbers or null],"left":[12 numbers or null],"points_r":number|null,"points_l":number|null,"tip":number|null,"greatest":number|null,"inside":number|null,"abnormal":number|null,"gross":number|null,"net":number|null,"hunter":string|null}. right and left are the Column 2 (right antler) and Column 3 (left antler) values in THIS order: F main beam, G-1, G-2, G-3, G-4, G-5, H-1, H-2, H-3, H-4, G-6, G-7. Use null for any box that is blank or unreadable. inside = D inside spread of main beams, abnormal = E total of abnormal points, gross = the gross score line, net = the final net score line. usable=false if this is not a score sheet or nothing is readable.',
  kind: 'Look at this one photo from a deer hunter and say what it shows. Answer with ONLY this JSON: {"kind":"jawbone"|"field"|"rack"|"mount"|"other","view":"side"|"top"|"tilt"|"close_molars"|"close_premolars"|"front"|"unknown","side":"left"|"right"|"both"|"unknown"}. kind: jawbone = a deer lower jaw or teeth, loose or on a skull. field = a live or downed deer, a deer in the woods, a trail camera or stand photo, or a whole animal. rack = antlers or a skull cap with antlers. mount = taxidermy or a wall mount. other = anything else. For a jawbone only (otherwise use "unknown"): view = side (the cheek side of the tooth row seen from the side, roughly level or slightly from above), top (looking straight down on the chewing surface of the row), tilt (an angled view across the chewing surface), close_molars (tight close-up of the first and second molars), close_premolars (tight close-up of the premolars and front of the tooth row), front (the front teeth, incisors). side = which half of the lower jaw (the animal\'s own left or right) the photo shows, worked out from which way the tooth row runs (front incisors versus back molars), where the cheek side is, and the curve of the bone; both if the photo shows both halves, unknown if you truly cannot tell. Do not guess a side you cannot see.',
  jaw: 'You assist a hunter aging a white-tailed deer from lower-jaw photos using tooth replacement and wear (Severinghaus). Wear past 2.5 years is unreliable even for experts: be conservative. Grade molar wear on the FIRST and SECOND molars (they wear first), on every visible cusp, not the back molar. Known bias: graders under-call wear and under-age older deer. Give grade 1 only when enamel is clearly wider than dentine on all cusps and the cusps are sharp and tall; if torn between 1 and 2, choose 2; if torn between 2 and 3, choose 3. A big rack or body does not change the jaw grade.',
  deer: 'You assist a hunter estimating the age class of a whole white-tailed deer from body photos. This is unreliable: cap confidence at 60.',
  bc: 'You estimate Boone and Crockett typical whitetail net score from antler photos using a visible scale reference. If none, usable=false.'
};
const FORMAT = ' Reply with ONLY one JSON object with these fields: {"usable":bool,"quality":0-100 (overall photo quality),"premolar3_temporary":bool|null,"molar_wear":0|1|2|3|null,"net_low":number|null,"net_high":number|null,"confidence":0-100,"reasoning":"3-6 plain sentences, written for a hunter, explaining how what you saw leads to this age","features":[{"feature":"e.g. 3rd premolar","observation":"what you see","points_to":"what that suggests about age"}],"alternatives":["other age classes you considered and why they are less likely"],"photo_notes":["one note per photo: what it shows and any quality problem"],"evidence":[string],"would_change_answer":["specific extra photo or fact that would raise or change your confidence"],"age_probs":{"0.5":n,"1.5":n,"2.5":n,"3.5":n,"4.5":n,"5.5":n,"6.5+":n} (your honest percent probability for each age, summing to 100; lean toward the most likely age and be decisive, but reflect real uncertainty: for jaws weigh dentine-to-enamel ratio, cusp sharpness and wear grade; for live deer weigh leg length to body depth, belly sag, neck and shoulder muscle, swayback, face shape),"missing":[specific extra photo or fix needed],"issues":[string]}. Wear scale: 0 unworn/just erupted, 1 light, 2 moderate (dentine wider than enamel), 3 heavy. If photos are blurry, glared, dark, incomplete or not what was requested, set usable=false and say exactly what to retake. Never guess.';
const usageBox = new AsyncLocalStorage<any>();
const post = async (url: string, headers: any, body: any) => { const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body), signal: AbortSignal.timeout(120000) }); if (!r.ok) throw new Error(`${r.status} ${(await r.text()).slice(0, 200)}`); const j: any = await r.json(), st = usageBox.getStore(), u = j.usage || j.usageMetadata;
  if (st && u) { st.inTok = (st.inTok || 0) + (u.input_tokens ?? u.prompt_tokens ?? u.promptTokenCount ?? 0); st.outTok = (st.outTok || 0) + (u.output_tokens ?? u.completion_tokens ?? ((u.candidatesTokenCount ?? 0) + (u.thoughtsTokenCount ?? 0))); } return j; };
// Prices in USD per million tokens. Defaults come from published rates in Nov 2026; admins can override them in Admin > Costs because vendors change prices often.
const DEFAULT_PRICES: any = { 'claude-opus-5-5': { in: 4, out: 20 }, 'claude-sonnet-5-5': { in: 3, out: 15 }, 'gpt-6.2-astra': { in: 8, out: 40 }, 'gemini-4-argon': { in: 4, out: 20 }, 'gemini-2.5-flash': { in: 0.3, out: 2.5 }, 'gpt-4o': { in: 2.5, out: 10 } };
async function prices() { let o: any = {}; try { o = JSON.parse((await getSetting('cost_prices')) || '{}'); } catch {} return { ...DEFAULT_PRICES, ...o }; }
const runCost = (pr: any, model: string, i: number, o: number) => { const p = pr[model]; return p && (i || o) ? Math.round(((i * p.in + o * p.out) / 1e6) * 1e6) / 1e6 : null; };
const parse = (t: string) => { const m = t.match(/\{[\s\S]*\}/); return JSON.parse(m ? m[0] : t); };
const NOTEMP: any = {}; const tOpt = (p: string, t: any, extra: any = {}) => (t != null && !NOTEMP[p] ? { temperature: t, ...extra } : {});
const PROV: any = {
  claude: async (imgs: any[], mode: string, temp?: number) => (await post((env.ANTHROPIC_URL || 'https://api.anthropic.com') + '/v1/messages', { 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' }, { model: env.MODEL_CLAUDE, max_tokens: 6000, ...tOpt('claude', temp), messages: [{ role: 'user', content: [...imgs.map(i => ({ type: 'image', source: { type: 'base64', media_type: i.mime, data: i.b64 } })), { type: 'text', text: PROMPT[mode] + ((imgs as any).note || '') + (mode === 'kind' || mode === 'sheet' ? '' : FORMAT) }] }] })).content.map((c: any) => c.text || '').join(''),
  openai: async (imgs: any[], mode: string, temp?: number) => (await post('https://api.openai.com/v1/chat/completions', { authorization: 'Bearer ' + env.OPENAI_API_KEY }, { model: env.MODEL_OPENAI, response_format: { type: 'json_object' }, ...tOpt('openai', temp, { seed: 7 }), messages: [{ role: 'user', content: [...imgs.map(i => ({ type: 'image_url', image_url: { url: `data:${i.mime};base64,${i.b64}` } })), { type: 'text', text: PROMPT[mode] + ((imgs as any).note || '') + (mode === 'kind' || mode === 'sheet' ? '' : FORMAT) }] }] })).choices[0].message.content,
  gemini: async (imgs: any[], mode: string, temp?: number) => (await post(`https://generativelanguage.googleapis.com/v1beta/models/${env.MODEL_GEMINI}:generateContent`, { 'x-goog-api-key': env.GEMINI_API_KEY }, { contents: [{ parts: [...imgs.map(i => ({ inline_data: { mime_type: i.mime, data: i.b64 } })), { text: PROMPT[mode] + ((imgs as any).note || '') + (mode === 'kind' || mode === 'sheet' ? '' : FORMAT) }] }], generationConfig: { responseMimeType: 'application/json', ...tOpt('gemini', temp) } })).candidates[0].content.parts.map((p: any) => p.text || '').join('')
};
const KEYS: any = { claude: 'ANTHROPIC_API_KEY', openai: 'OPENAI_API_KEY', gemini: 'GEMINI_API_KEY' };
const configured = () => Object.keys(PROV).filter(p => env.MOCK_MODELS || (env[KEYS[p]] && env['MODEL_' + p.toUpperCase()]));
// Circuit breaker: a model that fails for a lasting reason (no credit, bad key, unknown model) is skipped for 15 minutes so scans stay fast and users never wait on it. Admins see why in Admin > Models.
const BREAKER: any = {};
const fatalErr = (m: string) => /^(401|403|404) /.test(m) || /quota|billing|insufficient|no credits/i.test(m);
const live = (all: string[]) => { const ok = all.filter(p => !(BREAKER[p]?.until > Date.now())); return ok.length ? ok : all; }; // if every model is tripped, try them all anyway
const MOCK: any = { claude: [2, 82], openai: [2, 71], gemini: [1, 58] };
async function runOnce(p: string, imgs: any[], mode: string, temp?: number) {
  const t = Date.now(), model = env.MOCK_MODELS ? 'mock-' + p : env['MODEL_' + p.toUpperCase()];
  if (env.MOCK_MODELS && (env.MOCK_FAIL || '').split(',').some(x => x === p || x === 'all')) return { provider: p, model, ms: 1, error: '429 You have no credits remaining (mock)' }; // test hook
  if (env.MOCK_MODELS && mode === 'sheet') return { provider: p, model, ms: 1, result: { usable: true, right: [24, 8, 9, 9, 6, 0, 4.5, 4.4, 4.3, 4, 0, 0], left: [23.5, 8, 9.5, 8.5, 6, 0, 4.5, 4.5, 4.2, 4, 0, 0], points_r: 4, points_l: 4, tip: 12, greatest: 18, inside: 17, abnormal: 0, gross: 150, net: 146.5, hunter: 'Test Hunter' } };
  if (env.MOCK_MODELS && mode === 'kind') return { provider: p, model, ms: 1, result: { kind: env.MOCK_KIND || 'jawbone', view: env.MOCK_VIEW || 'side', side: env.MOCK_SIDE || 'left' } };
  if (env.MOCK_MODELS) return { provider: p, model, ms: 1, inTok: 6000, outTok: 1200, result: mode === 'bc' ? { usable: false, quality: 80, confidence: 20, missing: ['Add a ruler or hat for scale'], issues: ['No scale reference'] } : { usable: true, quality: 90, premolar3_temporary: false, molar_wear: MOCK[p][0], age_probs: { '2.5': 5, '3.5': 25, '4.5': 40, '5.5': 22, '6.5+': 8 }, confidence: MOCK[p][1], evidence: ['mock evidence from ' + p], reasoning: 'The third premolar is a permanent tooth and the molar crests show moderate wear, so this deer is middle-aged.', features: [{ feature: '3rd premolar', observation: 'Permanent, two cusps', points_to: 'Yearling or older' }, { feature: 'First molar', observation: 'Dentine wider than enamel', points_to: 'Moderate wear, about 3.5-5.5 years' }], alternatives: ['2.5 years: less likely because the dentine is wider than the enamel'], photo_notes: ['Photo 1: sharp, good light'], would_change_answer: ['A top-down photo of the molars would confirm the wear grade'], missing: [], issues: [] } };
  let last = '', tin = 0, tout = 0;
  for (let i = 0; i < 2; i++) { // one retry for transient failures (overload, timeout, truncated or malformed JSON); tokens from every attempt are billed, so all are counted
    const box: any = {};
    try { const txt = await usageBox.run(box, () => PROV[p](imgs, mode, temp)); tin += box.inTok || 0; tout += box.outTok || 0; return { provider: p, model, result: parse(txt), ms: Date.now() - t, inTok: tin, outTok: tout }; } catch (e: any) { tin += box.inTok || 0; tout += box.outTok || 0; last = String(e.message || e).slice(0, 300); console.error(`model ${p} failed (try ${i + 1}, ${imgs.length} imgs, ${Math.round(imgs.reduce((a: number, x: any) => a + x.b64.length, 0) / 1024)} KB):`, last); if (/^400 /.test(last) && /temperature|seed/i.test(last) && !NOTEMP[p]) { NOTEMP[p] = true; continue; } if (/^(400|401|403|404) /.test(last) || /quota|billing|insufficient/i.test(last)) break; }
  }
  return { provider: p, model, error: last, ms: Date.now() - t, inTok: tin, outTok: tout };
}
// ---------- consistent readings: fixed seed/temperature, several passes per model voted together, and a cache so the same photos always give the same answer
const PV = 'v2';
const med = (a: number[]) => { const x = [...a].sort((m, n) => m - n); return x[Math.floor(x.length / 2)]; };
function aggregate(rs: any[]) {
  if (rs.length === 1) return rs[0];
  const usable = rs.filter(r => r && r.usable !== false); if (usable.length * 2 <= rs.length) return [...rs].sort((a, b) => (b?.quality || 0) - (a?.quality || 0))[0];
  const wears = usable.map(r => r.molar_wear).filter(w => w != null && Number.isFinite(+w)).map(Number), wear = wears.length ? med(wears) : null;
  const p3t = usable.filter(r => r.premolar3_temporary === true).length, p3f = usable.filter(r => r.premolar3_temporary === false).length, p3 = p3t + p3f === 0 ? null : p3t > p3f;
  const rep = usable.filter(r => wear != null && Number(r.molar_wear) === wear).sort((a, b) => (b.confidence || 0) - (a.confidence || 0))[0] || usable[0];
  const probs: any = {}; for (const a of AGES) probs[a] = usable.reduce((t, r) => t + (+(r.age_probs || {})[a] || 0), 0) / usable.length;
  const agree = wears.length ? wears.filter(w => w === wear).length / wears.length : 1;
  return { ...rep, premolar3_temporary: p3, molar_wear: wear, age_probs: probs, confidence: Math.round(med(usable.map(r => +r.confidence || 0)) * (0.6 + 0.4 * agree)), quality: med(usable.map(r => +r.quality || 0)), consistency: { samples: rs.length, usable: usable.length, wear_votes: wears, agree: Math.round(agree * 100) / 100 } };
}
async function samplesN() { const n = +((await getSetting('analysis_samples')) || 3); return Number.isInteger(n) && n >= 1 && n <= 5 ? n : 3; }
async function runModel(p: string, imgs: any[], mode: string) {
  if (env.MOCK_MODELS) return runOnce(p, imgs, mode);
  const model = env['MODEL_' + p.toUpperCase()], k = mode === 'bc' ? 1 : await samplesN(), h = crypto.createHash('sha256'); h.update([PV, p, model, mode, k, (imgs as any).note || '', PROMPT[mode], FORMAT].join('|')); for (const i of imgs) h.update(crypto.createHash('sha256').update(i.b64).digest()); const key = h.digest('hex');
  const [hit] = await q('select result from analysis_cache where key=$1', [key]); if (hit) return { provider: p, model, result: hit.result, ms: 0, inTok: 0, outTok: 0, cached: true };
  const t = Date.now(), runs: any[] = await Promise.all(Array.from({ length: k }, () => runOnce(p, imgs, mode, k > 1 ? 0.5 : 0))), good = runs.filter(r => r.result), inTok = runs.reduce((a, r) => a + (r.inTok || 0), 0), outTok = runs.reduce((a, r) => a + (r.outTok || 0), 0);
  if (!good.length) return { ...runs[0], inTok, outTok, ms: Date.now() - t };
  const result = aggregate(good.map(r => r.result)); await q('insert into analysis_cache(key,provider,result) values($1,$2,$3) on conflict do nothing', [key, p, result]);
  return { provider: p, model, result, ms: Date.now() - t, inTok, outTok };
}
const confDetail = (o: any, mode: string) => { const cap = mode === 'jaw' ? 100 : 60, m = o?.confidence ?? 0, q = o?.quality ?? 100, f = Math.max(0, Math.min(m, q, cap)); return { model: m, quality: q, cap, final: f, limited_by: q < m && q <= cap ? 'photo quality' : cap < m && cap < q ? 'the method limit' : 'AI certainty' }; };
const conf = (o: any, mode: string) => confDetail(o, mode).final;
// Age probability: the model's own distribution blended with a population prior. The less we trust the photos, the more the prior (and so honest uncertainty) shows.
const AGES = ['0.5', '1.5', '2.5', '3.5', '4.5', '5.5', '6.5+'];
const PRIOR: any = { '0.5': 0.02, '1.5': 0.18, '2.5': 0.22, '3.5': 0.22, '4.5': 0.17, '5.5': 0.12, '6.5+': 0.07 };
const FIXED: any = { Fawn: { '0.5': 1 }, Yearling: { '1.5': 0.88, '2.5': 0.12 }, '2.5': { '1.5': 0.04, '2.5': 0.5, '3.5': 0.32, '4.5': 0.14 } }; // light wear is often misjudged on older deer, so a grade-1 call keeps real weight on 3.5+
// Shift a distribution toward older classes (regional wear curve). s is in age classes, so 0.5 moves half the weight up one class. Fawn and yearling calls come from tooth replacement, which does not vary by region, so they are never shifted.
const shiftDist = (m: any, sh: number) => { const up = (x: any) => { const r: any = {}; for (const a of AGES) r[a] = 0; AGES.forEach((a, i) => { r[AGES[Math.min(i + 1, AGES.length - 1)]] += x[a] || 0; }); return r; }; let cur: any = { ...m }; for (const a of AGES) cur[a] = cur[a] || 0; const whole = Math.floor(sh), f = sh - whole; for (let i = 0; i < whole; i++) cur = up(cur); if (f > 0) { const u1 = up(cur), r: any = {}; for (const a of AGES) r[a] = (1 - f) * cur[a] + f * u1[a]; cur = r; } return cur; };
// Antler size is only supporting evidence: a known Boone & Crockett net score gently shifts the odds toward the ages that usually carry that much antler. It never decides the age.
const ANTLER_L: [number, any][] = [[90, { '0.5': 1, '1.5': 1.6, '2.5': 1.5, '3.5': 0.9, '4.5': 0.5, '5.5': 0.35, '6.5+': 0.3 }], [110, { '1.5': 1.4, '2.5': 1.5, '3.5': 1.1, '4.5': 0.7, '5.5': 0.5, '6.5+': 0.4 }], [130, { '1.5': 0.6, '2.5': 1, '3.5': 1.3, '4.5': 1.2, '5.5': 0.9, '6.5+': 0.8 }], [150, { '1.5': 0.3, '2.5': 0.6, '3.5': 1.1, '4.5': 1.5, '5.5': 1.4, '6.5+': 1.2 }], [1e9, { '1.5': 0.15, '2.5': 0.3, '3.5': 0.8, '4.5': 1.4, '5.5': 1.6, '6.5+': 1.5 }]];
const ANTLER_W = 0.5;
function applyAntler(d: any, score: number | null) {
  if (!d || !(score > 0) || d.probs['0.5'] >= 99) return d;
  const L = ANTLER_L.find(x => score < x[0])![1], probs: any = {}; let tot = 0;
  for (const a of AGES) { probs[a] = (d.probs[a] || 0) * (1 + ANTLER_W * ((L[a] ?? 1) - 1)); tot += probs[a]; }
  for (const a of AGES) probs[a] = Math.round((probs[a] / tot) * 1000) / 10;
  const best = AGES.reduce((x, y) => (probs[y] > probs[x] ? y : x)); let cum = 0, lo = AGES[0], hi = AGES[AGES.length - 1], gotLo = false;
  for (const a of AGES) { cum += probs[a]; if (!gotLo && cum >= 10) { lo = a; gotLo = true; } if (cum >= 90) { hi = a; break; } }
  return { ...d, probs, best, lo, hi, antler: { score, before: d.best } };
}
const antlerFor = (b: any): number | null => { const k = +b?.known_score, n = +(b?.bc?.net ?? b?.bc_net); return k > 0 ? k : n > 0 ? n : null; };
const ageDist = (o: any, mode: string, cls: string | null, cf: number, shift = 0, antler: number | null = null) => {
  if (!o || o.usable === false || mode === 'bc') return null;
  let m: any = FIXED[cls as string] || null;
  if (!m && o.age_probs && typeof o.age_probs === 'object') { m = {}; let t = 0; for (const a of AGES) { m[a] = Math.max(0, +o.age_probs[a] || 0); t += m[a]; } if (t > 0) for (const a of AGES) m[a] /= t; else m = null; }
  if (!m && cls === 'Middle') m = { '3.5': 0.36, '4.5': 0.34, '5.5': 0.3 }; if (!m && cls === 'Old') m = { '5.5': 0.3, '6.5+': 0.7 };
  if (!m) return null;
  const c = Math.min(cf / 100, mode === 'jaw' ? 0.9 : 0.6), mk = (mm: any) => { const probs: any = {}; let tot = 0;
    for (const a of AGES) { probs[a] = c * (mm[a] || 0) + (1 - c) * PRIOR[a]; tot += probs[a]; }
    for (const a of AGES) probs[a] = Math.round((probs[a] / tot) * 1000) / 10;
    const best = AGES.reduce((x, y) => (probs[y] > probs[x] ? y : x)); let cum = 0, lo = AGES[0], hi = AGES[AGES.length - 1], gotLo = false;
    for (const a of AGES) { cum += probs[a]; if (!gotLo && cum >= 10) { lo = a; gotLo = true; } if (cum >= 90) { hi = a; break; } }
    return { probs, best, lo, hi, method: mode }; };
  const raw = mk(m), sh = shift > 0 && cls !== 'Fawn' && cls !== 'Yearling' && mode === 'jaw' ? shift : 0;
  return applyAntler(sh ? { ...mk(shiftDist(m, sh)), raw_best: raw.best, shift: sh } : { ...raw, raw_best: raw.best, shift: 0 }, antler);
};

const regionFor = async (u: any) => { const z = String(u?.zip || '').replace(/\D/g, ''); if (z.length < 3) return null; const [r] = await q('select r.id,r.name,r.shift::float shift from regions r where exists (select 1 from unnest(r.zip_prefixes) p where $1 like p || \'%\') order by (select max(length(p)) from unnest(r.zip_prefixes) p where $1 like p || \'%\') desc limit 1', [String(u.zip).replace(/\D/g, '').slice(0, 5)]); return r || null; };
// The curve for one deer: the region of the ZIP where he was killed (else the hunter's own ZIP), plus an optional adjustment for the rut phase he was taken in (set in Admin > Calibration, 0 by default).
const RUT_PHASES = ['Early / pre-rut', 'Seeking', 'Chasing', 'Peak breeding', 'Post-rut', 'Not rutting'];
async function rutShifts() { try { const j = JSON.parse((await getSetting('rut_shifts')) || '{}'); return Object.fromEntries(RUT_PHASES.map(k => [k, Math.max(-1, Math.min(1, +j[k] || 0))])); } catch { return Object.fromEntries(RUT_PHASES.map(k => [k, 0])); } }
async function curveFor(u: any, buck: any) {
  const rgn = await regionFor({ zip: buck?.kill_zip || u?.zip }), rs = (await rutShifts())[buck?.rut_phase] || 0; if (!rgn && !rs) return null;
  return { id: rgn?.id || 'rut', name: rgn?.name || 'Rut phase', shift: Math.max(0, (rgn?.shift || 0) + rs), region_shift: rgn?.shift || 0, rut: rs ? { phase: buck.rut_phase, shift: rs } : null };
}
// ---------- email (Resend)
async function mail(to: string, subject: string, body: string, kind = 'misc') {
  const key = await getSetting('resend_api_key'), from = (await getSetting('mail_from')) || 'Deer Ager <noreply@deerager.com>';
  const html = `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;color:#2d3a1f"><h2 style="font-family:Georgia,serif;font-style:italic">Deer <span style="color:#b8923a">Ager</span></h2>${body}<p style="color:#888;font-size:12px;margin-top:24px">Deer Ager results are estimates, not official ages or scores.</p></div>`;
  let status = 'logged', error: string | null = null;
  if (key) { try { const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { authorization: 'Bearer ' + key, 'content-type': 'application/json' }, body: JSON.stringify({ from, to: [to], subject, html }) }); status = r.ok ? 'sent' : 'failed'; if (!r.ok) error = (await r.text()).slice(0, 300); } catch (e: any) { status = 'failed'; error = String(e.message); } }
  await q('insert into email_log(to_addr,subject,kind,status,error) values($1,$2,$3,$4,$5)', [to, subject, kind, status, error]); return status;
}
const mailTo = async (acc: { n: number; err?: string }, ...a: [string, string, string, string?]) => { const st = await mail(...a); if (st === 'sent' || (st === 'logged' && env.MOCK_MODELS)) acc.n++; else acc.err = st === 'logged' ? 'email_not_configured' : 'email_failed'; };
const emailRes = (c: any, acc: { n: number; err?: string }, total: number) => acc.n ? c.json({ ok: true, sent: acc.n, failed: total - acc.n }) : c.json({ error: acc.err || 'email_failed' }, 502);
const btn = (url: string, label: string) => `<p><a href="${url}" style="background:#2f6b3f;color:#fff;padding:12px 20px;border-radius:8px;text-decoration:none;display:inline-block">${label}</a></p><p style="font-size:12px;color:#666">Or paste this link: ${url}</p>`;
const eh = (s: any) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' } as any)[c]);
async function sendVerify(u: any) { const t = crypto.randomBytes(32).toString('hex'); await q('update users set verify_token=$1 where id=$2', [sha(t), u.id]); return mail(u.email, 'Confirm your Deer Ager account', `<p>Hi ${eh(u.first_name)}, confirm your email to activate your account.</p>${btn(`${env.APP_URL}/api/verify?token=${t}`, 'Confirm my email')}`, 'verify'); }
async function makeReset(u: any, hours = 1) { const t = crypto.randomBytes(32).toString('hex'); await q("update users set reset_token=$1,reset_expires=now()+($3||' hours')::interval where id=$2", [sha(t), u.id, String(hours)]); return `${env.APP_URL}/?reset=${t}`; }
async function sendReset(u: any) { const link = await makeReset(u); return mail(u.email, 'Reset your Deer Ager password', `<p>Hi ${eh(u.first_name)}, use this link within 1 hour to set a new password.</p>${btn(link, 'Reset password')}<p>If you did not request this, you can ignore it.</p>`, 'reset'); }
const wantsBilling = (u: any) => u.prefs?.billing !== false;

// ---------- app, security, auth
const app = new Hono();
app.use('*', compress());
app.use('*', async (c, next) => { await next(); c.header('x-content-type-options', 'nosniff'); c.header('x-frame-options', 'DENY'); c.header('referrer-policy', 'strict-origin-when-cross-origin'); c.header('strict-transport-security', 'max-age=31536000; includeSubDomains'); c.header('permissions-policy', 'camera=(self), microphone=(), geolocation=()');
  c.header('content-security-policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"); if (c.req.path.startsWith('/api')) c.header('cache-control', 'no-store'); });
const hits = new Map<string, number[]>();
const limited = (c: any, name: string, max = 10) => { if (env.MOCK_MODELS) max = 9999; const ip = (c.req.header('x-forwarded-for') || '').split(',')[0].trim() || 'local', k = name + ip, now = Date.now(), a = (hits.get(k) || []).filter(t => now - t < 9e5); a.push(now); hits.set(k, a); if (hits.size > 5000) hits.clear(); return a.length > max; };
const s3 = new Bun.S3Client({ endpoint: env.S3_ENDPOINT, bucket: env.S3_BUCKET, region: env.S3_REGION || 'auto', accessKeyId: env.S3_ACCESS_KEY_ID, secretAccessKey: env.S3_SECRET_ACCESS_KEY, virtualHostedStyle: env.S3_VHOST === 'true' });
const sign = (u: any) => jwt.sign({ id: u.id }, env.JWT_SECRET!, { expiresIn: '30d' });
const ACTIVE = ['trialing', 'active', 'comped'];
const STAFF = (u: any) => u.role === 'admin' || u.role === 'biologist';
const canScan = (u: any) => STAFF(u) || (ACTIVE.includes(u.sub_status) && (u.sub_status !== 'trialing' || u.scans_used < u.trial_scans));
const dataOk = (u: any) => STAFF(u) || u.lifetime_data || [...ACTIVE, 'past_due'].includes(u.sub_status);
const stage = (u: any) => (STAFF(u) || ACTIVE.includes(u.sub_status) || u.sub_status === 'past_due') ? 'ready' : 'pay';
const view = (u: any) => { const { pw, verify_token, reset_token, reset_expires, ...v } = u; return { ...v, stage: stage(u), can_scan: canScan(u), data_locked: !dataOk(u) }; };
const auth = async (c: any, next: any) => {
  try { const p: any = jwt.verify((c.req.header('authorization') || '').replace('Bearer ', ''), env.JWT_SECRET!);
    const [u] = await q("select u.*,(select trial_scans from plans where id='trial') trial_scans,(select trial_days from plans where id='trial') trial_days from users u where u.id=$1", [p.id]);
    if (!u || u.status !== 'active') return c.json({ error: 'account_inactive' }, 403); c.set('user', u);
  } catch { return c.json({ error: 'unauthorized' }, 401); } await next();
};
const admin = async (c: any, next: any) => c.get('user').role === 'admin' ? next() : c.json({ error: 'forbidden' }, 403);
const gate = async (c: any, next: any) => dataOk(c.get('user')) ? next() : c.json({ error: 'data_locked' }, 403);

app.post('/api/hit', async c => { if (limited(c, 'hit', 300)) return c.body(null, 204); const b = await c.req.json().catch(() => ({})), ua = c.req.header('user-agent') || '';
  if (!ua || /bot|crawl|spider|slurp|preview|monitor|curl|python|headless/i.test(ua)) return c.body(null, 204);
  const ip = (c.req.header('x-forwarded-for') || '').split(',')[0].trim(), day = new Date().toISOString().slice(0, 10), visitor = sha(ip + ua + day + env.JWT_SECRET).slice(0, 16); // daily-rotating hash: no cookies, no stored IPs
  let ref = ''; try { ref = b.ref ? new URL(b.ref).hostname.replace(/^www\./, '') : ''; } catch {} if (ref && env.APP_URL && ref === new URL(env.APP_URL).hostname.replace(/^www\./, '')) ref = '';
  const dev = /ipad|tablet/i.test(ua) ? 'tablet' : /mobi|android|iphone/i.test(ua) ? 'mobile' : 'desktop', t = (v: any) => (v ? String(v).slice(0, 80) : null);
  await q('insert into visits(path,ref,utm_source,utm_medium,utm_campaign,visitor,device,country,landing) values($1,$2,$3,$4,$5,$6,$7,$8,$9)', [t(b.path), ref || null, t(b.source), t(b.medium), t(b.campaign), visitor, dev, t(c.req.header('cf-ipcountry')), !!b.landing]); return c.body(null, 204); });
app.get('/health', c => c.text('ok'));
const OGIMG = Bun.file(new URL('../public/og.png', import.meta.url)); app.get('/og.png', async c => c.body(await OGIMG.arrayBuffer(), 200, { 'content-type': 'image/png', 'cache-control': 'public,max-age=86400' }));
app.get('/logo.svg', c => c.body(LOGO, 200, { 'content-type': 'image/svg+xml', 'cache-control': 'public,max-age=86400' }));
app.get('/logo-full.svg', c => c.body(LOGOFULL, 200, { 'content-type': 'image/svg+xml', 'cache-control': 'public,max-age=86400' }));

// ---------- accounts
const FIELDS = ['first_name', 'last_name', 'address', 'city', 'state', 'zip', 'phone'];
const checkProfile = (b: any) => { for (const f of FIELDS) if (!String(b[f] || '').trim()) return 'missing_' + f;
  if (!/^[A-Za-z]{2}$/.test(b.state)) return 'bad_state'; if (!/^\d{5}(-\d{4})?$/.test(b.zip)) return 'bad_zip'; if (String(b.phone).replace(/\D/g, '').length < 10) return 'bad_phone'; return null; };
app.post('/api/signup', async c => { if (limited(c, 'signup', 8)) return c.json({ error: 'rate_limited' }, 429); const b = await c.req.json();
  const e = checkProfile(b) || (!/^\S+@\S+\.\S+$/.test(b.email || '') ? 'bad_email' : (b.password || '').length < 10 ? 'weak_password' : null); if (e) return c.json({ error: e }, 400);
  try { const [u] = await q('insert into users(email,pw,first_name,last_name,address,city,state,zip,phone) values($1,$2,$3,$4,$5,$6,$7,$8,$9) returning *', [b.email.trim().toLowerCase(), bcrypt.hashSync(b.password, 12), ...FIELDS.map(f => String(b[f]).trim().slice(0, 120)).map((v, i) => i === 4 ? v.toUpperCase() : v)]);
    await sendVerify(u); return c.json({ token: sign(u) }); } catch { return c.json({ error: 'email_taken' }, 409); } });
app.post('/api/login', async c => { if (limited(c, 'login', 12)) return c.json({ error: 'rate_limited' }, 429); const b = await c.req.json();
  const [u] = await q('select * from users where email=$1', [String(b.email || '').toLowerCase()]);
  return u && bcrypt.compareSync(b.password || '', u.pw) ? c.json({ token: sign(u) }) : c.json({ error: 'bad_credentials' }, 401); });
app.get('/api/verify', async c => { const t = c.req.query('token') || ''; const r = await q('update users set email_verified_at=now(),verify_token=null where verify_token=$1 returning id', [sha(t)]); return c.redirect('/?verified=' + (r.length ? '1' : '0')); });
app.post('/api/forgot', async c => { if (limited(c, 'forgot', 6)) return c.json({ error: 'rate_limited' }, 429); const { email } = await c.req.json(); const [u] = await q('select * from users where email=$1', [String(email || '').toLowerCase()]); if (u) await sendReset(u); return c.json({ ok: true }); });
app.post('/api/reset', async c => { if (limited(c, 'reset', 10)) return c.json({ error: 'rate_limited' }, 429); const { token, password } = await c.req.json(); if ((password || '').length < 10) return c.json({ error: 'weak_password' }, 400);
  const r = await q('update users set pw=$1,reset_token=null,reset_expires=null,email_verified_at=coalesce(email_verified_at,now()) where reset_token=$2 and reset_expires>now() returning id', [bcrypt.hashSync(password, 12), sha(token || '')]); return r.length ? c.json({ ok: true }) : c.json({ error: 'bad_token' }, 400); });
app.post('/api/resend-verify', auth, async c => { if (limited(c, 'rv', 5)) return c.json({ error: 'rate_limited' }, 429); await sendVerify(c.get('user')); return c.json({ ok: true }); });
app.get('/api/me', auth, c => c.json(view(c.get('user'))));
app.patch('/api/me', auth, async c => { const u = c.get('user'), b = await c.req.json(), e = checkProfile(b); if (e) return c.json({ error: e }, 400);
  await q('update users set first_name=$1,last_name=$2,address=$3,city=$4,state=$5,zip=$6,phone=$7 where id=$8', [...FIELDS.map(f => String(b[f]).trim().slice(0, 120)), u.id]);
  if (u.stripe_customer) { const st = await getStripe(); try { await st?.customers.update(u.stripe_customer, { name: `${b.first_name} ${b.last_name}`, phone: b.phone, address: { line1: b.address, city: b.city, state: b.state, postal_code: b.zip, country: 'US' } }); } catch {} }
  return c.json({ ok: true }); });
app.post('/api/password', auth, async c => { const u = c.get('user'), b = await c.req.json(); if (!bcrypt.compareSync(b.current || '', u.pw)) return c.json({ error: 'bad_credentials' }, 401); if ((b.password || '').length < 10) return c.json({ error: 'weak_password' }, 400);
  await q('update users set pw=$1 where id=$2', [bcrypt.hashSync(b.password, 12), u.id]); return c.json({ ok: true }); });
app.put('/api/prefs', auth, async c => { const b = await c.req.json(); const extra = [...new Set((b.extra_emails || []).map((x: string) => String(x).trim().toLowerCase()).filter((x: string) => /^\S+@\S+\.\S+$/.test(x)))].slice(0, 5);
  const old = c.get('user').prefs || {}, num = (v: any, lo: number, hi: number) => (v === '' || v == null || !Number.isFinite(+v) ? null : Math.max(lo, Math.min(hi, +v)));
  const min_age = [2.5, 3.5, 4.5, 5.5, 6.5].includes(+b.min_age) ? +b.min_age : (old.min_age ?? 4.5);
  const profiles = Array.isArray(b.profiles) ? b.profiles.slice(0, 8).map((x: any) => ({ id: String(x.id || crypto.randomUUID()).slice(0, 40), name: String(x.name || 'My rules').slice(0, 60), kind: ['public', 'club', 'private'].includes(x.kind) ? x.kind : 'private',
    min_age: [2.5, 3.5, 4.5, 5.5, 6.5].includes(+x.min_age) ? +x.min_age : null, min_points: num(x.min_points, 0, 30), min_spread: num(x.min_spread, 0, 40), min_net: num(x.min_net, 0, 300), season_limit: num(x.season_limit, 0, 20), does_first: num(x.does_first, 0, 20),
    antler_rule: String(x.antler_rule || '').slice(0, 200), notes: String(x.notes || '').slice(0, 500) })) : (old.profiles || []);
  const active_profile = profiles.some((x: any) => x.id === b.active_profile) ? b.active_profile : (b.active_profile === '' ? null : (profiles.some((x: any) => x.id === old.active_profile) ? old.active_profile : null));
  await q('update users set prefs=$1 where id=$2', [{ results_email: !!b.results_email, billing: b.billing !== false, extra_emails: extra, min_age, profiles, active_profile }, c.get('user').id]); return c.json({ ok: true, extra_emails: extra, profiles, active_profile }); });

// ---------- bucks (private to owner; admin reads via /api/admin)
const BUCK = ['name', 'hunted_on', 'location', 'stand', 'wind_dir', 'temp_f', 'rut_phase', 'tactics', 'notes', 'bc', 'points', 'property_kind', 'property_name', 'status', 'kill_zip', 'known_score'];
const buckVals = (b: any) => [String(b.name || '').trim().slice(0, 80), b.hunted_on || null, b.location || null, b.stand || null, b.wind_dir || null, b.temp_f === '' || b.temp_f == null ? null : Math.round(+b.temp_f), b.rut_phase || null, JSON.stringify((b.tactics || []).slice(0, 20).map((x: any) => String(x).slice(0, 40))), String(b.notes || '').slice(0, 4000), b.bc ? JSON.stringify(b.bc) : null, b.points === '' || b.points == null ? null : Math.max(0, Math.min(40, Math.round(+b.points) || 0)), ['public', 'club', 'private'].includes(b.property_kind) ? b.property_kind : null, String(b.property_name || '').slice(0, 80) || null, ['watching', 'passed', 'harvested'].includes(b.status) ? b.status : 'watching', String(b.kill_zip || '').replace(/\D/g, '').slice(0, 5) || null, b.known_score === '' || b.known_score == null || !(+b.known_score > 0) ? null : Math.min(300, Math.round(+b.known_score * 8) / 8)];
app.get('/api/bucks', auth, gate, async c => c.json(await q("select b.*,(select count(*)::int from scans s where s.buck_id=b.id) scans,(select class from scans s where s.buck_id=b.id and s.mode='jaw' order by created_at desc limit 1) age_class,(select count(*)::int from buck_photos p where p.buck_id=b.id)+(select count(*)::int from photos p join scans s on s.id=p.scan_id where s.buck_id=b.id) photo_count from bucks b where user_id=$1 order by coalesce(hunted_on,created_at::date) desc,created_at desc", [c.get('user').id])));
app.post('/api/bucks', auth, async c => { const v = buckVals(await c.req.json()); if (!v[0]) return c.json({ error: 'name_required' }, 400);
  const [b] = await q(`insert into bucks(user_id,${BUCK.join(',')}) values(${['$1', ...BUCK.map((_, i) => '$' + (i + 2))].join(',')}) returning *`, [c.get('user').id, ...v]); return c.json(b); });
// Age case: every scan on a named deer is pooled into one running estimate from the PHOTOS only. Rescans and retakes replace the scans they came from.
// The hunter's own estimate is shown beside it but never changes it, and is never passed to the AI.
async function buckCase(buckId: string) {
  const rows = await q("select id,mode,confidence,created_at,observations,observations->'dist' dist,retake_of,reuse_of,user_age,approval,rollup from scans where buck_id=$1 and mode in ('jaw','deer') order by created_at", [buckId]);
  const sup = new Set(rows.flatMap((r: any) => [r.retake_of, r.reuse_of]).filter(Boolean)), srcs: any[] = [], roll = Math.max(0, ...rows.filter((r: any) => r.rollup && r.mode === 'jaw').map((r: any) => +new Date(r.created_at)));
  for (const r of rows as any[]) if (r.mode === 'jaw' && !r.rollup && +new Date(r.created_at) < roll) sup.add(r.id); // a roll-up replaces every earlier jaw scan
  const hunter = [...rows].reverse().map((r: any) => r.user_age).find(Boolean) || null;
  for (const r of rows as any[]) { if (!r.dist?.probs) continue; const w = Math.max(0.1, (r.confidence || 50) / 100) * (r.mode === 'jaw' ? 1 : 0.35); srcs.push({ id: r.id, mode: r.mode, created_at: r.created_at, best: r.dist.best, conf: r.confidence, weight: Math.round(w * 100) / 100, superseded: sup.has(r.id), approval: r.approval, probs: r.dist.probs, obs: r.observations }); }
  const used = srcs.filter(x => !x.superseded);
  if (!used.length) return hunter ? { dist: null, hunter, n_used: 0, n_total: 0, sources: [], why: [] } : null;
  const tw = used.reduce((t, x) => t + x.weight, 0), k = tw > 2 ? 2 / tw : 1, lg: any = {}; let mx = -1e9;
  for (const a of AGES) { lg[a] = used.reduce((t, x) => t + x.weight * k * Math.log(Math.max((+x.probs[a] || 0) / 100, 0.005)), 0); mx = Math.max(mx, lg[a]); }
  const ex: any = {}; let tot = 0; for (const a of AGES) { ex[a] = Math.exp(lg[a] - mx); tot += ex[a]; }
  const pr: any = {}; for (const a of AGES) pr[a] = Math.round((ex[a] / tot) * 1000) / 10;
  const best = AGES.reduce((x, y) => (pr[y] > pr[x] ? y : x)); let cum = 0, lo = AGES[0], hi = AGES[AGES.length - 1], got = false;
  for (const a of AGES) { cum += pr[a]; if (!got && cum >= 10) { lo = a; got = true; } if (cum >= 90) { hi = a; break; } }
  const dist = { probs: pr, best, lo, hi, method: 'case' };
  // Why we scored it this way: plain-language reasons from what the photos showed
  const why: string[] = [], WEAR = ['unworn, just erupted', 'light', 'moderate (dentine about as wide as enamel)', 'heavy'];
  why.push(`${used.length === 1 ? 'One scan' : used.length + ' scans'} point to ${best} years (${pr[best]}%), most likely between ${lo} and ${hi}. ${used.length > 1 ? 'Independent scans agreeing makes this firmer.' : 'More angles or a rescan would firm it up.'}`);
  for (const x of [...used].reverse().slice(0, 3)) { const o = x.obs || {}, d = fdate(x.created_at);
    if (x.mode === 'jaw' && o.molar_wear != null) why.push(`${d}: molar wear graded ${o.molar_wear} (${WEAR[+o.molar_wear] || '?'}).${o.premolar3_temporary === true ? ' The 3rd premolar is still a baby tooth, which means a fawn.' : ''}`);
    const r = String(o.reasoning || '').split(/(?<=[.!?])\s+/).slice(0, 2).join(' '); if (r) why.push(`${d}: ${r}`);
    for (const f of (o.features || []).slice(0, 3)) if (f?.feature && f.observation) why.push(`${f.feature}: ${f.observation}${f.points_to ? ' → ' + f.points_to : ''}`); }
  if (+String(best).replace('+', '') >= 3.5) why.push('Tooth wear gets less reliable past 3.5 years, even for experts, so older deer are often aged too young from teeth alone. A lab cementum test is the gold standard.');
  const lastObs = [...used].reverse().map(x => x.obs?.would_change_answer).find((w: any) => Array.isArray(w) && w.length); if (lastObs) why.push('What would sharpen this: ' + lastObs.slice(0, 2).join('; '));
  if (hunter && hunter !== best) why.push(`You estimate ${hunter} years. The photos point to ${best}. Your estimate is shown but does not change this result. To settle it, add a clear close-up of the first molar and a straight-down shot of the chewing surface.`);
  return { dist, hunter, n_used: used.length, n_total: srcs.length, sources: srcs.map(({ probs, obs, ...x }) => x), why };
}
const fdate = (d: any) => new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
app.get('/api/bucks/:id', auth, gate, async c => { const [b] = await q('select * from bucks where id=$1 and user_id=$2', [c.req.param('id'), c.get('user').id]); if (!b) return c.json({ error: 'not_found' }, 404);
  const sl = await q('select id,mode,class,range,confidence,flags,created_at,observations->\'dist\' dist,(select s3_key from photos where scan_id=scans.id order by slot limit 1) thumb from scans where buck_id=$1 order by created_at desc', [b.id]);
  const ph = await q('select id,s3_key,kind,caption,view,side from buck_photos where buck_id=$1 order by created_at', [b.id]);
  const loose = await q("select id,mode,class,created_at from scans where user_id=$1 and (buck_id is null or buck_id<>$2) order by created_at desc limit 50", [c.get('user').id, b.id]);
  return c.json({ ...b, age_case: await buckCase(b.id), scan_list: sl.map(({ thumb, ...x }: any) => ({ ...x, thumb: thumb ? s3.file(thumb).presign({ expiresIn: 3600 }) : null })), jaw_check: ph.some((p: any) => p.kind === 'jawbone' && p.view) ? jawCoverage(ph) : null, photo_list: ph.map((p: any) => ({ id: p.id, kind: p.kind, view: p.view, side: p.side, caption: p.caption, url: s3.file(p.s3_key).presign({ expiresIn: 3600 }) })), loose_scans: loose }); });
const PHOTO_KINDS = ['jawbone', 'field', 'rack', 'mount', 'other'], VIEWS = ['side', 'top', 'tilt', 'close_molars', 'close_premolars', 'front', 'unknown'], SIDES = ['left', 'right', 'both', 'unknown'];
// Looks at one photo and says what it is (and, for a jaw, which view and which half), so hunters never have to pick a photo type. Returns null if no model could tell.
async function identifyPhoto(b64: string, mime: string): Promise<{ kind: string; view: string; side: string } | null> {
  try { const all = configured(); if (!all.length) return null;
    for (const p of live(all)) { const r: any = await runOnce(p, [{ mime, b64 }], 'kind', 0), x = r.result; if (x && PHOTO_KINDS.includes(x.kind)) return { kind: x.kind, view: x.kind === 'jawbone' && VIEWS.includes(x.view) ? x.view : 'unknown', side: x.kind === 'jawbone' && SIDES.includes(x.side) ? x.side : 'unknown' }; } } catch (e: any) { console.error('identifyPhoto', e?.message); }
  return null; }
// What the standard jaw set needs: both cheek sides and a top-down view are required; a molar close-up is strongly recommended.
const JAW_NEEDS: any = {
  left: { label: 'Left side of the jaw', required: true, how: 'Lay the jaw on its side, cheek side up, and shoot the whole tooth row from slightly above, with a ruler or coin beside it.' },
  right: { label: 'Right side of the jaw', required: true, how: 'The same view of the other half of the jaw (flip the jaw over).' },
  top: { label: 'Top-down chewing surface', required: true, how: 'Look straight down on the chewing surface of the whole tooth row, phone parallel to the bone.' },
  close: { label: 'Close-up of the first and second molars', required: false, how: 'Move in close on the two back flat teeth so the dentine and enamel lines are sharp, lit from one side.' } };
function jawCoverage(list: any[]) {
  const jaw = list.filter(x => x && x.kind === 'jawbone'), seen = new Set<string>();
  for (const x of jaw) { if (x.view === 'top') { seen.add('top'); continue; }
    if (['side', 'tilt', 'close_molars', 'close_premolars'].includes(x.view)) { if (x.side === 'left' || x.side === 'both') seen.add('left'); if (x.side === 'right' || x.side === 'both') seen.add('right'); }
    if (x.view === 'close_molars') seen.add('close'); }
  return { jaw_photos: jaw.length, missing: Object.keys(JAW_NEEDS).filter(k => !seen.has(k)).map(k => ({ key: k, ...JAW_NEEDS[k] })) };
}
app.post('/api/photos/identify', auth, async c => { const f: any = await c.req.parseBody({ all: true }), files = [].concat(f.photos || []) as any[]; if (!files.length || files.length > 12) return c.json({ error: 'invalid_input' }, 400);
  const photos = await Promise.all(files.map(async (file: any) => { if (!file.type?.startsWith('image/') || file.size > 4.9e6) return null; return identifyPhoto(Buffer.from(await file.arrayBuffer()).toString('base64'), file.type); }));
  const sure = photos.every(Boolean); return c.json({ photos, ...(sure ? jawCoverage(photos as any[]) : { jaw_photos: 0, missing: [] }), unsure: !sure }); });
app.post('/api/bucks/:id/photos', auth, gate, async c => { const u = c.get('user'); const [b] = await q('select id from bucks where id=$1 and user_id=$2', [c.req.param('id'), u.id]); if (!b) return c.json({ error: 'not_found' }, 404);
  const f: any = await c.req.parseBody({ all: true }), files = [].concat(f.photo || f.photos || []) as any[]; if (!files.length || files.length > 10) return c.json({ error: 'invalid_input' }, 400);
  const given = PHOTO_KINDS.includes(f.kind) ? f.kind : f.kind === 'auto' ? 'auto' : 'other', out: any[] = [], kinds: string[] = [];
  for (const file of files) { if (!file.type?.startsWith('image/')) return c.json({ error: 'bad_image' }, 400); if (file.size > 8e6) return c.json({ error: 'photo_too_large' }, 413);
    const buf = Buffer.from(await file.arrayBuffer()), key = `${u.id}/${sha(buf.toString('latin1')).slice(0, 24)}.jpg`;
    try { if (!(await s3.file(key).exists())) await s3.write(key, buf, { type: file.type }); } catch (e: any) { console.error('s3 write failed', e.message); return c.json({ error: 'storage_failed' }, 502); }
    const idf = given === 'auto' ? await identifyPhoto(buf.toString('base64'), file.type) : null, kind = given === 'auto' ? idf?.kind || 'other' : given; kinds.push(kind);
    out.push((await q('insert into buck_photos(buck_id,s3_key,kind,caption,bytes,view,side) values($1,$2,$3,$4,$5,$6,$7) returning id', [b.id, key, kind, String(f.caption || '').slice(0, 200) || null, buf.length, idf?.view || null, idf?.side || null]))[0].id); }
  return c.json({ ok: true, ids: out, kinds }); });
app.delete('/api/bucks/:id/photos/:pid', auth, gate, async c => { const [p] = await q('select p.id,p.s3_key from buck_photos p join bucks b on b.id=p.buck_id where p.id=$1 and b.id=$2 and b.user_id=$3', [c.req.param('pid'), c.req.param('id'), c.get('user').id]); if (!p) return c.json({ ok: true });
  await q('delete from buck_photos where id=$1', [p.id]); if (!(await q('select 1 from photos where s3_key=$1 union all select 1 from buck_photos where s3_key=$1 limit 1', [p.s3_key])).length) await s3.file(p.s3_key).delete().catch(() => {}); return c.json({ ok: true }); });
app.put('/api/bucks/:id', auth, gate, async c => { const v = buckVals(await c.req.json()); if (!v[0]) return c.json({ error: 'name_required' }, 400);
  const r = await q(`update bucks set ${BUCK.map((k, i) => `${k}=$${i + 3}`).join(',')} where id=$1 and user_id=$2 returning id`, [c.req.param('id'), c.get('user').id, ...v]); if (r.length) recalcAll(c.req.param('id')).catch(e => console.error('recalc', e.message)); return r.length ? c.json({ ok: true }) : c.json({ error: 'not_found' }, 404); });
app.delete('/api/bucks/:id', auth, gate, async c => { await q('delete from bucks where id=$1 and user_id=$2', [c.req.param('id'), c.get('user').id]); return c.json({ ok: true }); });

// ---------- buck data sheet (view / print / email / text link)
async function buckSheet(b: any, ttl = 3600, mk?: (k: string) => string) {
  const sl = await q("select mode,class,range,confidence,created_at,observations->'dist' dist from scans where buck_id=$1 order by created_at desc", [b.id]);
  const ph = await q('select s3_key,kind from buck_photos where buck_id=$1 order by created_at', [b.id]);
  const sp = await q('select p.s3_key from photos p join scans s on s.id=p.scan_id where s.buck_id=$1 order by s.created_at desc,p.slot limit 4', [b.id]);
  const url = mk || ((k: string) => s3.file(k).presign({ expiresIn: ttl })), pri = ['rack', 'field', 'mount', 'jawbone', 'other'];
  const hero = [...ph].sort((x: any, y: any) => pri.indexOf(x.kind) - pri.indexOf(y.kind))[0]?.s3_key || sp[0]?.s3_key || null;
  const jaw = sl.find((x: any) => x.mode === 'jaw' && x.class) || sl.find((x: any) => x.class);
  return { name: b.name, points: b.points, hunted_on: b.hunted_on, location: b.location, stand: b.stand, wind_dir: b.wind_dir, temp_f: b.temp_f, rut_phase: b.rut_phase, tactics: b.tactics || [], notes: b.notes, bc: b.bc,
    age: jaw ? { cls: jaw.class, range: jaw.range, confidence: jaw.confidence, best: jaw.dist?.best || null } : null,
    scans: sl.filter((x: any) => x.class).map((x: any) => ({ mode: x.mode, cls: x.class, range: x.range, confidence: x.confidence, created_at: x.created_at })),
    hero: hero ? url(hero) : null, photos: [...ph.map((p: any) => ({ kind: p.kind, url: url(p.s3_key) })), ...sp.map((p: any) => ({ kind: 'scan', url: url(p.s3_key) }))].filter((p: any) => p.url !== (hero ? url(hero) : null)).slice(0, 8) };
}
const ownBuck = async (c: any) => (await q('select * from bucks where id=$1 and user_id=$2', [c.req.param('id'), c.get('user').id]))[0];
app.get('/api/bucks/:id/sheet', auth, gate, async c => { const b = await ownBuck(c); return b ? c.json(await buckSheet(b)) : c.json({ error: 'not_found' }, 404); });
app.post('/api/bucks/:id/share', auth, gate, async c => { const b = await ownBuck(c); if (!b) return c.json({ error: 'not_found' }, 404); let t = b.share_token; if (!t) { t = crypto.randomBytes(16).toString('hex'); await q('update bucks set share_token=$1 where id=$2', [t, b.id]); } return c.json({ url: `${env.APP_URL}/b/${t}` }); });
const photoResp = async (k: string) => { try { const f = s3.file(k); return new Response(await f.arrayBuffer(), { headers: { 'content-type': f.type || 'image/jpeg', 'cache-control': 'private, max-age=3600', 'x-robots-tag': 'noindex' } }); } catch { return new Response('not found', { status: 404 }); } };
app.get('/api/bshare/:t', async c => { const [b] = await q('select * from bucks where share_token=$1', [c.req.param('t')]); return b ? c.json(await buckSheet(b, 3600, (k: string) => `/api/bshare/${b.share_token}/p?k=${encodeURIComponent(k)}`)) : c.json({ error: 'not_found' }, 404); });
app.get('/api/bshare/:t/p', async c => { const [b] = await q('select id from bucks where share_token=$1', [c.req.param('t')]), k = c.req.query('k') || ''; if (!b || !(await q('select 1 from buck_photos where buck_id=$1 and s3_key=$2 union all select 1 from photos p join scans s on s.id=p.scan_id where s.buck_id=$1 and p.s3_key=$2 limit 1', [b.id, k])).length) return c.json({ error: 'not_found' }, 404); return photoResp(k); });
app.post('/api/bucks/:id/email', auth, gate, async c => { if (limited(c, 'em', 20)) return c.json({ error: 'rate_limited' }, 429); const b = await ownBuck(c); if (!b) return c.json({ error: 'not_found' }, 404); const u = c.get('user');
  const bj: any = await c.req.json().catch(() => ({})), to = [...new Set((bj.to || []).map((x: string) => String(x).trim().toLowerCase()).filter((x: string) => /^\S+@\S+\.\S+$/.test(x)))].slice(0, 5) as string[]; if (!to.length) return c.json({ error: 'invalid_input' }, 400);
  let t = b.share_token; if (!t) { t = crypto.randomBytes(16).toString('hex'); await q('update bucks set share_token=$1 where id=$2', [t, b.id]); }
  const ns = { n: 0 } as { n: number; err?: string }, sh: any = await buckSheet(b, 604800), link = `${env.APP_URL}/b/${t}`, row = (k: string, v: any) => (v == null || v === '' ? '' : `<tr><td style="color:#777;padding:3px 12px 3px 0">${k}</td><td><b>${eh(v)}</b></td></tr>`);
  const body = `<table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td valign="top"><h2 style="margin:0">${eh(sh.name)}</h2>${sh.points ? `<div style="font-size:20px;color:#2f6b3f"><b>${sh.points}-point</b></div>` : ''}${sh.age ? `<div style="margin-top:6px">Age: <b>${eh(sh.age.cls)}</b> <span style="color:#777">${eh(sh.age.range || '')}</span></div>` : ''}${sh.bc ? `<div>B&amp;C: <b>${(+sh.bc.net).toFixed(1)}"</b> net (estimate)</div>` : ''}</td>${sh.hero ? `<td width="42%" valign="top" align="right"><img src="${sh.hero}" width="200" style="width:100%;max-width:200px;border-radius:10px;display:block" alt=""></td>` : ''}</tr></table>
<table cellpadding="0" cellspacing="0" border="0" style="margin-top:12px">${row('Date', sh.hunted_on ? String(sh.hunted_on).slice(0, 10) : '')}${row('Location', sh.location)}${row('Stand', sh.stand)}${row('Wind', sh.wind_dir)}${row('Temp', sh.temp_f != null ? sh.temp_f + ' F' : '')}${row('Rut phase', sh.rut_phase)}${row('Tactics', (sh.tactics || []).join(', '))}</table>${sh.notes ? `<p>${eh(sh.notes)}</p>` : ''}${btn(link, 'View and print the full data sheet')}`;
  if (bj.sheet === 'bc' && sh.bc) { const bl = `${link}?sheet=bc`, net = (+sh.bc.net).toFixed(1), gr = (+sh.bc.gross).toFixed(1);
    for (const a of to) await mailTo(ns, a, `${sh.name}: Boone & Crockett score sheet (estimate)`, `<p>${eh(u.first_name)} shared a Boone &amp; Crockett score sheet for <b>${eh(sh.name)}</b>${sh.points ? ` (${sh.points}-point)` : ''}.</p><p style="font-size:26px;margin:6px 0"><b>${net}"</b> <span style="font-size:14px;color:#666">net (estimate), gross ${gr}"</span></p>${btn(bl, 'View and print the score sheet')}<p style="font-size:12px;color:#666">An estimate from the hunter's own tape measurements. It is not an official score. Official scoring needs a 60-day drying period and a certified measurer.</p>`, 'buck'); return emailRes(c, ns, to.length); }
  for (const a of to) await mailTo(ns, a, `${sh.name}${sh.points ? ` (${sh.points}-pt)` : ''}: Deer Ager data sheet`, `<p>${eh(u.first_name)} shared a buck data sheet.</p>` + body, 'buck'); return emailRes(c, ns, to.length); });

// share a buck sheet with another member of the site
app.post('/api/bucks/:id/share-member', auth, gate, async c => { if (limited(c, 'sm', 30)) return c.json({ error: 'rate_limited' }, 429); const b = await ownBuck(c); if (!b) return c.json({ error: 'not_found' }, 404); const me = c.get('user');
  const em = String((await c.req.json().catch(() => ({}))).email || '').trim().toLowerCase(), [t] = await q("select id,first_name,email,prefs from users where email=$1 and status='active'", [em]);
  if (!t || t.id === me.id) return c.json({ error: 'member_not_found' }, 404);
  await q('insert into buck_shares(buck_id,to_user) values($1,$2) on conflict do nothing', [b.id, t.id]);
  if (t.prefs?.billing !== false) mail(t.email, `${me.first_name} shared ${b.name} with you`, `<p>Hi ${eh(t.first_name)}, ${eh(me.first_name)} ${eh(me.last_name || '')} shared the buck <b>${eh(b.name)}</b>${b.points ? ` (${b.points}-point)` : ''} with you on Deer Ager.</p>${btn(env.APP_URL + '/', 'Open Deer Ager')}<p style="font-size:12px;color:#666">Find it under Bucks > Shared with me.</p>`, 'buck_share').catch(() => {});
  return c.json({ ok: true, name: t.first_name }); });
app.get('/api/bucks/:id/shares', auth, gate, async c => { const b = await ownBuck(c); if (!b) return c.json({ error: 'not_found' }, 404); return c.json(await q("select u.id,u.first_name,u.last_name from buck_shares s join users u on u.id=s.to_user where s.buck_id=$1 order by s.created_at", [b.id])); });
app.delete('/api/bucks/:id/shares/:uid', auth, gate, async c => { const b = await ownBuck(c); if (b) await q('delete from buck_shares where buck_id=$1 and to_user=$2', [b.id, c.req.param('uid')]); return c.json({ ok: true }); });
app.get('/api/shared', auth, async c => c.json(await q("select b.id,b.name,b.points,b.hunted_on,s.created_at,u.first_name,u.last_name from buck_shares s join bucks b on b.id=s.buck_id join users u on u.id=b.user_id where s.to_user=$1 order by s.created_at desc", [c.get('user').id])));
app.get('/api/shared/:id', auth, async c => { const [b] = await q('select b.* from bucks b join buck_shares s on s.buck_id=b.id where b.id=$1 and s.to_user=$2', [c.req.param('id'), c.get('user').id]); return b ? c.json(await buckSheet(b)) : c.json({ error: 'not_found' }, 404); });
app.delete('/api/shared/:id', auth, async c => { await q('delete from buck_shares where buck_id=$1 and to_user=$2', [c.req.param('id'), c.get('user').id]); return c.json({ ok: true }); });

// ---------- scans: photos -> S3, all configured models -> best result -> Postgres
async function report(s: any, admin = false) {
  const allRuns = await q('select provider,model,class,confidence,latency_ms,error,result from model_runs where scan_id=$1 and truth_class is null order by confidence desc nulls last', [s.id]), runs = admin ? allRuns : allRuns.filter((r: any) => !r.error); // end users never see a model that failed; admins do
  const ok = runs.filter((r: any) => r.class), best = ok[0] || null;
  return { id: s.id, pending: !!s.flags?.pending, failed: !!s.flags?.error, approval: s.approval || null, user_age: s.user_age || null, retake_of: s.retake_of || null, mode: s.mode, class: s.class, range: s.range, confidence: s.confidence, created_at: s.created_at, flags: s.flags, observations: s.observations,
    best: best && { provider: best.provider, model: best.model, confidence: best.confidence, observations: best.result }, agree: best ? ok.filter((r: any) => r.class === best.class).length : 0, total: runs.length,
    runs: runs.map((r: any) => ({ provider: r.provider, model: r.model, class: r.class, confidence: r.confidence, ms: r.latency_ms, error: r.error, evidence: r.result?.evidence || [] })), disclaimer: 'Estimate only. Tooth-wear aging is subjective; a lab cementum test is the gold standard.' };
}
// A scan that failed because every model was unavailable is retried by itself (90 seconds, then 6 minutes later), so the hunter just finds the result waiting.
async function autoRetry(id: string, n: number) {
  const [s] = await q('select * from scans where id=$1', [id]); if (!s || !s.flags?.error || s.class) return;
  const [u] = await q('select * from users where id=$1', [s.user_id]), ph = await q('select s3_key from photos where scan_id=$1 order by slot', [id]); if (!u || !ph.length) return;
  const imgs = await Promise.all(ph.map(async (p: any) => ({ mime: 'image/jpeg', b64: Buffer.from(await s3.file(p.s3_key).arrayBuffer()).toString('base64') })));
  s.flags = { ...s.flags, auto_retries: n }; const r: any = await runAnalysis(s, u, imgs); if (!r.error && r.scan?.class && u.prefs?.results_email) emailScan(r.scan, [u.email, ...(u.prefs.extra_emails || [])], u).catch(() => {});
}
// Re-scores stored jaw results with the current regional curve, without calling any AI, so every saved report matches the settings.
function rescoreJaw(o: any, rg: any, antler: number | null = null) {
  const k: any = classify(o); if (!k.cls) return null; o.rule = k.rule || null; o.conf_detail = confDetail(o, 'jaw'); delete o.region; delete o.rut;
  const d = ageDist(o, 'jaw', k.cls, conf(o, 'jaw'), rg?.shift || 0, antler); if (!d) return { k, o };
  if (rg && d.shift) { o.region = { id: rg.id, name: rg.name, shift: rg.shift }; if (rg.rut) o.rut = rg.rut; } o.dist = d;
  if (k.cls === 'Middle' || k.cls === 'Old' || d.shift || d.antler) k.range = `Most likely ${d.best} years (likely ${d.lo} to ${d.hi})`; return { k, o };
}
let RECALC: Promise<any> | null = null;
function recalcAll(buckId?: string) { if (buckId) return doRecalc(buckId); if (!RECALC) RECALC = doRecalc().finally(() => { RECALC = null; }); return RECALC; }
async function doRecalc(buckId?: string) { return await (async () => { let scans = 0, runs = 0; const cache = new Map<string, any>();
    const rows = await q("select s.id,s.observations,u.zip,b.kill_zip,b.rut_phase,b.known_score,b.bc from scans s join users u on u.id=s.user_id left join bucks b on b.id=s.buck_id where s.mode='jaw' and s.observations is not null and s.class is not null" + (buckId ? ' and s.buck_id=$1' : ''), buckId ? [buckId] : []);
    for (const r of rows as any[]) { const z = [r.kill_zip || r.zip || '', r.rut_phase || ''].join('|'); if (!cache.has(z)) cache.set(z, await curveFor({ zip: r.zip }, { kill_zip: r.kill_zip, rut_phase: r.rut_phase })); const rg = cache.get(z);
      const ant = antlerFor(r), x = rescoreJaw(r.observations, rg, ant); if (!x) continue; await q('update scans set observations=$1,range=$2 where id=$3', [x.o, x.k.range, r.id]); scans++;
      for (const m of await q('select id,result from model_runs where scan_id=$1 and truth_class is null and result is not null', [r.id]) as any[]) { if (rescoreJaw(m.result, rg, ant)) { await q('update model_runs set result=$1 where id=$2', [m.result, m.id]); runs++; } } }
    return { scans, runs }; })(); }
async function runAnalysis(s: any, u: any, imgs: any[]) {
  const mode = s.mode, all = configured(); if (!all.length) return { error: 'analysis_unavailable' };
  const bk: any = s.buck_id ? (await q('select kill_zip,rut_phase,known_score,bc from bucks where id=$1', [s.buck_id]))[0] : null, antler = antlerFor(bk), rg = mode === 'jaw' ? await curveFor(u, bk) : null, avail = live(all), pick = (await getSetting('compare_all')) === 'false' ? [avail.includes(env.PRIMARY_MODEL!) ? env.PRIMARY_MODEL! : avail[0]] : avail;
  const runs = await Promise.all(pick.map(p => runModel(p, imgs, mode)));
  for (const r of runs as any[]) { if (r.error && fatalErr(r.error)) BREAKER[r.provider] = { until: Date.now() + 15 * 60e3, reason: String(r.error).replace(/\s+/g, ' ').slice(0, 200), since: BREAKER[r.provider]?.since || new Date().toISOString() }; else if (r.result) delete BREAKER[r.provider]; }
  const scored = runs.map((r: any) => { const o = r.result, k: any = !o ? { cls: null, range: null } : mode === 'bc' ? { cls: o.usable !== false && o.net_low != null ? `Net ${o.net_low}-${o.net_high} in (est.)` : null, range: 'Estimate only. Not an official score.' } : classify(o); if (o) { o.rule = k.rule || null; o.conf_detail = confDetail(o, mode); const d = mode === 'bc' ? null : ageDist(o, mode, k.cls, conf(o, mode), rg?.shift || 0, antler); if (d && rg && d.shift) { o.region = { id: rg.id, name: rg.name, shift: rg.shift }; if (rg.rut) o.rut = rg.rut; }
      if (d) { o.dist = d; if (!k.cls && mode === 'deer') k.cls = d.best; if (mode === 'deer' || k.cls === 'Middle' || k.cls === 'Old' || d.shift || d.antler) k.range = `Most likely ${d.best} years (likely ${d.lo} to ${d.hi})`; } } return { ...r, ...k, conf: o ? conf(o, mode) : null }; });
  await q('delete from model_runs where scan_id=$1 and truth_class is null', [s.id]);
  const pr = await prices(); for (const r of scored as any[]) await q('insert into model_runs(scan_id,provider,model,result,class,confidence,latency_ms,error,in_tokens,out_tokens,cost_usd) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)', [s.id, r.provider, r.model, r.result || null, r.cls, r.conf, r.ms, r.error || null, r.inTok || null, r.outTok || null, runCost(pr, r.model, r.inTok || 0, r.outTok || 0)]);
  const good = scored.filter(r => r.cls).sort((a, b) => b.conf - a.conf), best = good[0] || scored.find(r => r.result);
  if (!best) { const tries = (s.flags?.auto_retries || 0); await q('update scans set flags=$1 where id=$2', [{ usable: false, error: true, retrying: tries < 2, auto_retries: tries, missing: [], issues: ['We could not finish this one yet. Your photos are saved and we will keep trying.'] }, s.id]);
    if (tries < 2 && !env.MOCK_MODELS) setTimeout(() => autoRetry(s.id, tries + 1).catch(() => {}), tries === 0 ? 90e3 : 6 * 60e3); return { error: 'analysis_failed' }; }
  const o = best.result, flags = { usable: !!best.cls, missing: o.missing || [], issues: o.issues || [] }, cf = best.conf;
  const [n] = await q('update scans set class=$1,range=$2,confidence=$3,observations=$4,flags=$5,model=$6 where id=$7 returning *', [best.cls, best.range, cf, o, flags, best.model, s.id]);
  if (flags.usable && !s.counted) { await q('update users set scans_used=scans_used+1 where id=$1', [u.id]); await q('update scans set counted=true where id=$1', [s.id]);
    if (u.prefs?.results_email) emailScan(n, [u.email, ...(u.prefs.extra_emails || [])], u).catch(() => {}); }
  return { scan: n, needs_more: !flags.usable || cf < 75 };
}
const fail = (c: any, r: any, id: string) => c.json({ error: r.error, scan_id: id }, r.error === 'analysis_unavailable' ? 503 : 502);
async function ingest(c: any, u: any, x: any = {}): Promise<any> {
  const f: any = await c.req.parseBody({ all: true }), mode = x.mode || f.mode, files = [].concat(f.photos || []);
  if (!canScan(u) && !(f.retake_of && ACTIVE.includes(u.sub_status))) return c.json({ error: 'subscription_required' }, 402); // a free retake is allowed even when trial scans are used up
  if (!['jaw', 'deer', 'bc'].includes(mode) || (!files.length && !f.reuse_scan) || files.length > 8) return c.json({ error: 'invalid_input' }, 400);
  let reuseOf: string | null = null;
  const dfiles = mode === 'jaw' ? ([] as any[]).concat(f.deer_photos || []) : []; // optional photos of the live deer, jaw scans only
  if (dfiles.length > 4 || files.length + dfiles.length > 12) return c.json({ error: 'invalid_input' }, 400);
  let buck: any = null; if (f.buck_id) { [buck] = await q('select id from bucks where id=$1 and user_id=$2', [f.buck_id, u.id]); if (!buck) return c.json({ error: 'not_found' }, 404); }
  const bname = String(f.buck_name || '').trim().slice(0, 80);
  if (!buck && bname) { [buck] = await q('select id from bucks where user_id=$1 and lower(name)=lower($2) limit 1', [u.id, bname]); if (!buck) [buck] = await q('insert into bucks(user_id,name) values($1,$2) returning id', [u.id, bname]); }
  if (dfiles.length && !buck) return c.json({ error: 'deer_name_required' }, 400); // deer photos need a named deer to tie to
  const imgs: any[] = [], stored: any[] = []; let storageDown = false; const dstored: any[] = [];
  for (const file of files as any[]) { if (!file.type?.startsWith('image/')) return c.json({ error: 'bad_image' }, 400); if (file.size > 4.9e6) return c.json({ error: 'photo_too_large' }, 413); // AI vision limit is about 5 MB per photo
    const buf = Buffer.from(await file.arrayBuffer()), h = sha(buf.toString('latin1')).slice(0, 24), key = `${u.id}/${h}.jpg`; // content-addressed: identical photos are stored once per user
    try { if (!(await s3.file(key).exists())) await s3.write(key, buf, { type: file.type }); stored.push({ key, bytes: buf.length, sha: h }); } catch (e: any) { console.error('s3 write failed', e.message); storageDown = true; } // keep going: the analysis still works from memory
    ; imgs.push({ mime: file.type, b64: buf.toString('base64') }); }
  if (f.reuse_scan && buck && mode === 'jaw') { // rescan: bring in the earlier jaw photos of this deer, newest first, up to 8 in all
    const [old] = await q('select id from scans where id=$1 and user_id=$2 and buck_id=$3 and mode=$4', [f.reuse_scan, u.id, buck.id, mode]); if (old) reuseOf = old.id;
    if (old) for (const p of await q('select s3_key,bytes,sha from photos where scan_id=$1 order by slot', [old.id])) { if (imgs.length >= 8) break; if (stored.some((x: any) => x.key === p.s3_key)) continue;
      try { imgs.push({ mime: 'image/jpeg', b64: Buffer.from(await s3.file(p.s3_key).arrayBuffer()).toString('base64') }); stored.push({ key: p.s3_key, bytes: p.bytes || 0, sha: p.sha || null }); } catch (e: any) { console.error('reuse read failed', e.message); } } }
  if (!imgs.length) return c.json({ error: 'invalid_input' }, 400);
  const reusedField = f.use_field === '1' && buck && mode === 'jaw' ? await q("select s3_key from buck_photos where buck_id=$1 and kind='field' order by created_at desc limit 4", [buck.id]) : [];
  for (const file of dfiles) { if (!file.type?.startsWith('image/')) return c.json({ error: 'bad_image' }, 400); if (file.size > 4.9e6) return c.json({ error: 'photo_too_large' }, 413);
    const buf = Buffer.from(await file.arrayBuffer()), key = `${u.id}/${sha(buf.toString('latin1')).slice(0, 24)}.jpg`;
    try { if (!(await s3.file(key).exists())) await s3.write(key, buf, { type: file.type }); dstored.push({ key, bytes: buf.length }); } catch (e: any) { console.error('s3 write failed', e.message); storageDown = true; }
    imgs.push({ mime: file.type, b64: buf.toString('base64') }); }
  let nField = 0; for (const p of reusedField as any[]) { if (nField + dfiles.length >= 4 || dstored.some((d: any) => d.key === p.s3_key)) continue; try { imgs.push({ mime: 'image/jpeg', b64: Buffer.from(await s3.file(p.s3_key).arrayBuffer()).toString('base64') }); nField++; } catch (e: any) { console.error('field read failed', e.message); } }
  const labels = ([] as any[]).concat(f.labels || []).map((x: any) => String(x).slice(0, 80)); if (labels.length === files.length && files.length && mode !== 'bc') (imgs as any).note = `\n\nThe first ${files.length} photo(s), in order, are: ${labels.map((l: string, i: number) => `${i + 1} = ${l}`).join('; ')}. Use the angled and close-up views to judge cusp height and the dentine-to-enamel ratio; a straight-on view can hide wear.` + ((imgs as any).note || '');
  if (dfiles.length + nField) (imgs as any).note = ((imgs as any).note || '') + `\n\nNOTE: the last ${dfiles.length + nField} photo(s) show the live animal (not the jaw). Use them only as weak supporting evidence for body condition and size; the jaw tooth wear takes precedence, and do not raise confidence because of them.\n\n`;
  let retake: any = null; if (f.retake_of) { [retake] = await q('select id from scans where id=$1 and user_id=$2 and mode=$3 and retake_of is null and not exists(select 1 from scans r where r.retake_of=scans.id)', [f.retake_of, u.id, mode]); } // one free retake per scan, so a bad photo never costs a trial scan
  if (!canScan(u) && !retake) return c.json({ error: 'subscription_required' }, 402);
  const [s] = await q('insert into scans(user_id,buck_id,mode,flags,partner_id,ext,retake_of,counted,reuse_of) values($1,$2,$3,$4,$5,$6,$7,$8,$9) returning *', [u.id, buck?.id || null, mode, { usable: false, pending: true }, x.partner_id || null, x.ext || null, retake?.id || null, !!retake, reuseOf]); // saved before analysis so photos are never orphaned
  for (const [i, p] of stored.entries()) await q('insert into photos(scan_id,s3_key,slot,bytes,sha) values($1,$2,$3,$4,$5)', [s.id, p.key, i, p.bytes, p.sha]);
  for (const d of dstored) if (!(await q('select 1 from buck_photos where buck_id=$1 and s3_key=$2', [buck.id, d.key])).length) await q("insert into buck_photos(buck_id,s3_key,kind,caption,bytes) values($1,$2,'field','From jaw scan',$3)", [buck.id, d.key, d.bytes]);
  const r: any = await runAnalysis(s, u, imgs); if (r.error) return fail(c, r, s.id);
  return { scan: r.scan, out: { ...(await report(r.scan)), buck_id: buck?.id || null, deer_photos: dstored.length, free_retake: !!retake, needs_more_photos: r.needs_more, storage_down: storageDown } };
}
// Pull every earlier jaw scan of a deer together: all their photos (newest first, up to 8) plus saved deer photos, re-run through the current analysis. Free, and replaces the earlier scans in the age case.
async function rollupBuck(u: any, buckId: string, background = false, opt: any = {}): Promise<any> {
  const smode = opt.mode === 'deer' ? 'deer' : 'jaw';
  const [buck] = await q('select id from bucks where id=$1 and user_id=$2', [buckId, u.id]); if (!buck) return { error: 'not_found' };
  const ph = opt.saved ? await q("select s3_key,bytes,null sha from buck_photos where buck_id=$1 order by created_at desc limit 8", [buck.id]) : await q("select p.s3_key,p.bytes,p.sha from photos p join scans s on s.id=p.scan_id where s.buck_id=$1 and s.mode='jaw' order by s.created_at desc,p.slot", [buck.id]); // 'saved' = he has photos in his log but no scan yet
  const seen = new Set<string>(), imgs: any[] = [], stored: any[] = [];
  for (const p of ph as any[]) { if (imgs.length >= 8 || seen.has(p.s3_key)) continue; seen.add(p.s3_key); try { imgs.push({ mime: 'image/jpeg', b64: Buffer.from(await s3.file(p.s3_key).arrayBuffer()).toString('base64') }); stored.push(p); } catch (e: any) { console.error('rollup read failed', e.message); } }
  if (imgs.length < 8) { const bp = await q("select s3_key,bytes from buck_photos where buck_id=$1 and kind<>'field' order by created_at desc limit 8", [buck.id]); // photos saved straight to the deer, with no scan yet
    for (const p of bp as any[]) { if (imgs.length >= 8 || seen.has(p.s3_key)) continue; seen.add(p.s3_key); try { imgs.push({ mime: 'image/jpeg', b64: Buffer.from(await s3.file(p.s3_key).arrayBuffer()).toString('base64') }); stored.push({ s3_key: p.s3_key, bytes: p.bytes, sha: null }); } catch (e: any) { console.error('rollup read failed', e.message); } } }
  if (!imgs.length) return { error: 'no_photos' };
  const jawN = imgs.length, fp = opt.saved ? [] : await q("select s3_key from buck_photos where buck_id=$1 and kind='field' order by created_at desc limit 4", [buck.id]); let nf = 0;
  for (const p of fp as any[]) { try { imgs.push({ mime: 'image/jpeg', b64: Buffer.from(await s3.file(p.s3_key).arrayBuffer()).toString('base64') }); nf++; } catch {} }
  if (nf) (imgs as any).note = `\n\nNOTE: the last ${nf} photo(s) show the live animal (not the jaw). Use them only as weak supporting evidence; the jaw tooth wear takes precedence, and do not raise confidence because of them.\n\n`;
  const [last] = await q("select id from scans where buck_id=$1 and mode='jaw' order by created_at desc limit 1", [buck.id]);
  const [s0] = await q('insert into scans(user_id,buck_id,mode,flags,counted,reuse_of,rollup) values($1,$2,$3,$4,true,$5,$6) returning *', [u.id, buck.id, smode, { usable: false, pending: true }, opt.saved ? null : last?.id || null, smode === 'jaw']);
  for (const [i, p] of stored.entries()) await q('insert into photos(scan_id,s3_key,slot,bytes,sha) values($1,$2,$3,$4,$5)', [s0.id, p.s3_key, i, p.bytes || 0, p.sha || null]);
  if (background) { runAnalysis(s0, u, imgs).catch((e: any) => console.error('rollup analysis crashed', e?.message)); return { scan_id: s0.id, pending: true }; } // runs on after the request ends, so a closed phone or dropped connection cannot lose it
  const r: any = await runAnalysis(s0, u, imgs); if (r.error) return { error: r.error, scan_id: s0.id };
  return { scan: r.scan, out: { ...(await report(r.scan)), buck_id: buck.id, photos_used: jawN, deer_photos: nf } };
}
app.post('/api/bucks/:id/rerun', auth, gate, async c => { const u = c.get('user'); if (!ACTIVE.includes(u.sub_status) && !STAFF(u)) return c.json({ error: 'subscription_required' }, 402);
  const bd = await c.req.json().catch(() => ({})), r = await rollupBuck(u, c.req.param('id'), true, { mode: bd.mode, saved: !!bd.saved }); if (r.error) return r.error === 'not_found' ? c.json({ error: 'not_found' }, 404) : r.error === 'no_photos' ? c.json({ error: 'no_photos' }, 400) : fail(c, r, r.scan_id); return c.json({ id: r.scan_id, pending: true, buck_id: c.req.param('id') }, 202); });
app.post('/api/scans', auth, async c => { const r = await ingest(c, c.get('user')); return r instanceof Response ? r : c.json(r.out); });
app.post('/api/scans/:id/reanalyze', auth, gate, async c => { const u = c.get('user'), s = await mine(c); if (!s) return c.json({ error: 'not_found' }, 404); if (!canScan(u)) return c.json({ error: 'subscription_required' }, 402);
  const ph = await q('select s3_key from photos where scan_id=$1 order by slot', [s.id]); if (!ph.length) return c.json({ error: 'no_photos' }, 400);
  const imgs = await Promise.all(ph.map(async (p: any) => ({ mime: 'image/jpeg', b64: Buffer.from(await s3.file(p.s3_key).arrayBuffer()).toString('base64') })));
  const r: any = await runAnalysis(s, u, imgs); if (r.error) return fail(c, r, s.id); return c.json({ ...(await report(r.scan)), buck_id: s.buck_id, needs_more_photos: r.needs_more }); });
async function shareToken(s: any) { if (s.share_token) return s.share_token; const t = crypto.randomBytes(16).toString('hex'); await q('update scans set share_token=$1 where id=$2', [t, s.id]); return t; }
async function emailScan(s: any, to: string[], u: any) { const t = await shareToken(s), url = `${env.APP_URL}/s/${t}`, ns = { n: 0 } as { n: number; err?: string };
  for (const a of to) await mailTo(ns, a, `Deer Ager result: ${s.class || 'Unclear'}`, `<p>${eh(u.first_name)} shared a Deer Ager result.</p><p style="font-size:22px"><b>${eh(s.class || 'Unclear')}</b> <span style="color:#666">${eh(s.range || '')}</span></p><p>Confidence: ${s.confidence ?? '-'}%</p>${btn(url, 'View full printable report')}`, 'result'); return ns; }
const mine = async (c: any) => (await q('select * from scans where id=$1 and user_id=$2', [c.req.param('id'), c.get('user').id]))[0];
app.get('/api/scans', auth, gate, async c => c.json(await q('select s.id,s.mode,s.class,s.range,s.confidence,s.flags,s.created_at,b.name buck from scans s left join bucks b on b.id=s.buck_id where s.user_id=$1 order by s.created_at desc limit 200', [c.get('user').id])));
app.get('/api/scans/:id', auth, gate, async c => { const s = await mine(c); if (!s) return c.json({ error: 'not_found' }, 404); const ph = await q('select s3_key from photos where scan_id=$1 order by slot', [s.id]);
  return c.json({ ...(await report(s)), notes: s.notes, buck_id: s.buck_id, photos: ph.map((p: any) => s3.file(p.s3_key).presign({ expiresIn: 3600 })) }); });
app.patch('/api/scans/:id', auth, gate, async c => { const body = await c.req.json(), { notes, buck_id } = body; if ('approval' in body) { if (body.approval && !['right', 'too_young', 'too_old', 'unsure'].includes(body.approval)) return c.json({ error: 'invalid_input' }, 400); await q('update scans set approval=$1,approval_at=case when $1::text is null then null else now() end where id=$2 and user_id=$3', [body.approval || null, c.req.param('id'), c.get('user').id]); }
  if ('user_age' in body) { if (body.user_age && !AGES.includes(body.user_age)) return c.json({ error: 'invalid_input' }, 400); await q('update scans set user_age=$1 where id=$2 and user_id=$3', [body.user_age || null, c.req.param('id'), c.get('user').id]); } if (buck_id && !(await q('select 1 from bucks where id=$1 and user_id=$2', [buck_id, c.get('user').id])).length) return c.json({ error: 'not_found' }, 404);
  await q('update scans set notes=coalesce($1,notes),buck_id=case when $5::bool then $2::uuid else buck_id end where id=$3 and user_id=$4', [notes == null ? null : String(notes).slice(0, 2000), buck_id || null, c.req.param('id'), c.get('user').id, 'buck_id' in body]); return c.json({ ok: true }); });
app.delete('/api/scans/:id', auth, gate, async c => { const s = await mine(c); if (!s) return c.json({ ok: true }); const keys = (await q('select s3_key from photos where scan_id=$1', [s.id])).map((p: any) => p.s3_key);
  await q('delete from scans where id=$1', [s.id]); for (const k of keys) if (!(await q('select 1 from photos where s3_key=$1 union all select 1 from buck_photos where s3_key=$1 limit 1', [k])).length) await s3.file(k).delete().catch(() => {}); return c.json({ ok: true }); });
app.post('/api/scans/:id/share', auth, gate, async c => { const s = await mine(c); if (!s) return c.json({ error: 'not_found' }, 404); return c.json({ url: `${env.APP_URL}/s/${await shareToken(s)}` }); });
app.post('/api/scans/:id/email', auth, gate, async c => { if (limited(c, 'em', 20)) return c.json({ error: 'rate_limited' }, 429); const s = await mine(c); if (!s) return c.json({ error: 'not_found' }, 404);
  const to = [...new Set(((await c.req.json()).to || []).map((x: string) => String(x).trim().toLowerCase()).filter((x: string) => /^\S+@\S+\.\S+$/.test(x)))].slice(0, 5) as string[]; if (!to.length) return c.json({ error: 'invalid_input' }, 400);
  return emailRes(c, await emailScan(s, to, c.get('user')), to.length); });
app.get('/api/share/:t', async c => { const [s] = await q('select * from scans where share_token=$1', [c.req.param('t')]); if (!s) return c.json({ error: 'not_found' }, 404); const ph = await q('select slot from photos where scan_id=$1 order by slot', [s.id]);
  return c.json({ ...(await report(s)), photos: ph.map((p: any) => `/api/share/${c.req.param('t')}/p/${p.slot}`) }); }); // photos included (served via this link only), no personal data
app.get('/api/share/:t/p/:slot', async c => { const [s] = await q('select id from scans where share_token=$1', [c.req.param('t')]); const [p] = s ? await q('select s3_key from photos where scan_id=$1 and slot=$2', [s.id, +c.req.param('slot') || 0]) : []; return p ? photoResp(p.s3_key) : c.json({ error: 'not_found' }, 404); });
app.post('/api/bc/read-sheet', auth, gate, async c => { const f: any = await c.req.parseBody({ all: true }), files = [].concat(f.photos || []) as any[], bid = String(f.buck_id || ''); if (!files.length || files.length > 3) return c.json({ error: 'invalid_input' }, 400);
  let buck: any = null; if (bid) { buck = (await q('select * from bucks where id=$1 and user_id=$2', [bid, c.get('user').id]))[0]; if (!buck) return c.json({ error: 'not_found' }, 404); }
  const imgs = await Promise.all(files.map(async (file: any) => ({ mime: file.type, b64: Buffer.from(await file.arrayBuffer()).toString('base64') }))); let x: any = null;
  try { for (const p of live(configured())) { const r: any = await runOnce(p, imgs, 'sheet', 0); if (r.result?.usable) { x = r.result; break; } } } catch (e: any) { console.error('read-sheet', e?.message); }
  if (!x) return c.json({ error: 'sheet_unreadable' }, 422);
  const arr = (a: any) => Array.from({ length: 12 }, (_, i) => { const n = +(a || [])[i]; return Number.isFinite(n) && n >= 0 && n < 100 ? n : 0; }), num = (v: any, mx = 300) => { const n = +v; return Number.isFinite(n) && n > 0 && n < mx ? n : 0; };
  const sheet: any = { l: arr(x.left), r: arr(x.right), spread: num(x.inside, 60), abnormal: num(x.abnormal, 100), pts_r: Math.round(num(x.points_r, 25)), pts_l: Math.round(num(x.points_l, 25)), tip: num(x.tip, 60), greatest: num(x.greatest, 60), hunter: String(x.hunter || '').slice(0, 80) }, calc = bc(sheet), netRead = num(x.net), grossRead = num(x.gross);
  const out = { ...sheet, gross: grossRead || calc.gross, net: netRead || calc.net, calc_net: calc.net, sheet_net: netRead || null, differs: netRead ? Math.abs(netRead - calc.net) > 0.6 : false, from_sheet: true };
  if (buck) { await q('update bucks set bc=$1,known_score=$2 where id=$3', [JSON.stringify({ ...sheet, gross: out.gross, net: out.net, from_sheet: true }), Math.round(out.net * 8) / 8, bid]); recalcAll(bid).catch(e => console.error('recalc', e.message)); }
  return c.json(out); });
app.post('/api/bc', auth, async c => c.json(bc(await c.req.json())));

// ---------- partner API (hunting-club software, outfitters, etc.): /api/v1 with a Bearer dk_… key, hosted capture links, webhooks
function rulesEval(rules: any, o: any, ext: any) {
  const checks: any[] = [], rl = rules || {}, d = o?.dist, num = (v: any) => (v === '' || v == null || !Number.isFinite(+v) ? null : +v);
  if (num(rl.min_age) != null) { const pct = d ? Math.round(AGES.filter(a => parseFloat(a) >= +rl.min_age).reduce((t, a) => t + (+d.probs?.[a] || 0), 0)) : null;
    checks.push({ rule: 'min_age', required: +rl.min_age, status: pct == null ? 'unknown' : pct >= 70 ? 'yes' : pct <= 30 ? 'no' : 'unsure', chance_pct: pct }); }
  for (const [k, f] of [['min_points', 'points'], ['min_spread', 'spread'], ['min_net', 'net']] as const) if (num(rl[k]) != null) { const v = num(ext?.[f]); checks.push({ rule: k, required: +rl[k], value: v, status: v == null ? 'unknown' : v >= +rl[k] ? 'yes' : 'no' }); }
  const meets = !checks.length ? null : checks.some(c => c.status === 'no') ? 'no' : checks.every(c => c.status === 'yes') ? 'yes' : 'unsure';
  return { meets, checks, notes: ['antler_rule', 'season_limit', 'does_first', 'notes'].filter(k => rl[k]).map(k => `${k}: ${rl[k]}`) };
}
async function v1scan(s: any) {
  const o = s.observations || {}, ext = s.ext || {}, d = o.dist, t = await shareToken(s);
  return { id: s.id, mode: s.mode, status: s.flags?.pending ? 'pending' : 'complete', created_at: s.created_at, class: s.class, range: s.range, confidence: s.confidence, usable: !!s.flags?.usable,
    age: d ? { best: d.best, low: d.lo, high: d.hi, probabilities: d.probs } : null, antler_estimate: s.mode === 'bc' ? { net_low: o.net_low ?? null, net_high: o.net_high ?? null } : undefined,
    needs_more_photos: !s.flags?.usable || (s.confidence ?? 0) < 75, issues: s.flags?.issues || [], missing: s.flags?.missing || [], reasoning: o.reasoning || null,
    rules: ext.rules ? rulesEval(ext.rules, o, ext) : null, member_id: ext.member_id || null, deer_id: ext.deer_id || null, club_id: ext.club_id || null, points: ext.points ?? null,
    report_url: `${env.APP_URL}/s/${t}`, disclaimer: 'Estimate only. Tooth-wear aging is subjective; a lab cementum test is the gold standard.' };
}
const clip = (v: any, n = 100) => (v == null || v === '' ? undefined : String(v).slice(0, n));
function extFrom(b: any) {
  let rules: any = b.rules; if (typeof rules === 'string') { try { rules = JSON.parse(rules); } catch { rules = null; } }
  const num = (v: any, lo: number, hi: number) => (v === '' || v == null || !Number.isFinite(+v) ? undefined : Math.max(lo, Math.min(hi, +v)));
  const r = rules && typeof rules === 'object' ? { min_age: [2.5, 3.5, 4.5, 5.5, 6.5].includes(+rules.min_age) ? +rules.min_age : undefined, min_points: num(rules.min_points, 0, 30), min_spread: num(rules.min_spread, 0, 40), min_net: num(rules.min_net, 0, 300), antler_rule: clip(rules.antler_rule, 200), season_limit: num(rules.season_limit, 0, 20), does_first: num(rules.does_first, 0, 20), notes: clip(rules.notes, 500) } : null;
  const ext: any = { member_id: clip(b.member_id), deer_id: clip(b.deer_id), club_id: clip(b.club_id), points: num(b.points, 0, 40), spread: num(b.spread, 0, 40), net: num(b.net, 0, 300), rules: r && Object.values(r).some(v => v != null) ? r : undefined };
  for (const k of Object.keys(ext)) if (ext[k] === undefined) delete ext[k]; return ext;
}
async function fireHook(p: any, event: string, data: any) {
  if (!p.webhook_url) return; const body = JSON.stringify({ id: 'evt_' + crypto.randomUUID(), type: event, created: Math.floor(Date.now() / 1000), data }), ts = Math.floor(Date.now() / 1000), sig = crypto.createHmac('sha256', p.webhook_secret || '').update(`${ts}.${body}`).digest('hex');
  for (let i = 0; i < 2; i++) { try { const r = await fetch(p.webhook_url, { method: 'POST', headers: { 'content-type': 'application/json', 'deerager-signature': `t=${ts},v1=${sig}` }, body, signal: AbortSignal.timeout(8000) }); await audit(null, 'partner_webhook', { partner: p.id, event, status: r.status }); if (r.ok) return; } catch (e: any) { await audit(null, 'partner_webhook', { partner: p.id, event, error: String(e.message).slice(0, 100) }); } if (!i) await new Promise(r => setTimeout(r, 5000)); }
}
const partnerUser = async (p: any) => (await q("select u.*,(select trial_scans from plans where id='trial') trial_scans from users u where u.id=$1", [p.user_id]))[0];
const monthUsed = async (p: any) => (await q("select count(*)::int n from scans where partner_id=$1 and created_at>=date_trunc('month',now())", [p.id]))[0].n;
const V1 = new Hono();
V1.use('*', async (c: any, next: any) => { const k = (c.req.header('authorization') || '').replace(/^Bearer /, '').trim(); const [p] = k.startsWith('dk_') ? await q('select * from partners where key_hash=$1 and active', [sha(k)]) : [];
  if (!p) return c.json({ error: 'unauthorized' }, 401); const u = await partnerUser(p); if (!u) return c.json({ error: 'unauthorized' }, 401); c.set('partner', p); c.set('user', u); await next(); });
V1.get('/me', async c => { const p = c.get('partner'); return c.json({ name: p.name, monthly_limit: p.monthly_limit, used_this_month: await monthUsed(p) }); });
async function partnerScan(c: any, p: any, u: any, x: any) {
  if (p.monthly_limit && (await monthUsed(p)) >= p.monthly_limit) return c.json({ error: 'limit_reached' }, 429);
  const r = await ingest(c, u, { ...x, partner_id: p.id }); if (r instanceof Response) return r;
  const out = await v1scan((await q('select * from scans where id=$1', [r.scan.id]))[0]); fireHook(p, 'scan.completed', out).catch(() => {}); return c.json({ ...out, storage_down: r.out.storage_down });
}
V1.post('/scans', async c => { const p = c.get('partner'), f: any = await c.req.parseBody({ all: true }); return partnerScan(c, p, c.get('user'), { ext: extFrom(f) }); });
V1.get('/scans', async c => { const p = c.get('partner'), w: string[] = ['partner_id=$1'], a: any[] = [p.id];
  for (const k of ['member_id', 'deer_id', 'club_id']) if (c.req.query(k)) { a.push(c.req.query(k)); w.push(`ext->>'${k}'=$${a.length}`); }
  const rows = await q(`select * from scans where ${w.join(' and ')} order by created_at desc limit ${Math.min(+(c.req.query('limit') || 50) || 50, 200)}`, a); return c.json({ scans: await Promise.all(rows.map(v1scan)) }); });
V1.get('/scans/:id', async c => { const [s] = await q('select * from scans where id=$1 and partner_id=$2', [c.req.param('id'), c.get('partner').id]).catch(() => []); return s ? c.json(await v1scan(s)) : c.json({ error: 'not_found' }, 404); });
V1.patch('/scans/:id', async c => { const b = await c.req.json().catch(() => ({})), [s] = await q('select * from scans where id=$1 and partner_id=$2', [c.req.param('id'), c.get('partner').id]).catch(() => []); if (!s) return c.json({ error: 'not_found' }, 404);
  const ext = { ...(s.ext || {}), ...extFrom(b) }; await q('update scans set ext=$1 where id=$2', [ext, s.id]); return c.json(await v1scan({ ...s, ext })); });
// a deer follows its member: move every scan of a member from one club to another
V1.post('/members/:member/transfer', async c => { const b = await c.req.json().catch(() => ({})), to = clip(b.to_club), from = clip(b.from_club); if (!to) return c.json({ error: 'invalid_input' }, 400);
  const r = await q(`update scans set ext=jsonb_set(coalesce(ext,'{}'),'{club_id}',to_jsonb($1::text)) where partner_id=$2 and ext->>'member_id'=$3 ${from ? "and ext->>'club_id'=$4" : ''} returning id`, from ? [to, c.get('partner').id, c.req.param('member'), from] : [to, c.get('partner').id, c.req.param('member')]); return c.json({ moved: r.length }); });
V1.post('/capture-links', async c => { const p = c.get('partner'), b = await c.req.json().catch(() => ({})); if (!['jaw', 'deer', 'bc'].includes(b.mode)) return c.json({ error: 'invalid_input' }, 400);
  const ru = b.return_url ? String(b.return_url).slice(0, 500) : null; if (ru && !/^https:\/\/[^\s]+$/.test(ru)) return c.json({ error: 'invalid_return_url' }, 400);
  const t = crypto.randomBytes(18).toString('hex'), hrs = Math.min(Math.max(+b.expires_hours || 24, 1), 168); await q("insert into capture_links(token,partner_id,mode,ext,return_url,expires_at,max_uses) values($1,$2,$3,$4,$5,now()+($6||' hours')::interval,$7)", [t, p.id, b.mode, extFrom(b), ru, String(hrs), Math.min(Math.max(+b.max_uses || 3, 1), 10)]);
  return c.json({ url: `${env.APP_URL}/c/${t}`, expires_in_hours: hrs }); });
app.route('/api/v1', V1);
app.onError((e: any, c: any) => { console.error('unhandled', c.req.method, c.req.path, e?.stack || e?.message || e); return c.json({ error: 'server_error', ...(c.get('user')?.role === 'admin' ? { detail: String(e?.message || e).slice(0, 160) } : {}) }, 500); });
const capLink = async (t: string) => (await q('select l.*,p.name partner_name,p.active from capture_links l join partners p on p.id=l.partner_id where l.token=$1 and l.expires_at>now()', [t]))[0];
app.get('/api/c/:t', async c => { const l = await capLink(c.req.param('t')); return l && l.active ? c.json({ mode: l.mode, partner: l.partner_name, return_url: l.return_url, left: l.max_uses - l.used }) : c.json({ error: 'not_found' }, 404); });
app.post('/api/c/:t/scan', async c => { if (limited(c, 'cap', 20)) return c.json({ error: 'rate_limited' }, 429); const l = await capLink(c.req.param('t')); if (!l || !l.active || l.used >= l.max_uses) return c.json({ error: 'link_expired' }, 410);
  const [p] = await q('select * from partners where id=$1', [l.partner_id]), u = await partnerUser(p); await q('update capture_links set used=used+1 where token=$1', [l.token]);
  return partnerScan(c, p, u, { mode: l.mode, ext: l.ext || {} }); });

// ---------- billing (Stripe Checkout hosted page keeps card data off our servers: PCI SAQ A)
let _s: any = { k: null, c: null };
const getStripe = async () => { const k = await getSetting('stripe_secret_key'); if (!k) return null; if (_s.k !== k) _s = { k, c: new Stripe(k) }; return _s.c as Stripe; };
app.get('/api/config', async c => c.json({ stripe_pk: await getSetting('stripe_publishable_key'), billing_ready: !!(await getSetting('stripe_secret_key')) }));
app.get('/api/plans', async c => c.json(await q("select id,name,price_cents,interval,trial_days,trial_scans from plans where active and (id='trial' or interval in ('month','year')) order by (case when interval='year' then price_cents/12.0 else price_cents end)")));
async function priceFor(st: Stripe, p: any) { if (p.stripe_price_id) return p.stripe_price_id;
  const pr = await st.prices.create({ unit_amount: p.price_cents, currency: 'usd', recurring: { interval: p.interval }, product_data: { name: 'Deer Ager ' + p.name } }); await q('update plans set stripe_price_id=$1 where id=$2', [pr.id, p.id]); return pr.id; }
app.post('/api/billing/checkout', auth, async c => { const u = c.get('user'); const st = await getStripe(); if (!st) return c.json({ error: 'billing_not_configured' }, 503);
  const { plan } = await c.req.json(); const [p] = await q("select * from plans where id=$1 and interval in ('month','year') and active", [plan]); if (!p) return c.json({ error: 'invalid_input' }, 400);
  const [tr] = await q("select trial_days from plans where id='trial'");
  try { let cust = u.stripe_customer; if (!cust) { cust = (await st.customers.create({ email: u.email, name: `${u.first_name} ${u.last_name}`, phone: u.phone, address: { line1: u.address, city: u.city, state: u.state, postal_code: u.zip, country: 'US' }, metadata: { uid: u.id } })).id; await q('update users set stripe_customer=$1 where id=$2', [cust, u.id]); }
    const eligible = !u.stripe_sub; // first subscription gets the free trial; card is always collected
    const s = await st.checkout.sessions.create({ mode: 'subscription', customer: cust, line_items: [{ price: await priceFor(st, p), quantity: 1 }], payment_method_types: ['card'], payment_method_collection: 'always', client_reference_id: u.id, subscription_data: { metadata: { uid: u.id }, ...(eligible && tr?.trial_days ? { trial_period_days: tr.trial_days } : {}) }, customer_update: { address: 'auto', name: 'auto' }, success_url: env.APP_URL + '/?paid=1', cancel_url: env.APP_URL + '/?paid=0' });
    return c.json({ url: s.url }); } catch (e: any) { return c.json({ error: 'stripe_error', detail: e.message }, 502); } });
app.post('/api/billing/portal', auth, async c => { const st = await getStripe(), u = c.get('user'); if (!st || !u.stripe_customer) return c.json({ error: 'no_subscription' }, 400); try { return c.json({ url: (await st.billingPortal.sessions.create({ customer: u.stripe_customer, return_url: env.APP_URL })).url }); } catch (e: any) { return c.json({ error: 'stripe_error', detail: e.message }, 502); } });
const setCancel = (flag: boolean) => async (c: any) => { const st = await getStripe(), u = c.get('user'); if (!st || !u.stripe_sub) return c.json({ error: 'no_subscription' }, 400);
  try { await st.subscriptions.update(u.stripe_sub, { cancel_at_period_end: flag }); await q('update users set cancel_at_end=$1 where id=$2', [flag, u.id]); await audit(u.id, flag ? 'cancel_requested' : 'cancel_undone'); return c.json({ ok: true }); } catch (e: any) { return c.json({ error: 'stripe_error', detail: e.message }, 502); } };
app.post('/api/billing/cancel', auth, setCancel(true)); app.post('/api/billing/resume', auth, setCancel(false));
async function applySub(sub: any) {
  const uid = sub.metadata?.uid; const [u] = uid ? await q('select * from users where id=$1', [uid]) : await q('select * from users where stripe_customer=$1', [sub.customer]); if (!u) return;
  const price = sub.items?.data?.[0]?.price?.id, [p] = price ? await q('select id from plans where stripe_price_id=$1', [price]) : [], pid = p?.id || u.plan_id;
  const ended = ['canceled', 'incomplete_expired'].includes(sub.status), status = ended ? 'canceled' : sub.status;
  await q('update users set stripe_customer=$1,stripe_sub=$2,sub_status=$3,plan_id=$4,cancel_at_end=$5,period_end=to_timestamp($6),lifetime_data=lifetime_data or $7 where id=$8', [sub.customer, sub.id, status, ended ? 'lapsed' : pid, !!sub.cancel_at_period_end, sub.current_period_end || null, pid === 'annual' && !ended, u.id]);
  if (u.sub_status !== status) { if (wantsBilling(u)) { const m: any = { trialing: ['Your free trial has started', 'Your free trial is active. Your card will be charged when it ends unless you cancel in Account.'], active: ['Your subscription is active', 'Thanks for subscribing to Deer Ager.'], past_due: ['Payment failed', 'We could not process your payment. Please update your card in Account to keep scanning.'], canceled: ['Your subscription has ended', 'You can no longer scan new deer. ' + (pid === 'annual' || u.lifetime_data ? 'Your saved data stays available.' : 'Your saved data returns if you resubscribe.')] }; if (m[status]) await mail(u.email, m[status][0], `<p>Hi ${eh(u.first_name)},</p><p>${m[status][1]}</p>${btn(env.APP_URL!, 'Open Deer Ager')}`, 'billing'); } }
}
app.post('/api/webhooks/stripe', async c => { const st = await getStripe(), wh = await getSetting('stripe_webhook_secret'); if (!st || !wh) return c.text('not configured', 503);
  let e: any; try { e = await st.webhooks.constructEventAsync(await c.req.text(), c.req.header('stripe-signature') || '', wh); } catch { return c.text('bad signature', 400); }
  const o = e.data.object;
  if (e.type === 'checkout.session.completed' && o.client_reference_id) await q('update users set stripe_customer=$1 where id=$2', [o.customer, o.client_reference_id]);
  if (e.type === 'checkout.session.completed' && o.metadata?.consult_id && o.payment_status === 'paid') { const [x] = await q("update consults set status='open',paid_at=now(),payment_intent=$1 where id=$2 and status='pending_payment' returning *", [o.payment_intent, o.metadata.consult_id]);
    if (x) { try { const pi = await st.paymentIntents.retrieve(o.payment_intent); await q('update consults set charge_id=$1 where id=$2', [pi.latest_charge, x.id]); } catch {}
      const [h] = await q('select email from users where id=$1', [x.hunter_id]), [bk] = await q('select name from bucks where id=$1', [x.buck_id]), cfg = await consultCfg();
      if (h) mail(h.email, 'Your biologist consult is in the queue', `<p>Thanks. Your consult for <b>${esc(bk?.name || 'your deer')}</b> is paid and waiting for a biologist. Expect an answer within ${cfg.sla_hours} hours.</p>`, 'consult').catch(() => {});
      for (const b of await q("select email from users where role='biologist' and status='active'")) mail(b.email, 'New consult in the queue', `<p>A hunter asked for a consult on <b>${esc(bk?.name || 'a deer')}</b>. Open Deer Ager and go to the Biologist tab to claim it.</p>`, 'consult').catch(() => {}); } }
  if (e.type === 'charge.refunded' && o.payment_intent) await q("update consults set status='refunded',refunded_at=now(),payout_status=case when payout_status='unpaid' then 'none' else payout_status end where payment_intent=$1 and status<>'answered'", [o.payment_intent]);
  if (e.type.startsWith('customer.subscription.')) await applySub(o);
  if (e.type === 'invoice.payment_failed') { const [u] = await q('select * from users where stripe_customer=$1', [o.customer]); if (u) await q("update users set sub_status='past_due' where id=$1 and sub_status<>'canceled'", [u.id]); }
  await audit(null, 'stripe:' + e.type, { id: e.id }); return c.json({ received: true }); });

// ---------- biologist consults
const esc = (t: any) => String(t ?? '').replace(/[&<>"]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' } as any)[ch]);
const cfgNum = async (k: string, d: number) => { const v = +((await getSetting(k)) ?? ''); return v >= 0 && (await getSetting(k)) != null && (await getSetting(k)) !== '' ? v : d; };
const consultCfg = async () => ({ consult_price_cents: await cfgNum('consult_price_cents', 1500), age_price_cents: await cfgNum('age_price_cents', 2500), payout_pct: await cfgNum('consult_payout_pct', 70), sla_hours: await cfgNum('consult_sla_hours', 48) });
const CPUB = (x: any) => ({ id: x.id, kind: x.kind || 'age', buck_id: x.buck_id, status: x.status, question: x.question, price_cents: x.price_cents, created_at: x.created_at, paid_at: x.paid_at, claimed_at: x.claimed_at, answered_at: x.answered_at,
  biologist: x.bio_first ? `${x.bio_first} ${x.bio_last || ''}`.trim() : null, bio_title: x.bio_title || null, need_info: x.need_info || null, hunter_reply: x.hunter_reply || null,
  answer: x.status === 'answered' ? { kind: x.kind || 'age', data: x.answer_data || null, age: x.answer_age, confidence: x.answer_conf, notes: x.answer_notes } : null });
const CSEL = "select c.*,u.first_name bio_first,u.last_name bio_last,u.bio_title from consults c left join users u on u.id=c.biologist_id";
// Send a biologist their share. Uses Stripe Connect when their account is set up, otherwise the earning waits for a manual payout from Admin.
async function payoutConsult(id: string) {
  const [c] = await q('select c.*,u.stripe_connect_id from consults c join users u on u.id=c.biologist_id where c.id=$1', [id]);
  if (!c || c.status !== 'answered' || c.payout_status !== 'unpaid' || !c.stripe_connect_id || !c.payout_cents) return false;
  const st = await getStripe(); if (!st) return false;
  try { const acct = await st.accounts.retrieve(c.stripe_connect_id); if (!acct.payouts_enabled) return false;
    const t = await st.transfers.create({ amount: c.payout_cents, currency: 'usd', destination: c.stripe_connect_id, transfer_group: 'consult_' + c.id, ...(c.charge_id ? { source_transaction: c.charge_id } : {}), metadata: { consult_id: c.id } }, { idempotencyKey: 'consult-transfer-' + c.id });
    await q("update consults set payout_status='transferred',transfer_id=$1,payout_paid_at=now() where id=$2", [t.id, c.id]); return true; } catch (e: any) { console.error('payout failed', c.id, e.message); return false; } }
// Standard aging form: the biologist taps choices, the app writes the report.
const AGEFORM = {
  basis: [['jaw', 'Jawbone teeth'], ['deer', 'Live or whole-deer photos']],
  p3: [['tri', 'Three cusps (young tooth)'], ['bi', 'Two cusps (adult tooth)'], ['na', 'Cannot tell']],
  m3: [['absent', 'Not erupted'], ['erupting', 'Erupting'], ['full', 'Fully erupted'], ['na', 'Cannot tell']],
  wear: [['sharp', 'Sharp, no wear'], ['slight', 'Slight, cusps just blunting'], ['moderate', 'Moderate, dentine wider than enamel'], ['heavy', 'Heavy, cusps mostly flat'], ['severe', 'Severe, worn to the gum line'], ['na', 'Cannot tell']],
  quality: [['good', 'Clear, enough to age'], ['limited', 'Limited, so allow a wider range'], ['poor', 'Not enough to age well']],
  body: [['lean', 'Lean, leggy, narrow chest'], ['mature', 'Deep chest, thick neck, even lines'], ['old', 'Sagging belly, swayed back, thin legs'], ['na', 'Cannot tell']],
  face: [['smooth', 'Smooth, dark face'], ['gray', 'Some gray around muzzle and eyes'], ['heavy', 'Heavy gray, sunken face'], ['na', 'Cannot tell']],
};
const lab = (k: keyof typeof AGEFORM, v: any) => (AGEFORM[k].find((x: string[]) => x[0] === v) || [0, ''])[1];
function suggestAge(d: any): string | null {
  if (d.basis === 'deer') { const sc = { smooth: 0, gray: 1, heavy: 2 } as any, bd = { lean: 0, mature: 1, old: 2 } as any; if (!(d.body in bd) && !(d.face in sc)) return null; const t = (bd[d.body] ?? 1) + (sc[d.face] ?? 1); return ['2.5', '3.5', '4.5', '5.5', '6.5+'][Math.min(4, t + (t > 0 ? 1 : 0))] ?? null; }
  if (d.p3 === 'tri' && d.m3 === 'absent') return '0.5';
  if (d.p3 === 'tri' && (d.m3 === 'erupting' || d.m3 === 'full')) return '1.5';
  const w = ({ sharp: '2.5', slight: '3.5', moderate: '4.5', heavy: '5.5', severe: '6.5+' } as any)[d.wear_m1]; return w ?? null; }
function stdReport(d: any, age: string, conf: string, comment: string) {
  const L = [`Biologist age report`, `Basis: ${lab('basis', d.basis)}.`];
  if (d.basis === 'deer') { if (d.body && d.body !== 'na') L.push(`Body: ${lab('body', d.body).toLowerCase()}.`); if (d.face && d.face !== 'na') L.push(`Face: ${lab('face', d.face).toLowerCase()}.`); }
  else { if (d.p3 && d.p3 !== 'na') L.push(`Lower third premolar: ${lab('p3', d.p3).toLowerCase()}.`); if (d.m3 && d.m3 !== 'na') L.push(`Third molar: ${lab('m3', d.m3).toLowerCase()}.`);
    const w = [['first', d.wear_m1], ['second', d.wear_m2], ['third', d.wear_m3]].filter(x => x[1] && x[1] !== 'na').map(x => `${x[0]} molar ${lab('wear', x[1]).toLowerCase()}`); if (w.length) L.push(`Tooth wear: ${w.join('; ')}.`);
    if (d.cementum) L.push(`Cementum annuli counted: ${d.cementum}.`); }
  L.push(`Photo quality: ${lab('quality', d.quality).toLowerCase()}.`, `Age: ${age} years (confidence: ${conf}).`); if (comment) L.push(`Note: ${comment}`); return L.join('\n'); }
const bioAuth = async (c: any, next: any) => STAFF(c.get('user')) ? next() : c.json({ error: 'forbidden' }, 403);
app.get('/api/consult/info', auth, async c => { const cfg = await consultCfg(), st = await getStripe(); return c.json({ consult_price_cents: cfg.consult_price_cents, age_price_cents: cfg.age_price_cents, sla_hours: cfg.sla_hours, available: !!st && (await q("select 1 from users where role in ('biologist') and status='active' limit 1")).length > 0 }); });
app.post('/api/bucks/:id/consult', auth, gate, async c => { const u = c.get('user'), b = await ownBuck(c); if (!b) return c.json({ error: 'not_found' }, 404);
  const body = await c.req.json().catch(() => ({})), question = String(body.question || '').trim().slice(0, 1500), kind = body.kind === 'consult' ? 'consult' : 'age';
  if (kind === 'consult' && question.length < 5) return c.json({ error: 'consult_needs_question' }, 400);
  if (!(await q('select 1 from scans where buck_id=$1 union all select 1 from buck_photos where buck_id=$1 limit 1', [b.id])).length) return c.json({ error: 'consult_needs_photos' }, 400);
  if ((await q("select 1 from consults where buck_id=$1 and kind=$2 and status in ('open','claimed','needs_info') limit 1", [b.id, kind])).length) return c.json({ error: 'consult_active' }, 409);
  const st = await getStripe(); if (!st) return c.json({ error: 'billing_not_configured' }, 503);
  const cfg = await consultCfg(), price = kind === 'consult' ? cfg.consult_price_cents : cfg.age_price_cents, [row] = await q('insert into consults(buck_id,hunter_id,question,price_cents,payout_pct,payout_cents,kind) values($1,$2,$3,$4,$5,$6,$7) returning id', [b.id, u.id, question, price, cfg.payout_pct, Math.round(price * cfg.payout_pct / 100), kind]);
  try { const base = env.APP_URL || new URL(c.req.url).origin;
    const ses = await st.checkout.sessions.create({ mode: 'payment', ...(u.stripe_customer ? { customer: u.stripe_customer } : { customer_email: u.email }), line_items: [{ quantity: 1, price_data: { currency: 'usd', unit_amount: price, product_data: { name: (kind === 'consult' ? 'Biologist consult: ' : 'Biologist age: ') + b.name.slice(0, 60), description: kind === 'consult' ? 'A wildlife biologist answers your question about this deer.' : 'A wildlife biologist reviews your deer and gives a formal age.' } } }], payment_intent_data: { transfer_group: 'consult_' + row.id, metadata: { consult_id: row.id } }, metadata: { consult_id: row.id }, client_reference_id: u.id, success_url: `${base}/?consult=paid&buck=${b.id}`, cancel_url: `${base}/?consult=cancelled&buck=${b.id}` });
    await q('update consults set checkout_session=$1 where id=$2', [ses.id, row.id]); return c.json({ url: ses.url, id: row.id }); } catch (e: any) { await q("delete from consults where id=$1 and status='pending_payment'", [row.id]); console.error('consult checkout failed', e.message); return c.json({ error: 'billing_failed' }, 502); } });
app.get('/api/bucks/:id/consults', auth, async c => { const b = await ownBuck(c); if (!b) return c.json({ error: 'not_found' }, 404); return c.json((await q(CSEL + " where c.buck_id=$1 and c.status<>'pending_payment' order by c.created_at desc", [b.id])).map(CPUB)); });
app.post('/api/consults/:id/reply', auth, async c => { const u = c.get('user'), body = await c.req.json().catch(() => ({})), t = String(body.text || '').trim().slice(0, 1500); if (!t) return c.json({ error: 'invalid_input' }, 400);
  const [x] = await q("update consults set status='claimed',hunter_reply=$1 where id=$2 and hunter_id=$3 and status='needs_info' returning biologist_id", [t, c.req.param('id'), u.id]); if (!x) return c.json({ error: 'not_found' }, 404);
  const [bio] = await q('select email from users where id=$1', [x.biologist_id]); if (bio) mail(bio.email, 'The hunter answered your question', `<p>${esc(u.first_name || 'The hunter')} replied on a consult:</p><blockquote>${esc(t)}</blockquote><p>Open Deer Ager and go to the Biologist tab.</p>`, 'consult').catch(() => {}); return c.json({ ok: true }); });
app.post('/api/consults/:id/cancel', auth, async c => { const u = c.get('user'), [x] = await q("select * from consults where id=$1 and hunter_id=$2 and status='open'", [c.req.param('id'), u.id]); if (!x) return c.json({ error: 'not_found' }, 404);
  const st = await getStripe(); try { if (st && x.payment_intent) await st.refunds.create({ payment_intent: x.payment_intent }, { idempotencyKey: 'consult-refund-' + x.id }); } catch (e: any) { console.error('refund failed', e.message); return c.json({ error: 'refund_failed' }, 502); }
  await q("update consults set status='refunded',refunded_at=now(),payout_status='none' where id=$1", [x.id]); return c.json({ ok: true }); });
// biologist panel
const B = new Hono(); B.use('*', auth, bioAuth);
B.get('/form', async c => c.json(AGEFORM));
B.post('/suggest', async c => c.json({ age: suggestAge(await c.req.json().catch(() => ({}))) }));
B.get('/queue', async c => { const cfg = await consultCfg(); return c.json({ sla_hours: cfg.sla_hours, items: (await q("select c.id,c.kind,c.question,c.created_at,c.paid_at,c.payout_cents,b.name,u.first_name,u.state,(select count(*)::int from scans s where s.buck_id=b.id) scans,(select count(*)::int from buck_photos p where p.buck_id=b.id) photos from consults c join bucks b on b.id=c.buck_id join users u on u.id=c.hunter_id where c.status='open' order by c.paid_at")) }); });
B.get('/mine', async c => c.json((await q("select c.id,c.kind,c.status,c.question,c.created_at,c.claimed_at,c.answered_at,c.answer_age,c.payout_cents,c.payout_status,b.name,b.id buck_id,u.first_name,u.state from consults c join bucks b on b.id=c.buck_id join users u on u.id=c.hunter_id where c.biologist_id=$1 order by coalesce(c.answered_at,c.claimed_at) desc", [c.get('user').id])))); 
B.post('/consults/:id/claim', async c => { const me = c.get('user'), [x] = await q("update consults set status='claimed',biologist_id=$1,claimed_at=now() where id=$2 and status='open' returning *", [me.id, c.req.param('id')]); if (!x) return c.json({ error: 'already_claimed' }, 409);
  await q('insert into buck_shares(buck_id,to_user) values($1,$2) on conflict do nothing', [x.buck_id, me.id]); const [h] = await q('select email,first_name from users where id=$1', [x.hunter_id]);
  if (h) mail(h.email, 'A biologist is reviewing your deer', `<p>${esc(me.first_name || 'A biologist')} ${esc(me.last_name || '')} has taken your consult and is reviewing your deer now. You will get an email when the answer is ready.</p>`, 'consult').catch(() => {}); return c.json({ ok: true }); });
B.get('/consults/:id', async c => { const me = c.get('user'), [x] = await q(CSEL.replace('c.*,', 'c.*,') + ' where c.id=$1 and (c.biologist_id=$2 or $3)', [c.req.param('id'), me.id, me.role === 'admin']); if (!x) return c.json({ error: 'not_found' }, 404);
  const [b] = await q('select * from bucks where id=$1', [x.buck_id]), [h] = await q('select first_name,state from users where id=$1', [x.hunter_id]);
  const ph = await q("select s3_key,kind,'saved' src from buck_photos where buck_id=$1 union all select p.s3_key,'scan','scan' from photos p join scans s on s.id=p.scan_id where s.buck_id=$1", [b.id]), seen = new Set<string>();
  const photos = ph.filter((p: any) => !seen.has(p.s3_key) && seen.add(p.s3_key)).slice(0, 30).map((p: any) => ({ kind: p.kind, url: s3.file(p.s3_key).presign({ expiresIn: 3600 }) }));
  return c.json({ ...CPUB(x), payout_cents: x.payout_cents, payout_status: x.payout_status, buck: await buckSheet(b), age_case: await buckCase(b.id), photos, hunter: h ? { first_name: h.first_name, state: h.state } : null, answer_draft: { age: x.answer_age, confidence: x.answer_conf, notes: x.answer_notes }, form: AGEFORM, scans: (await q("select id,mode,class,range,confidence,created_at,observations->'dist' dist from scans where buck_id=$1 and class is not null order by created_at desc", [b.id])) }); });
B.post('/consults/:id/answer', async c => { const me = c.get('user'), b = await c.req.json().catch(() => ({})), conf = ['high', 'medium', 'low'].includes(b.confidence) ? b.confidence : null, comment = String(b.notes || '').trim().slice(0, 3000);
  const [cur] = await q('select kind from consults where id=$1', [c.req.param('id')]), isAge = (cur?.kind || 'age') === 'age'; let notes = comment, data: any = null;
  if (isAge) { const d = b.data || {}, ok = (k: keyof typeof AGEFORM, v: any) => v == null || v === '' || AGEFORM[k].some((x: string[]) => x[0] === v);
    if (!AGES.includes(b.age) || !conf || !ok('basis', d.basis) || !d.basis || !d.quality || !ok('quality', d.quality) || !ok('p3', d.p3) || !ok('m3', d.m3) || !ok('wear', d.wear_m1) || !ok('wear', d.wear_m2) || !ok('wear', d.wear_m3) || !ok('body', d.body) || !ok('face', d.face)) return c.json({ error: 'invalid_input' }, 400);
    if (d.quality === 'poor' && b.age) { /* allowed: low-confidence answer with a reason */ }
    data = { basis: d.basis, p3: d.p3 || null, m3: d.m3 || null, wear_m1: d.wear_m1 || null, wear_m2: d.wear_m2 || null, wear_m3: d.wear_m3 || null, cementum: d.cementum ? String(d.cementum).slice(0, 12) : null, body: d.body || null, face: d.face || null, quality: d.quality, suggested: suggestAge(d) };
    notes = stdReport(data, b.age, conf!, comment); }
  else if (notes.length < 10) return c.json({ error: 'invalid_input' }, 400);
  const [x] = await q("update consults set status='answered',answer_age=$1,answer_conf=$2,answer_notes=$3,answer_data=$4,answered_at=now() where id=$5 and biologist_id=$6 and status='claimed' returning *", [isAge ? b.age : null, conf, notes, data, c.req.param('id'), me.id]); if (!x) return c.json({ error: 'not_found' }, 404);
  const pct = me.payout_pct ?? x.payout_pct; if (pct !== x.payout_pct) await q('update consults set payout_pct=$1,payout_cents=$2 where id=$3', [pct, Math.round(x.price_cents * pct / 100), x.id]);
  payoutConsult(x.id).catch(() => {}); const [h] = await q('select email from users where id=$1', [x.hunter_id]), [bk] = await q('select name from bucks where id=$1', [x.buck_id]);
  if (h) mail(h.email, `Biologist ${isAge ? 'age' : 'answer'} for ${bk?.name || 'your deer'}`, `<p>A biologist reviewed <b>${esc(bk?.name || 'your deer')}</b>.</p>${isAge ? `<p style="font-size:22px"><b>Age: ${esc(b.age)} years</b> (confidence: ${conf})</p>` : ''}<p>${esc(notes).replace(/\n/g, '<br>')}</p><p>Open Deer Ager and go to the deer's page to see it with your scans.</p>`, 'consult').catch(() => {}); return c.json({ ok: true }); });
B.post('/consults/:id/need-info', async c => { const me = c.get('user'), t = String((await c.req.json().catch(() => ({}))).text || '').trim().slice(0, 1500); if (t.length < 5) return c.json({ error: 'invalid_input' }, 400);
  const [x] = await q("update consults set status='needs_info',need_info=$1 where id=$2 and biologist_id=$3 and status='claimed' returning hunter_id,buck_id", [t, c.req.param('id'), me.id]); if (!x) return c.json({ error: 'not_found' }, 404);
  const [h] = await q('select email from users where id=$1', [x.hunter_id]); if (h) mail(h.email, 'The biologist needs a little more from you', `<p>The biologist reviewing your deer asks:</p><blockquote>${esc(t)}</blockquote><p>Open Deer Ager, go to the deer's page, add the photos or answer, and the review continues.</p>`, 'consult').catch(() => {}); return c.json({ ok: true }); });
B.post('/consults/:id/release', async c => { const me = c.get('user'), [x] = await q("update consults set status='open',biologist_id=null,claimed_at=null where id=$1 and biologist_id=$2 and status in ('claimed','needs_info') returning buck_id", [c.req.param('id'), me.id]); if (!x) return c.json({ error: 'not_found' }, 404); await q('delete from buck_shares where buck_id=$1 and to_user=$2', [x.buck_id, me.id]); return c.json({ ok: true }); });
B.get('/earnings', async c => { const id = c.get('user').id, tot = (await q("select coalesce(sum(payout_cents) filter (where status='answered'),0)::int earned,coalesce(sum(payout_cents) filter (where status='answered' and payout_status in ('transferred','manual_paid')),0)::int paid,coalesce(sum(payout_cents) filter (where status='answered' and payout_status='unpaid'),0)::int owed,count(*) filter (where status='answered')::int answered,coalesce(sum(payout_cents) filter (where status='answered' and answered_at>=date_trunc('month',now())),0)::int this_month from consults where biologist_id=$1", [id]))[0];
  return c.json({ ...tot, avg: tot.answered ? Math.round(tot.earned / tot.answered) : 0, months: await q("select to_char(date_trunc('month',answered_at),'Mon YYYY') m,count(*)::int n,sum(payout_cents)::int cents from consults where biologist_id=$1 and status='answered' group by date_trunc('month',answered_at) order by date_trunc('month',answered_at) desc limit 12", [id]),
    list: await q("select c.id,c.kind,c.answered_at,c.answer_age,c.payout_cents,c.payout_status,c.payout_paid_at,b.name from consults c join bucks b on b.id=c.buck_id where c.biologist_id=$1 and c.status='answered' order by c.answered_at desc limit 200", [id]) }); });
B.get('/connect', async c => { const me = c.get('user'), st = await getStripe(); if (!st) return c.json({ configured: false }); if (!me.stripe_connect_id) return c.json({ configured: true, connected: false });
  try { const a = await st.accounts.retrieve(me.stripe_connect_id); if (a.payouts_enabled) { const n = (await q("select id from consults where biologist_id=$1 and status='answered' and payout_status='unpaid'", [me.id])); for (const r of n as any[]) await payoutConsult(r.id); } return c.json({ configured: true, connected: true, payouts_enabled: !!a.payouts_enabled, details_submitted: !!a.details_submitted }); } catch (e: any) { return c.json({ configured: true, connected: false, error: 'lookup_failed' }); } });
B.post('/connect', async c => { const me = c.get('user'), st = await getStripe(); if (!st) return c.json({ error: 'billing_not_configured' }, 503); const base = env.APP_URL || new URL(c.req.url).origin;
  try { let id = me.stripe_connect_id; if (!id) { const a = await st.accounts.create({ type: 'express', email: me.email, capabilities: { transfers: { requested: true } }, business_type: 'individual', metadata: { user_id: me.id } }); id = a.id; await q('update users set stripe_connect_id=$1 where id=$2', [id, me.id]); }
    const l = await st.accountLinks.create({ account: id, type: 'account_onboarding', refresh_url: `${base}/?bio=payout`, return_url: `${base}/?bio=payout` }); return c.json({ url: l.url }); }
  catch (e: any) { console.error('connect failed', e.message); return c.json({ error: /connect/i.test(e.message) ? 'connect_not_enabled' : 'billing_failed' }, 502); } });
B.put('/profile', async c => { const b = await c.req.json().catch(() => ({})); await q('update users set bio_title=$1 where id=$2', [String(b.title || '').slice(0, 80) || null, c.get('user').id]); return c.json({ ok: true }); });
app.route('/api/bio', B);
// ---------- admin API
const A = new Hono(); A.use('*', auth, admin);
const USERCOLS = 'id,email,first_name,last_name,address,city,state,zip,phone,role,status,plan_id,sub_status,cancel_at_end,period_end,lifetime_data,payout_pct,scans_used,email_verified_at,trial_start,created_at,stripe_customer';
A.get('/stats', async c => { const n = async (w: string) => (await q(`select count(*)::int n from users where email not like 'partner+%' ${w ? 'and ' + w.replace(/^where /, '') : ''}`))[0].n;
  const [m] = await q("select coalesce(sum(case when p.interval='month' then p.price_cents when p.interval='year' then p.price_cents/12.0 end),0)::int mrr from users u join plans p on p.id=u.plan_id where u.sub_status='active'");
  return c.json({ users: await n(''), trials: await n("where sub_status='trialing'"), subscribers: await n("where sub_status='active'"), comped: await n("where sub_status='comped'"), past_due: await n("where sub_status='past_due'"), unverified: await n('where email_verified_at is null'), scans: (await q('select count(*)::int n from scans'))[0].n, scans_7d: (await q("select count(*)::int n from scans where created_at>now()-interval '7 days'"))[0].n, flagged_rate: +(await q("select coalesce(avg((not (flags->>'usable')::bool)::int),0) r from scans"))[0].r, mrr_cents: m.mrr }); });
A.get('/drill/:kind', async c => { const k = c.req.param('kind'); const W: any = { users: '', trials: "where sub_status='trialing'", subscribers: "where sub_status='active'", comped: "where sub_status='comped'", past_due: "where sub_status='past_due'", unverified: 'where email_verified_at is null' };
  if (k === 'scans') return c.json(await q("select u.id,u.email,u.first_name,u.last_name,count(s.id)::int scans,count(*) filter (where not (s.flags->>'usable')::bool)::int flagged,max(s.created_at) last_scan from users u join scans s on s.user_id=u.id group by u.id order by scans desc limit 200"));
  if (!(k in W)) return c.json({ error: 'not_found' }, 404); return c.json(await q(`select ${USERCOLS} from users ${W[k]} order by created_at desc limit 500`)); });
A.post('/users', async c => { const b = await c.req.json(), email = String(b.email || '').trim().toLowerCase();
  if (!/^\S+@\S+\.\S+$/.test(email) || !String(b.first_name || '').trim() || !String(b.last_name || '').trim()) return c.json({ error: 'invalid_input' }, 400);
  if (b.password && String(b.password).length < 10) return c.json({ error: 'weak_password' }, 400);
  const pw = b.password ? String(b.password) : crypto.randomBytes(18).toString('hex');
  try { const [u] = await q("insert into users(email,pw,first_name,last_name,address,city,state,zip,phone,plan_id,sub_status,email_verified_at,role,bio_title) values($1,$2,$3,$4,$5,$6,$7,$8,$9,'free','comped',now(),$10,$11) returning *", [email, bcrypt.hashSync(pw, 12), ...FIELDS.map(f => String(b[f] || '').trim().slice(0, 120)), b.role === 'biologist' ? 'biologist' : 'user', b.role === 'biologist' ? String(b.title || '').trim().slice(0, 80) || null : null]);
    let link = null; if (!b.password) { link = await makeReset(u, 168); await mail(u.email, 'Your Deer Ager access', `<p>Hi ${eh(u.first_name)}, you've been given ${u.role === 'biologist' ? 'biologist access' : 'free access'} to Deer Ager. Set your password to get started.</p>${btn(link, 'Set your password')}`, 'invite'); }
    await audit(c.get('user').id, 'admin_create_user', { target: u.id }); return c.json({ ok: true, id: u.id, invite_link: link }); } catch { return c.json({ error: 'email_taken' }, 409); } });
A.post('/users/:id/grant', async c => { const { on } = await c.req.json(), id = c.req.param('id'), [u] = await q('select sub_status from users where id=$1', [id]); if (!u) return c.json({ error: 'not_found' }, 404);
  if (on) { if (['active', 'trialing'].includes(u.sub_status)) return c.json({ error: 'has_subscription' }, 409); await q("update users set plan_id='free',sub_status='comped' where id=$1", [id]); }
  else await q("update users set plan_id='trial',sub_status='none' where id=$1 and sub_status='comped'", [id]);
  await audit(c.get('user').id, on ? 'grant_free' : 'revoke_free', { target: id }); return c.json({ ok: true }); });
A.get('/scan-stats', async c => { const d = Math.min(Math.max(+(c.req.query('days') || 30), 1), 365), tz = 'America/Chicago';
  const days = await q(`select to_char(g.dy,'Mon DD') label,to_char(g.dy,'Dy') dow,to_char(g.dy,'YYYY-MM-DD') iso,coalesce(x.jaw,0)::int jaw,coalesce(x.deer,0)::int deer,coalesce(x.users,0)::int users from generate_series(((now() at time zone $2)::date - ($1::int-1)),(now() at time zone $2)::date,'1 day') g(dy) left join (select (created_at at time zone $2)::date as dy,count(*) filter (where mode='jaw') jaw,count(*) filter (where mode<>'jaw') deer,count(distinct user_id) users from scans where created_at>now()-(($1::int+1)||' days')::interval and (flags->>'pending') is distinct from 'true' group by 1) x on x.dy=g.dy::date order by g.dy`, [d, tz]);
  const users = await q(`select u.id,u.first_name,u.last_name,u.email,count(*)::int scans,count(*) filter (where s.mode='jaw')::int jaw,count(*) filter (where s.mode<>'jaw')::int deer,max(s.created_at) last_scan,count(distinct (s.created_at at time zone $2)::date)::int active_days from scans s join users u on u.id=s.user_id where s.created_at>now()-($1||' days')::interval and (s.flags->>'pending') is distinct from 'true' group by u.id order by scans desc,last_scan desc limit 200`, [String(d), tz]);
  const tot = days.reduce((a: any, x: any) => ({ jaw: a.jaw + x.jaw, deer: a.deer + x.deer }), { jaw: 0, deer: 0 }), total = tot.jaw + tot.deer, best = days.reduce((m: any, x: any) => (x.jaw + x.deer > (m ? m.jaw + m.deer : -1) ? x : m), null);
  return c.json({ days: d, tz, total, jaw: tot.jaw, deer: tot.deer, avg_per_day: Math.round(total / d * 10) / 10, active_users: users.length, best_day: best && best.jaw + best.deer ? { label: best.label, n: best.jaw + best.deer } : null,
    users: users.map((u: any) => ({ ...u, name: u.email.startsWith('partner+') ? 'Partner API' : `${u.first_name || ''} ${u.last_name || ''}`.trim() || u.email, email: u.email.startsWith('partner+') ? '' : u.email })), daily: days }); });
A.get('/analytics', async c => { const d = Math.min(Math.max(+(c.req.query('days') || 30), 1), 365), w = 'at>now()-($1||\' days\')::interval';
  const one = async (t: string) => (await q(t, [String(d)]))[0];
  return c.json({ days: d, views: (await one(`select count(*)::int n from visits where ${w}`)).n, visitors: (await one(`select count(distinct visitor)::int n from visits where ${w}`)).n,
    signups: (await one("select count(*)::int n from users where created_at>now()-($1||' days')::interval and role='user'")).n, converted: (await one("select count(*)::int n from users where created_at>now()-($1||' days')::interval and role='user' and sub_status in ('trialing','active')")).n,
    daily: await q(`select to_char(date_trunc('day',at),'Mon DD') as day,count(*)::int views,count(distinct visitor)::int visitors from visits where ${w} group by date_trunc('day',at) order by date_trunc('day',at)`, [String(d)]),
    sources: await q(`select coalesce(nullif(utm_source,''),nullif(ref,''),'direct') src,count(distinct visitor)::int visitors from visits where landing and ${w} group by 1 order by 2 desc limit 15`, [String(d)]),
    pages: await q(`select path,count(*)::int views from visits where ${w} group by 1 order by 2 desc limit 15`, [String(d)]),
    devices: await q(`select coalesce(device,'unknown') k,count(distinct visitor)::int n from visits where ${w} group by 1 order by 2 desc`, [String(d)]),
    countries: await q(`select country k,count(distinct visitor)::int n from visits where country is not null and ${w} group by 1 order by 2 desc limit 10`, [String(d)]) }); });
A.get('/system', async c => { const r: any = {}, ok = (v: boolean, note = '') => ({ ok: v, note });
  try { await q('select 1'); r.database = ok(true); } catch (e: any) { r.database = ok(false, e.message); }
  try { const k = `healthcheck/${Date.now()}`; await s3.write(k, 'ok', { type: 'text/plain' }); const back = await s3.file(k).text(); await s3.file(k).delete(); r.photo_storage = ok(back === 'ok', 'write, read and delete worked'); } catch (e: any) { r.photo_storage = ok(false, 'Check the S3_* variables: ' + String(e.message).slice(0, 120)); }
  r.app_url = ok(/^https:\/\//.test(env.APP_URL || ''), env.APP_URL || 'APP_URL is not set');
  r.stripe_secret_key = ok(!!(await getSetting('stripe_secret_key')), 'Add it in Settings'); r.stripe_webhook = ok(!!(await getSetting('stripe_webhook_secret')), 'Use "Create webhook automatically"');
  r.email_resend = ok(!!(await getSetting('resend_api_key')), 'Emails are only logged until a Resend key is added'); const m = configured(); r.ai_models = ok(m.length > 0, m.length ? m.join(', ') : 'Set an API key and MODEL_* id'); return c.json(r); });
A.get('/users', async c => c.json(await q(`select ${USERCOLS} from users where email not like 'partner+%' order by created_at desc limit 500`)));
A.get('/users/:id', async c => { const id = c.req.param('id'), [u] = await q(`select ${USERCOLS},prefs from users where id=$1`, [id]); if (!u) return c.json({ error: 'not_found' }, 404);
  return c.json({ user: u, scans: await q('select s.id,s.mode,s.class,s.confidence,s.flags,s.created_at,b.name buck from scans s left join bucks b on b.id=s.buck_id where s.user_id=$1 order by s.created_at desc limit 100', [id]), bucks: await q('select * from bucks where user_id=$1 order by created_at desc', [id]), emails: await q('select kind,subject,status,at from email_log where to_addr=(select email from users where id=$1) order by at desc limit 20', [id]) }); });
A.get('/scans/:id', async c => { const [s] = await q('select * from scans where id=$1', [c.req.param('id')]); if (!s) return c.json({ error: 'not_found' }, 404); const ph = await q('select s3_key from photos where scan_id=$1 order by slot', [s.id]);
  return c.json({ ...(await report(s, true)), notes: s.notes, photos: ph.map((p: any) => s3.file(p.s3_key).presign({ expiresIn: 3600 })) }); });
A.patch('/users/:id', async c => { const b = await c.req.json(), id = c.req.param('id'); await q('update users set status=coalesce($1,status),role=coalesce($2,role),lifetime_data=coalesce($3,lifetime_data) where id=$4', [b.status, b.role, b.lifetime_data, id]); if ('payout_pct' in b) { const v = b.payout_pct === null || b.payout_pct === '' ? null : Math.max(0, Math.min(100, Math.round(+b.payout_pct))); await q('update users set payout_pct=$1 where id=$2', [Number.isFinite(v as number) ? v : null, id]); } await audit(c.get('user').id, 'user_update', { target: id, ...b }); return c.json({ ok: true }); });
A.post('/users/:id/reset', async c => { const [u] = await q('select * from users where id=$1', [c.req.param('id')]); if (!u) return c.json({ error: 'not_found' }, 404); const st = await sendReset(u); await audit(c.get('user').id, 'admin_password_reset', { target: u.id }); return c.json({ ok: true, email: st }); });
A.post('/users/:id/verify', async c => { const [u] = await q('select * from users where id=$1', [c.req.param('id')]); if (!u) return c.json({ error: 'not_found' }, 404); const st = await sendVerify(u); return c.json({ ok: true, email: st }); });
A.get('/plans', async c => c.json(await q("select p.*,(select count(*)::int from users where plan_id=p.id) users from plans p where p.id not in ('free','lapsed') order by (p.interval='none') desc, (case when p.interval='year' then p.price_cents/12.0 else p.price_cents end), p.created_at nulls first")));
A.post('/plans', async c => { const b = await c.req.json(), name = String(b.name || '').trim().slice(0, 60), price = Math.round(+b.price_cents), iv = b.interval === 'year' ? 'year' : 'month';
  if (!name || !Number.isFinite(price) || price < 50 || price > 1000000) return c.json({ error: 'invalid_input' }, 400);
  const id = 'p_' + crypto.randomBytes(4).toString('hex'); await q('insert into plans(id,name,price_cents,interval,active) values($1,$2,$3,$4,true)', [id, name, price, iv]); await audit(c.get('user').id, 'plan_create', { plan: id, name, price }); return c.json({ id }); });
// remove a plan: deleted outright when nobody is on it, otherwise taken off sale (existing subscribers keep it until they cancel)
A.delete('/plans/:id', async c => { const id = c.req.param('id'); if (['trial', 'free', 'lapsed'].includes(id)) return c.json({ error: 'protected_plan' }, 400);
  const [pl] = await q('select * from plans where id=$1', [id]); if (!pl) return c.json({ error: 'not_found' }, 404);
  if (pl.active && !(await q("select 1 from plans where active and interval in ('month','year') and id<>$1", [id])).length) return c.json({ error: 'last_plan' }, 400);
  const [{ n }] = await q('select count(*)::int n from users where plan_id=$1', [id]);
  if (n) { await q('update plans set active=false where id=$1', [id]); await audit(c.get('user').id, 'plan_retire', { plan: id, users: n }); return c.json({ ok: true, retired: true, users: n }); }
  await q('delete from plans where id=$1', [id]); await audit(c.get('user').id, 'plan_delete', { plan: id }); return c.json({ ok: true, deleted: true }); });
A.put('/plans/:id', async c => { const b = await c.req.json(); if (b.active === false) { if (c.req.param('id') === 'trial') return c.json({ error: 'protected_plan' }, 400); if (!(await q("select 1 from plans where active and interval in ('month','year') and id<>$1", [c.req.param('id')])).length) return c.json({ error: 'last_plan' }, 400); } await q('update plans set name=coalesce($1,name),price_cents=coalesce($2,price_cents),trial_days=coalesce($3,trial_days),trial_scans=coalesce($4,trial_scans),stripe_price_id=case when $2::int is not null and $2::int<>price_cents and $5::text is null then null else coalesce($5::text,stripe_price_id) end,active=coalesce($6,active) where id=$7', [b.name, b.price_cents, b.trial_days, b.trial_scans, b.stripe_price_id, b.active, c.req.param('id')]); await audit(c.get('user').id, 'plan_update', { plan: c.req.param('id'), ...b }); return c.json({ ok: true }); });
A.get('/settings', async c => { const o: any = {}; for (const k of SETTING_KEYS) { const v = await getSetting(k); o[k] = !v ? '' : SECRETS.includes(k) ? '\u2022\u2022\u2022\u2022' + v.slice(-4) : v; } return c.json(o); });
A.put('/settings', async c => { const b = await c.req.json(), ok: any = { stripe_publishable_key: /^pk_(test|live)_/, stripe_secret_key: /^(sk|rk)_(test|live)_/, stripe_webhook_secret: /^whsec_/, resend_api_key: /^re_/, mail_from: /^.{3,120}$/, compare_all: /^(true|false)$/, analysis_samples: /^[1-5]$/ };
  for (const [k, re] of Object.entries(ok) as any) if (b[k] != null && b[k] !== '') { if (!re.test(b[k])) return c.json({ error: 'bad_' + k }, 400); await setSetting(k, b[k], c.get('user').id); await audit(c.get('user').id, 'setting_update', { key: k }); } return c.json({ ok: true }); });
A.post('/email/test', async c => { const { to } = await c.req.json(); if (!/^\S+@\S+\.\S+$/.test(to || '')) return c.json({ error: 'invalid_input' }, 400); return c.json({ ok: true, status: await mail(to, 'Deer Ager test email', '<p>Email delivery is working.</p>', 'test') }); });
A.post('/stripe/test', async c => { const st = await getStripe(); if (!st) return c.json({ error: 'no_secret_key' }, 400); try { return c.json({ ok: true, livemode: (await st.balance.retrieve()).livemode }); } catch (e: any) { return c.json({ error: e.message }, 400); } });
A.post('/stripe/webhook', async c => { const st = await getStripe(); if (!st) return c.json({ error: 'no_secret_key' }, 400);
  try { const w = await st.webhookEndpoints.create({ url: env.APP_URL + '/api/webhooks/stripe', enabled_events: ['checkout.session.completed', 'customer.subscription.created', 'customer.subscription.updated', 'customer.subscription.deleted', 'invoice.payment_failed'] }); await setSetting('stripe_webhook_secret', w.secret!, c.get('user').id); await audit(c.get('user').id, 'webhook_created', { id: w.id }); return c.json({ ok: true, url: w.url }); } catch (e: any) { return c.json({ error: e.message }, 400); } });
A.get('/tdrill', async c => { const d = String(Math.min(Math.max(+(c.req.query('days') || 30), 1), 365)), kind = c.req.query('kind') || 'views', val = c.req.query('value') || '';
  const base = `with v as (select at,path,coalesce(nullif(utm_source,''),nullif(ref,''),'direct') src,visitor,device,country,landing,lag(path) over (partition by visitor order by at) prev_path,lead(path) over (partition by visitor order by at) next_path from visits where at>now()-($1||' days')::interval)`;
  const visitors = async (where: string, p: any[]) => q(`${base}, f as (select * from v ${where}) select left(visitor,6) vid,min(at) first_seen,max(at) last_seen,count(*)::int views,(array_agg(src order by at))[1] source,(array_agg(device order by at))[1] device,(array_agg(country order by at))[1] country,string_agg(path,' > ' order by at) journey from f group by visitor order by max(at) desc limit 300`, p);
  if (kind === 'visitors') return c.json({ mode: 'visitors', title: 'All visitors', rows: await visitors('', [d]) });
  if (kind === 'source') return c.json({ mode: 'visitors', title: 'Visitors from ' + val, rows: await visitors('where visitor in (select visitor from v where landing and src=$2)', [d, val]) });
  if (kind === 'device') return c.json({ mode: 'visitors', title: 'Visitors on ' + val, rows: await visitors('where visitor in (select visitor from v where device=$2)', [d, val]) });
  if (kind === 'country') return c.json({ mode: 'visitors', title: 'Visitors from ' + val, rows: await visitors('where visitor in (select visitor from v where country=$2)', [d, val]) });
  if (kind === 'day') return c.json({ mode: 'visitors', title: 'Visitors on ' + val, rows: await visitors("where visitor in (select visitor from v where to_char(date_trunc('day',at),'Mon DD')=$2)", [d, val]) });
  const where = kind === 'path' ? 'where path=$2' : '', p = kind === 'path' ? [d, val] : [d];
  const rows = await q(`${base} select at,path,src,prev_path,next_path,device,country,left(visitor,6) vid from v ${where} order by at desc limit 300`, p);
  const out: any = { mode: 'views', title: kind === 'path' ? 'Page: ' + val : 'All page views', rows };
  if (kind === 'path') { out.came_from = await q(`${base} select coalesce(prev_path,'From '||src) k,count(*)::int n from v ${where} group by 1 order by 2 desc limit 10`, p); out.went_to = await q(`${base} select coalesce(next_path,'Left the site') k,count(*)::int n from v ${where} group by 1 order by 2 desc limit 10`, p); }
  return c.json(out); });
A.get('/models/overview', async c => {
  const tr = "coalesce(s.truth_age,s.user_age)", num = (x: string) => `replace(${x},'+','')::numeric`, best = "r.result->'dist'->>'best'";
  const recent = await q("select s.id,s.created_at,s.class,s.range,s.confidence,s.truth_age,s.user_age,s.approval,u.first_name,u.last_name,s.observations->'dist'->>'best' best,(select json_agg(json_build_object('p',r.provider,'age',r.result->'dist'->>'best','conf',r.confidence,'err',r.error,'wear',r.result->>'molar_wear') order by r.provider) from model_runs r where r.scan_id=s.id and r.truth_class is null) runs from scans s join users u on u.id=s.user_id where s.mode='jaw' and (s.class is not null or s.flags->>'pending' is null) and u.email not like 'partner+%' order by s.created_at desc limit 60");
  return c.json({
    providers: Object.keys(PROV).map(p => ({ provider: p, key: !!env[KEYS[p]], model: env['MODEL_' + p.toUpperCase()] || null, on: configured().includes(p) })), mock: !!env.MOCK_MODELS, compare_all: (await getSetting('compare_all')) !== 'false', primary: env.PRIMARY_MODEL || null,
    usage: await q("select provider,model,count(*)::int runs,count(*) filter (where error is not null)::int errors,count(*) filter (where class is null and error is null)::int unclear,round(avg(confidence))::int avg_conf,round(avg(latency_ms))::int ms,round((percentile_cont(0.5) within group (order by latency_ms))::numeric)::int p50,round((percentile_cont(0.95) within group (order by latency_ms))::numeric)::int p95,max(created_at) last_run from model_runs where truth_class is null group by 1,2 order by 3 desc"),
    errors: await q("select provider,model,left(error,300) error,created_at,scan_id from model_runs where error is not null and truth_class is null order by created_at desc limit 15"),
    daily: await q("select to_char(date_trunc('day',created_at),'Mon DD') d,provider,count(*)::int runs,count(*) filter (where error is not null)::int errors from model_runs where truth_class is null and created_at>now()-interval '14 days' group by date_trunc('day',created_at),provider order by date_trunc('day',created_at) desc,provider"),
    graded: await q(`select r.provider,count(*)::int n,round(avg((${best}=${tr})::int)*100)::int exact,round(avg((abs(${num(best)}-${num(tr)})<=1)::int)*100)::int within1,round(avg(${num(best)}-${num(tr)}),2) bias,round(avg(abs(${num(best)}-${num(tr)})),2) mae,count(*) filter (where s.truth_age is null)::int hunter_n from model_runs r join scans s on s.id=r.scan_id where ${tr} is not null and r.truth_class is null and ${best} is not null group by 1 order by 1`),
    by_age: await q(`select r.provider,${tr} truth,count(*)::int n,round(avg(${num(best)}),1) avg_guess,round(avg((${best}=${tr})::int)*100)::int exact from model_runs r join scans s on s.id=r.scan_id where ${tr} is not null and r.truth_class is null and ${best} is not null group by 1,2 order by 2,1`),
    approval: { total: (await q("select count(*)::int n,count(*) filter (where approval is not null)::int answered,count(*) filter (where approval='right')::int right_n,count(*) filter (where approval='too_young')::int too_young,count(*) filter (where approval='too_old')::int too_old,count(*) filter (where approval='unsure')::int unsure from scans where mode='jaw' and class is not null and (ext is null)"))[0],
      weekly: await q("select to_char(date_trunc('week',approval_at),'Mon DD') wk,count(*)::int n,count(*) filter (where approval='right')::int right_n from scans where approval is not null and mode='jaw' group by date_trunc('week',approval_at) order by date_trunc('week',approval_at) desc limit 8"),
      by_result: await q("select coalesce(observations->'dist'->>'best',class) age,count(*)::int n,count(*) filter (where approval='right')::int right_n,count(*) filter (where approval='too_young')::int too_young,count(*) filter (where approval='too_old')::int too_old from scans where approval is not null and mode='jaw' group by 1 order by 1"),
      rejected: await q("select s.id,s.approval_at,s.approval,s.user_age,s.truth_age,s.observations->'dist'->>'best' best,s.confidence,u.first_name,u.last_name from scans s join users u on u.id=s.user_id where s.approval in ('too_young','too_old') and s.mode='jaw' order by s.approval_at desc limit 25") },
    breakers: Object.entries(BREAKER).filter(([, v]: any) => v.until > Date.now()).map(([p, v]: any) => ({ provider: p, reason: v.reason, since: v.since, retry_at: new Date(v.until).toISOString() })),
    scans: recent, wear: await q(`select r.result->>'molar_wear' wear,${tr} truth,count(*)::int n from model_runs r join scans s on s.id=r.scan_id where ${tr} is not null and r.truth_class is null and r.result->>'molar_wear' is not null group by 1,2 order by 1,2`) }); });
const RERUN: any = { running: false, total: 0, done: 0, failed: 0, current: '', started: null, finished: null };
A.get('/rerun-all', async c => c.json(RERUN));
A.post('/rerun-all', async c => { if (RERUN.running) return c.json({ error: 'already_running', ...RERUN }, 409);
  const recalc = await recalcAll().catch(() => ({ scans: 0, runs: 0 }));
  const deer = await q("select b.id,b.name,b.user_id from bucks b where exists(select 1 from scans s where s.buck_id=b.id and s.mode='jaw' and s.flags->>'pending' is null) and not exists(select 1 from scans s where s.buck_id=b.id and s.rollup and s.created_at>now()-interval '1 hour') order by b.created_at");
  Object.assign(RERUN, { running: true, total: deer.length, done: 0, failed: 0, current: '', started: new Date().toISOString(), finished: null });
  (async () => { for (const d of deer as any[]) { RERUN.current = d.name; try { const [u] = await q('select * from users where id=$1', [d.user_id]); const r: any = await rollupBuck(u, d.id); if (r.error) RERUN.failed++; } catch (e: any) { console.error('rerun-all', d.name, e.message); RERUN.failed++; } RERUN.done++; }
    RERUN.running = false; RERUN.current = ''; RERUN.finished = new Date().toISOString(); })();
  return c.json({ ok: true, total: deer.length, updated_reports: recalc.scans }); });
A.get('/costs', async c => { const days = Math.min(Math.max(+(c.req.query('days') || 30), 1), 365), pr = await prices(), stGb = +((await getSetting('cost_storage_gb')) || 0.015), budget = +((await getSetting('cost_budget')) || 0);
  const used = await q("select distinct model from model_runs where model is not null"); const priced: any = {}; for (const m of used as any[]) priced[m.model] = pr[m.model] || null;
  const tot = (await q("select count(*)::int runs,count(*) filter (where cost_usd is not null)::int tracked,count(distinct scan_id)::int scans,coalesce(sum(cost_usd),0)::float cost,coalesce(sum(in_tokens),0)::bigint in_tok,coalesce(sum(out_tokens),0)::bigint out_tok from model_runs where truth_class is null and created_at>now()-($1||' days')::interval", [String(days)]))[0];
  const trk = (await q("select count(distinct scan_id)::int scans,coalesce(sum(cost_usd),0)::float cost from model_runs where truth_class is null and cost_usd is not null and created_at>now()-($1||' days')::interval", [String(days)]))[0];
  const mtd = (await q("select coalesce(sum(cost_usd),0)::float cost from model_runs where truth_class is null and created_at>=date_trunc('month',now())"))[0].cost, now = new Date(), dim = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
  const bytes = (await q("select coalesce(sum(b),0)::float bytes,count(*)::int files from (select distinct s3_key,bytes b from (select p.s3_key,p.bytes from photos p union all select s3_key,bytes from buck_photos) x) y"))[0];
  const users = await q(`select u.id,u.email,u.first_name,u.last_name,u.plan_id,u.sub_status,coalesce(pl.price_cents,0) price_cents,pl.interval,
      coalesce((select count(distinct r.scan_id) from model_runs r join scans s on s.id=r.scan_id where s.user_id=u.id and r.truth_class is null and r.created_at>now()-($1||' days')::interval),0)::int scans,
      coalesce((select sum(r.cost_usd) from model_runs r join scans s on s.id=r.scan_id where s.user_id=u.id and r.truth_class is null and r.created_at>now()-($1||' days')::interval),0)::float ai_cost,
      coalesce((select sum(b) from (select distinct s3_key,bytes b from (select p.s3_key,p.bytes from photos p join scans s on s.id=p.scan_id where s.user_id=u.id union all select bp.s3_key,bp.bytes from buck_photos bp join bucks k on k.id=bp.buck_id where k.user_id=u.id) x) y),0)::float bytes
      from users u left join plans pl on pl.id=u.plan_id where u.role<>'admin' and u.email not like 'partner+%' order by 11 desc limit 200`, [String(days)]);
  return c.json({ days, prices: pr, priced, storage_gb: stGb, budget, totals: tot, tracked: trk, mtd, projected: Math.round((mtd / Math.max(1, now.getDate())) * dim * 100) / 100,
    by_model: await q("select provider,model,count(*)::int runs,coalesce(sum(in_tokens),0)::bigint in_tok,coalesce(sum(out_tokens),0)::bigint out_tok,coalesce(sum(cost_usd),0)::float cost,round(avg(cost_usd)::numeric,4)::float avg_cost from model_runs where truth_class is null and created_at>now()-($1||' days')::interval group by 1,2 order by cost desc nulls last", [String(days)]),
    daily: await q("select to_char(date_trunc('day',created_at),'Mon DD') d,count(*)::int runs,coalesce(sum(cost_usd),0)::float cost from model_runs where truth_class is null and created_at>now()-interval '14 days' group by date_trunc('day',created_at) order by date_trunc('day',created_at) desc"),
    storage: { bytes: bytes.bytes, files: bytes.files, gb: bytes.bytes / 1e9, monthly_cost: (bytes.bytes / 1e9) * stGb }, users });
});
A.put('/costs/settings', async c => { const b = await c.req.json().catch(() => ({}));
  if (b.prices) { const o: any = {}; for (const [m, v] of Object.entries(b.prices) as any) { const i = +v?.in, t = +v?.out; if (!/^[\w.\-]{2,80}$/.test(m) || !(i >= 0) || !(t >= 0) || i > 1000 || t > 1000) return c.json({ error: 'invalid_input' }, 400); o[m] = { in: i, out: t }; } await setSetting('cost_prices', JSON.stringify(o), c.get('user').id); }
  if (b.storage_gb != null) { const v = +b.storage_gb; if (!(v >= 0) || v > 10) return c.json({ error: 'invalid_input' }, 400); await setSetting('cost_storage_gb', String(v), c.get('user').id); }
  if (b.budget != null) { const v = +b.budget; if (!(v >= 0) || v > 1e6) return c.json({ error: 'invalid_input' }, 400); await setSetting('cost_budget', String(v), c.get('user').id); }
  await audit(c.get('user').id, 'cost_settings', {}); return c.json({ ok: true }); });
// Live check from the server itself: is the key valid, does the configured model answer, and which models does each key actually offer?
A.post('/models/test', async c => { const out: any[] = [], pr = await prices();
  const tests: any = {
    claude: { list: async () => (await (await fetch('https://api.anthropic.com/v1/models?limit=100', { headers: { 'x-api-key': env.ANTHROPIC_API_KEY!, 'anthropic-version': '2023-06-01' }, signal: AbortSignal.timeout(20000) })).json()).data?.map((m: any) => m.id) || [],
      ping: () => post('https://api.anthropic.com/v1/messages', { 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' }, { model: env.MODEL_CLAUDE, max_tokens: 16, messages: [{ role: 'user', content: 'Reply with OK' }] }) },
    openai: { list: async () => ((await (await fetch('https://api.openai.com/v1/models', { headers: { authorization: 'Bearer ' + env.OPENAI_API_KEY }, signal: AbortSignal.timeout(20000) })).json()).data || []).map((m: any) => m.id),
      ping: () => post('https://api.openai.com/v1/chat/completions', { authorization: 'Bearer ' + env.OPENAI_API_KEY }, { model: env.MODEL_OPENAI, messages: [{ role: 'user', content: 'Reply with OK' }] }) },
    gemini: { list: async () => ((await (await fetch('https://generativelanguage.googleapis.com/v1beta/models?pageSize=200', { headers: { 'x-goog-api-key': env.GEMINI_API_KEY! }, signal: AbortSignal.timeout(20000) })).json()).models || []).map((m: any) => String(m.name).replace('models/', '')),
      ping: () => post(`https://generativelanguage.googleapis.com/v1beta/models/${env.MODEL_GEMINI}:generateContent`, { 'x-goog-api-key': env.GEMINI_API_KEY }, { contents: [{ parts: [{ text: 'Reply with OK' }] }] }) } };
  await Promise.all(Object.keys(PROV).map(async p => { const model = env['MODEL_' + p.toUpperCase()] || null, r: any = { provider: p, model, key: !!env[KEYS[p]] }; out.push(r);
    if (env.MOCK_MODELS) { r.ok = true; r.mock = true; r.models = ['mock-' + p]; r.in_list = true; return; } if (!r.key || !model) { r.error = !r.key ? 'No API key set' : 'No model name set'; return; }
    try { r.models = ((await tests[p].list()) as string[]).sort(); r.in_list = r.models.includes(model); } catch (e: any) { r.list_error = String(e.message || e).slice(0, 160); }
    const box: any = {}, t = Date.now(); try { await usageBox.run(box, () => tests[p].ping()); r.ok = true; r.ms = Date.now() - t; r.in_tokens = box.inTok || 0; r.out_tokens = box.outTok || 0; r.cost = runCost(pr, model, r.in_tokens, r.out_tokens); } catch (e: any) { r.ok = false; r.error = String(e.message || e).slice(0, 300); } }));
  out.sort((a, b) => a.provider.localeCompare(b.provider)); return c.json(out); });
A.post('/scans/:id/truth', async c => { const { truth_age } = await c.req.json().catch(() => ({})); if (truth_age && !AGES.includes(truth_age)) return c.json({ error: 'invalid_input' }, 400);
  await q('update scans set truth_age=$1 where id=$2', [truth_age || null, c.req.param('id')]); return c.json({ ok: true }); });
A.post('/benchmark/:scanId', async c => { const { truth_class } = await c.req.json().catch(() => ({})); const [s] = await q('select * from scans where id=$1', [c.req.param('scanId')]); if (!s) return c.json({ error: 'not_found' }, 404);
  const imgs = await Promise.all((await q('select s3_key from photos where scan_id=$1 order by slot', [s.id])).map(async (p: any) => ({ mime: 'image/jpeg', b64: Buffer.from(await s3.file(p.s3_key).arrayBuffer()).toString('base64') })));
  const out = await Promise.all(configured().map(p => runModel(p, imgs, s.mode)));
  for (const r of out as any[]) await q('insert into model_runs(scan_id,provider,model,result,class,confidence,latency_ms,error,truth_class) values($1,$2,$3,$4,$5,$6,$7,$8,$9)', [s.id, r.provider, r.model, r.result || null, r.result ? classify(r.result).cls : null, r.result ? conf(r.result, s.mode) : null, r.ms, r.error || null, truth_class || 'unlabeled']); return c.json(out); });
A.get('/benchmark/summary', async c => c.json(await q("select provider,count(*)::int n,round(avg((class=truth_class)::int)*100) exact_pct,round(avg(latency_ms)) ms from model_runs where truth_class is not null and truth_class<>'unlabeled' and error is null group by 1")));
A.get('/audit', async c => c.json(await q('select * from audit order by at desc limit 200')));
const newKey = () => 'dk_live_' + crypto.randomBytes(24).toString('hex');
A.get('/partners', async c => c.json(await Promise.all((await q('select id,name,key_prefix,webhook_url,monthly_limit,active,created_at,(select count(*)::int from scans where partner_id=partners.id) total from partners order by created_at desc')).map(async (p: any) => ({ ...p, used: await monthUsed(p) })))));
A.post('/partners', async c => { const b = await c.req.json(), name = String(b.name || '').trim().slice(0, 80); if (!name) return c.json({ error: 'invalid_input' }, 400);
  const wh = b.webhook_url ? String(b.webhook_url).trim() : null; if (wh && !/^https:\/\/\S+$/.test(wh)) return c.json({ error: 'invalid_webhook' }, 400);
  const [u] = await q("insert into users(email,pw,first_name,last_name,plan_id,sub_status,email_verified_at) values($1,$2,$3,'(Partner API)','free','comped',now()) returning id", [`partner+${crypto.randomUUID()}@partners.deerager.com`, bcrypt.hashSync(crypto.randomBytes(24).toString('hex'), 10), name.slice(0, 60)]);
  const key = newKey(), secret = 'whsec_' + crypto.randomBytes(20).toString('hex'); const [p] = await q('insert into partners(name,key_hash,key_prefix,user_id,webhook_url,webhook_secret,monthly_limit) values($1,$2,$3,$4,$5,$6,$7) returning id', [name, sha(key), key.slice(0, 12), u.id, wh, secret, Math.max(0, Math.min(+b.monthly_limit || 0, 1e6))]);
  await audit(c.get('user').id, 'partner_create', { name }); return c.json({ id: p.id, key, webhook_secret: secret }); });
A.put('/partners/:id', async c => { const b = await c.req.json(), wh = b.webhook_url ? String(b.webhook_url).trim() : null; if (wh && !/^https:\/\/\S+$/.test(wh)) return c.json({ error: 'invalid_webhook' }, 400);
  await q('update partners set name=coalesce($1,name),webhook_url=$2,monthly_limit=coalesce($3,monthly_limit),active=coalesce($4,active) where id=$5', [b.name ? String(b.name).slice(0, 80) : null, wh, b.monthly_limit == null ? null : Math.max(0, Math.min(+b.monthly_limit || 0, 1e6)), typeof b.active === 'boolean' ? b.active : null, c.req.param('id')]); await audit(c.get('user').id, 'partner_update', { partner: c.req.param('id') }); return c.json({ ok: true }); });
A.post('/partners/:id/rotate', async c => { const key = newKey(); const r = await q('update partners set key_hash=$1,key_prefix=$2 where id=$3 returning id', [sha(key), key.slice(0, 12), c.req.param('id')]); if (!r.length) return c.json({ error: 'not_found' }, 404); await audit(c.get('user').id, 'partner_rotate', { partner: c.req.param('id') }); return c.json({ key }); });
A.get('/consults', async c => { const cfg = await consultCfg();
  const rows = await q("select c.id,c.kind,c.status,c.price_cents,c.payout_pct,c.payout_cents,c.payout_status,c.created_at,c.paid_at,c.claimed_at,c.answered_at,c.answer_age,c.refunded_at,c.transfer_id,b.name deer,h.email hunter,bu.id bio_id,bu.email bio_email,bu.first_name||' '||bu.last_name bio_name,bu.stripe_connect_id is not null connected from consults c join bucks b on b.id=c.buck_id join users h on h.id=c.hunter_id left join users bu on bu.id=c.biologist_id where c.status<>'pending_payment' order by c.created_at desc limit 300");
  const t = (await q("select coalesce(sum(price_cents) filter (where status in ('open','claimed','needs_info','answered')),0)::int revenue,coalesce(sum(payout_cents) filter (where status='answered'),0)::int owed_total,coalesce(sum(payout_cents) filter (where status='answered' and payout_status in ('transferred','manual_paid')),0)::int paid_out,coalesce(sum(payout_cents) filter (where status='answered' and payout_status='unpaid'),0)::int unpaid,count(*) filter (where status='open')::int open_n,count(*) filter (where status in ('claimed','needs_info'))::int active_n,count(*) filter (where status='answered')::int answered_n from consults"))[0];
  const bios = await q("select u.id,u.email,u.first_name,u.last_name,u.status,u.payout_pct,u.bio_title,u.stripe_connect_id is not null connected,(select count(*)::int from consults x where x.biologist_id=u.id and x.status='answered') answered,(select coalesce(sum(payout_cents),0)::int from consults x where x.biologist_id=u.id and x.status='answered' and x.payout_status='unpaid') unpaid from users u where u.role='biologist' order by u.created_at");
  return c.json({ settings: cfg, totals: { ...t, platform_net: t.revenue - t.owed_total }, rows, biologists: bios }); });
A.put('/consults/settings', async c => { const b = await c.req.json(), set = async (k: string, v: any, lo: number, hi: number) => { if (v == null || v === '') return; const n = Math.round(+v); if (!Number.isFinite(n) || n < lo || n > hi) throw new Error('bad ' + k); await setSetting(k, String(n)); };
  try { await set('consult_price_cents', b.consult_price_cents, 100, 100000); await set('age_price_cents', b.age_price_cents, 100, 100000); await set('consult_payout_pct', b.payout_pct, 0, 100); await set('consult_sla_hours', b.sla_hours, 1, 720); } catch { return c.json({ error: 'invalid_input' }, 400); }
  await audit(c.get('user').id, 'consult_settings', b); return c.json({ ok: true, settings: await consultCfg() }); });
A.post('/consults/:id/mark-paid', async c => { const [x] = await q("update consults set payout_status='manual_paid',payout_paid_at=now() where id=$1 and status='answered' and payout_status='unpaid' returning id", [c.req.param('id')]); if (!x) return c.json({ error: 'not_found' }, 404); await audit(c.get('user').id, 'consult_mark_paid', { id: x.id }); return c.json({ ok: true }); });
A.post('/consults/:id/pay-out', async c => { const ok = await payoutConsult(c.req.param('id')); return c.json(ok ? { ok: true } : { error: 'payout_unavailable' }, ok ? 200 : 409); });
A.post('/consults/:id/refund', async c => { const [x] = await q("select * from consults where id=$1 and status in ('open','claimed','needs_info','answered')", [c.req.param('id')]); if (!x) return c.json({ error: 'not_found' }, 404);
  const st = await getStripe(); if (!st || !x.payment_intent) return c.json({ error: 'billing_not_configured' }, 503);
  try { await st.refunds.create({ payment_intent: x.payment_intent, ...(x.payout_status === 'transferred' ? { reverse_transfer: true } : {}) }, { idempotencyKey: 'consult-refund-' + x.id }); } catch (e: any) { console.error('refund failed', e.message); return c.json({ error: 'refund_failed' }, 502); }
  await q("update consults set status='refunded',refunded_at=now(),payout_status=case when payout_status='transferred' then 'reversed' else 'none' end where id=$1", [x.id]); await q('delete from buck_shares where buck_id=$1 and to_user=$2', [x.buck_id, x.biologist_id]).catch(() => {});
  await audit(c.get('user').id, 'consult_refund', { id: x.id }); return c.json({ ok: true }); });
// ---- manage biologists
const releaseActive = async (bioId: string) => { const rows = await q("update consults set status='open',biologist_id=null,claimed_at=null where biologist_id=$1 and status in ('claimed','needs_info') returning buck_id", [bioId]); for (const r of rows as any[]) await q('delete from buck_shares where buck_id=$1 and to_user=$2', [r.buck_id, bioId]); return rows.length; };
A.post('/biologists', async c => { const b = await c.req.json().catch(() => ({})), email = String(b.email || '').trim().toLowerCase();
  if (!/^\S+@\S+\.\S+$/.test(email)) return c.json({ error: 'invalid_input' }, 400);
  const [ex] = await q('select id,role from users where email=$1', [email]);
  if (ex) { if (ex.role === 'admin') return c.json({ error: 'invalid_input' }, 400); await q("update users set role='biologist',status='active' where id=$1", [ex.id]); await audit(c.get('user').id, 'biologist_add', { target: ex.id }); return c.json({ ok: true, id: ex.id, existing: true }); }
  if (!String(b.first_name || '').trim() || !String(b.last_name || '').trim()) return c.json({ error: 'invalid_input' }, 400);
  const [u] = await q("insert into users(email,pw,first_name,last_name,role,plan_id,sub_status,email_verified_at,bio_title) values($1,$2,$3,$4,'biologist','free','comped',now(),$5) returning *", [email, bcrypt.hashSync(crypto.randomBytes(18).toString('hex'), 12), String(b.first_name).trim().slice(0, 60), String(b.last_name).trim().slice(0, 60), String(b.title || '').trim().slice(0, 80) || null]);
  const link = await makeReset(u, 168); await mail(u.email, 'You are invited to Deer Ager as a biologist', `<p>Hi ${eh(u.first_name)}, you have been set up as a biologist on Deer Ager. Set your password, then open the Biologist tab to see consults and set up your payouts.</p>${btn(link, 'Set your password')}`, 'invite');
  await audit(c.get('user').id, 'biologist_invite', { target: u.id }); return c.json({ ok: true, id: u.id, invite_link: link }); });
A.get('/biologists/:id', async c => { const id = c.req.param('id'), [u] = await q("select id,email,first_name,last_name,status,payout_pct,bio_title,stripe_connect_id is not null connected,created_at from users where id=$1 and role='biologist'", [id]); if (!u) return c.json({ error: 'not_found' }, 404);
  const t = (await q("select count(*) filter (where status='answered')::int answered,count(*) filter (where status in ('claimed','needs_info'))::int active,coalesce(sum(payout_cents) filter (where status='answered'),0)::int earned,coalesce(sum(payout_cents) filter (where status='answered' and payout_status in ('transferred','manual_paid')),0)::int paid,coalesce(sum(payout_cents) filter (where status='answered' and payout_status='unpaid'),0)::int owed,avg(extract(epoch from (answered_at-claimed_at))/3600) filter (where status='answered') avg_hours from consults where biologist_id=$1", [id]))[0];
  let payouts_enabled = null; if (u.connected) { try { const st = await getStripe(), me = (await q('select stripe_connect_id from users where id=$1', [id]))[0]; if (st) payouts_enabled = !!(await st.accounts.retrieve(me.stripe_connect_id)).payouts_enabled; } catch {} }
  return c.json({ ...u, payouts_enabled, totals: { ...t, avg_hours: t.avg_hours == null ? null : Math.round(+t.avg_hours * 10) / 10 }, consults: await q("select c.id,c.kind,c.status,c.answer_age,c.payout_cents,c.payout_status,c.claimed_at,c.answered_at,b.name deer from consults c join bucks b on b.id=c.buck_id where c.biologist_id=$1 order by coalesce(c.answered_at,c.claimed_at) desc limit 200", [id]) }); });
A.put('/biologists/:id/title', async c => { const t = String((await c.req.json().catch(() => ({}))).title || '').trim().slice(0, 80) || null; const [u] = await q("update users set bio_title=$1 where id=$2 and role='biologist' returning id", [t, c.req.param('id')]); return u ? c.json({ ok: true }) : c.json({ error: 'not_found' }, 404); });
A.post('/biologists/:id/status', async c => { const id = c.req.param('id'), on = !!(await c.req.json().catch(() => ({}))).active; const [u] = await q("update users set status=$1 where id=$2 and role='biologist' returning id", [on ? 'active' : 'suspended', id]); if (!u) return c.json({ error: 'not_found' }, 404);
  const released = on ? 0 : await releaseActive(id); await audit(c.get('user').id, on ? 'biologist_activate' : 'biologist_suspend', { target: id, released }); return c.json({ ok: true, released }); });
A.post('/biologists/:id/remove', async c => { const id = c.req.param('id'), [u] = await q("update users set role='user' where id=$1 and role='biologist' returning id", [id]); if (!u) return c.json({ error: 'not_found' }, 404); const released = await releaseActive(id); await audit(c.get('user').id, 'biologist_remove', { target: id, released }); return c.json({ ok: true, released }); });
A.post('/biologists/:id/pay-all', async c => { const id = c.req.param('id'), rows = await q("select id from consults where biologist_id=$1 and status='answered' and payout_status='unpaid'", [id]); let n = 0;
  const [u] = await q('select stripe_connect_id from users where id=$1', [id]); for (const r of rows as any[]) { if (u?.stripe_connect_id && await payoutConsult(r.id)) { n++; continue; } await q("update consults set payout_status='manual_paid',payout_paid_at=now() where id=$1 and payout_status='unpaid'", [r.id]); n++; }
  await audit(c.get('user').id, 'biologist_pay_all', { target: id, n }); return c.json({ ok: true, paid: n }); });
A.post('/consults/:id/reassign', async c => { const [o] = await q("select buck_id,biologist_id from consults where id=$1 and status in ('claimed','needs_info')", [c.req.param('id')]); if (!o) return c.json({ error: 'not_found' }, 404);
  await q("update consults set status='open',biologist_id=null,claimed_at=null where id=$1", [c.req.param('id')]); await q('delete from buck_shares where buck_id=$1 and to_user=$2', [o.buck_id, o.biologist_id]);
  await audit(c.get('user').id, 'consult_reassign', { id: c.req.param('id') }); return c.json({ ok: true }); });
// ---- regional calibration (how fast teeth wear where the deer live)
const numAge = (a: any) => (a == null ? NaN : parseFloat(String(a).replace('+', '')));
A.get('/calibration', async c => { const regs = await q('select id,name,zip_prefixes,shift::float shift,note from regions order by name'), useBio = (await getSetting('calib_use_biologist')) !== 'false';
  const rows = await q("select s.id,u.zip z,s.observations->'dist'->>'raw_best' raw,s.observations->'dist'->>'best' best,s.observations->>'molar_wear' wear,s.truth_age,(select answer_age from consults c where c.buck_id=s.buck_id and c.kind='age' and c.status='answered' order by answered_at desc limit 1) bio from scans s join users u on u.id=s.user_id where s.mode='jaw' and s.observations is not null and s.counted");
  const mk = (id: string | null) => { const m = rows.filter((r: any) => { const rg = regs.find((x: any) => (x.zip_prefixes || []).some((p: string) => String(r.z || '').startsWith(p))); return (rg ? rg.id : null) === id; }), g = m.map((r: any) => ({ ...r, truth: r.truth_age || (useBio ? r.bio : null) })).filter((r: any) => r.truth && Number.isFinite(numAge(r.truth)) && Number.isFinite(numAge(r.raw || r.best)));
    const d = g.map((r: any) => numAge(r.truth) - numAge(r.raw || r.best)), old = g.filter((r: any) => ['1', '2', '3'].includes(String(r.wear))), od = old.map((r: any) => numAge(r.truth) - numAge(r.raw || r.best)), avg = (a: number[]) => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : null);
    const by: any = {}; for (const r of g) { const w = String(r.wear ?? '?'); by[w] = by[w] || { wear: w, n: 0, truth: {} }; by[w].n++; by[w].truth[r.truth] = (by[w].truth[r.truth] || 0) + 1; }
    const bias = avg(od), suggest = old.length >= 8 && bias != null ? Math.max(0, Math.min(2, Math.round((bias / 1) * 4) / 4)) : null;
    return { scans: m.length, graded: g.length, verified: g.filter((r: any) => r.truth_age).length, from_biologist: g.filter((r: any) => !r.truth_age).length, bias: avg(d) == null ? null : Math.round(avg(d)! * 100) / 100, old_bias: bias == null ? null : Math.round(bias * 100) / 100, old_n: old.length, suggested_shift: suggest, by_wear: Object.values(by).sort((a: any, b: any) => a.wear.localeCompare(b.wear)) }; };
  return c.json({ use_biologist: useBio, rut_phases: RUT_PHASES, rut_shifts: await rutShifts(), regions: regs.map((r: any) => ({ ...r, stats: mk(r.id) })), elsewhere: mk(null) }); });
A.put('/regions/:id', async c => { const id = c.req.param('id').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 40), b = await c.req.json().catch(() => ({})); if (!id) return c.json({ error: 'invalid_input' }, 400);
  const name = String(b.name || '').trim().slice(0, 80), zips = Array.isArray(b.zip_prefixes) ? b.zip_prefixes : String(b.zip_prefixes || '').split(/[\s,]+/), z = [...new Set(zips.map((x: any) => String(x).trim()).filter((x: string) => /^\d{3,5}$/.test(x)))], sh = Number(b.shift);
  if (!name || !Number.isFinite(sh) || sh < 0 || sh > 4) return c.json({ error: 'invalid_input' }, 400);
  await q('insert into regions(id,name,zip_prefixes,shift,note) values($1,$2,$3,$4,$5) on conflict(id) do update set name=excluded.name,zip_prefixes=excluded.zip_prefixes,shift=excluded.shift,note=excluded.note', [id, name, z, Math.round(sh * 100) / 100, String(b.note || '').slice(0, 400) || null]); await audit(c.get('user').id, 'region_update', { id, shift: sh }); recalcAll().catch(e => console.error('recalc', e.message)); return c.json({ ok: true }); });
A.delete('/regions/:id', async c => { await q('delete from regions where id=$1', [c.req.param('id')]); recalcAll().catch(e => console.error('recalc', e.message)); return c.json({ ok: true }); });
A.post('/recalc', async c => c.json({ ok: true, ...(await recalcAll()) }));
A.put('/calibration/settings', async c => { const b = await c.req.json().catch(() => ({})); if (b.use_biologist !== undefined) await setSetting('calib_use_biologist', b.use_biologist === false ? 'false' : 'true', c.get('user').id); if (b.rut_shifts) { const o: any = {}; for (const k of RUT_PHASES) { const n = +b.rut_shifts[k]; if (b.rut_shifts[k] !== undefined && b.rut_shifts[k] !== '' && (!Number.isFinite(n) || n < -1 || n > 1)) return c.json({ error: 'invalid_input' }, 400); o[k] = Number.isFinite(n) ? n : 0; } await setSetting('rut_shifts', JSON.stringify(o), c.get('user').id); recalcAll().catch(e => console.error('recalc', e.message)); } return c.json({ ok: true }); });
mountSeo({ app, A, q, getSetting, setSetting, audit, env, HTML });
app.route('/api/admin', A);
export default { port: +(env.PORT || 3000), fetch: app.fetch };
