// Real-mode analysis against a fake Anthropic server: temperature set, passes voted, same photos cached.
import http from 'http'; import { spawn } from 'child_process';
const BASE = 'http://localhost:3002'; let fails = 0; const ok = (n, c, x = '') => { console.log((c ? 'PASS ' : 'FAIL ') + n + (c ? '' : ' ' + JSON.stringify(x))); if (!c) fails++; };
const calls = []; const seq = [1, 2, 2, 3, 3, 3, 1, 1, 1];
const fake = http.createServer((rq, rs) => { let b = ''; rq.on('data', d => b += d); rq.on('end', () => { const body = JSON.parse(b), n = calls.length; calls.push(body); const w = seq[n % seq.length];
  rs.setHeader('content-type', 'application/json'); rs.end(JSON.stringify({ usage: { input_tokens: 1000, output_tokens: 300 }, content: [{ type: 'text', text: JSON.stringify({ usable: true, quality: 90, premolar3_temporary: false, molar_wear: w, confidence: 80, reasoning: 'r', features: [], alternatives: [], photo_notes: [], evidence: [], would_change_answer: [], age_probs: { '2.5': 20, '3.5': 30, '4.5': 30, '5.5': 15, '6.5+': 5 } }) }] })); }); }).listen(9933);
const env = { ...process.env, PORT: '3002', ANTHROPIC_URL: 'http://localhost:9933', ANTHROPIC_API_KEY: 'k', MODEL_CLAUDE: 'claude-test', MOCK_MODELS: '', OPENAI_API_KEY: '', GEMINI_API_KEY: '' };
delete env.MOCK_MODELS; const app = spawn('/tmp/bunx/node_modules/.bin/bun', ['src/app.ts'], { env, stdio: 'ignore' }); await new Promise(r => setTimeout(r, 4000));
const call = async (m, p, body, tok) => { const h = tok ? { authorization: 'Bearer ' + tok } : {}; let b; if (body instanceof FormData) b = body; else if (body) { h['content-type'] = 'application/json'; b = JSON.stringify(body); } const r = await fetch(BASE + '/api' + p, { method: m, headers: h, body: b }); return { s: r.status, j: await r.json().catch(() => ({})) }; };
try {
  let r = await call('POST', '/login', { email: 'admin@test.com', password: 'adminpass12' }); const AD = r.j.token; ok('admin login', !!AD, r);
  await call('PUT', '/admin/settings', { compare_all: 'false', analysis_samples: '3' }, AD);
  const jpg = (n) => new Blob([Buffer.from('/9j/4AAQSkZJRg==', 'base64'), Buffer.from('photo' + n)], { type: 'image/jpeg' });
  const scan = async (n) => { const f = new FormData(); f.append('mode', 'jaw'); f.append('photos', jpg(n), 'a.jpg'); return call('POST', '/scans', f, AD); };
  r = await scan(1); ok('scan completes', r.s === 200, r);
  ok('three passes were made', calls.length === 3, calls.length);
  ok('temperature is set on every pass', calls.every(c => typeof c.temperature === 'number'), calls.map(c => c.temperature));
  const o = r.j.best ? r.j.best.observations : r.j.observations || (r.j.scan && r.j.scan.observations); const obs = o || {};
  ok('wear is the vote of the passes (1,2,2 gives 2)', obs.molar_wear === 2 || r.j.class === 'Middle', { w: obs.molar_wear, c: r.j.class });
  ok('agreement is recorded and lowers confidence', obs.consistency && obs.consistency.samples === 3 && obs.consistency.agree < 1 && obs.confidence < 80, obs.consistency);
  const before = calls.length; r = await scan(1); ok('identical photos answer from cache with no new model calls', r.s === 200 && calls.length === before, calls.length - before);
  r = await scan(2); ok('different photos run again', calls.length === before + 3, calls.length - before);
  const o2 = r.j.best ? r.j.best.observations : r.j.observations || {}; ok('unanimous passes keep full agreement', !o2.consistency || o2.consistency.agree === 1, o2.consistency);
  await call('PUT', '/admin/settings', { analysis_samples: '1' }, AD); const b2 = calls.length; r = await scan(3); ok('one pass when set to 1', calls.length === b2 + 1 && calls[b2].temperature === 0, calls.slice(b2).map(c => c.temperature));
  r = await call('PUT', '/admin/settings', { analysis_samples: '9' }, AD); ok('bad sample count rejected', r.s === 400, r);
} finally { app.kill(); fake.close(); }
console.log(fails ? `\n${fails} FAILED` : '\nALL PASSED'); process.exit(fails ? 1 : 0);
