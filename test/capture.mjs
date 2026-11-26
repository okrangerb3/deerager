// Reproduces the photo step in a simulated browser: pick a photo, the Analyze button must enable, click it, see a detailed result.
import { JSDOM, VirtualConsole } from 'jsdom';
const B = 'http://localhost:3000', sleep = ms => new Promise(r => setTimeout(r, ms)); let fails = 0; const errs = [];
const ok = (n, c, x = '') => { console.log((c ? 'PASS ' : 'FAIL ') + n + (c ? '' : ' ' + x)); if (!c) fails++; };
const token = async () => (await (await fetch(B + '/api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'admin@test.com', password: 'adminpass12' }) })).json()).token;
async function open(mode) { const vc = new VirtualConsole(); vc.on('jsdomError', e => errs.push(String(e.message).slice(0, 160)));
  const html = await (await fetch(B + '/')).text(), t = await token();
  const dom = new JSDOM(html, { url: B + '/', runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: vc, beforeParse(w) { w.fetch = (u, o = {}) => { if (o.body && o.body.constructor && o.body.constructor.name === 'FormData') { const nf = new FormData(); for (const [k, v] of o.body.entries()) { if (v && typeof v === 'object' && v.size !== undefined) nf.append(k, new Blob([new Uint8Array(2000)], { type: 'image/jpeg' }), 'p.jpg'); else nf.append(k, v); } o = { ...o, body: nf }; } return fetch(new URL(u, B), o); }; w.scrollTo = () => {}; w.localStorage.setItem('t', t); w.URL.createObjectURL = () => 'blob:x'; w.URL.revokeObjectURL = () => {};
    const cv = w.HTMLCanvasElement.prototype; cv.getContext = () => ({ drawImage() {}, getImageData: () => ({ data: new Uint8ClampedArray(160 * 120 * 4).fill(120) }) });
    if (mode === 'normal') { w.createImageBitmap = async () => ({ width: 1600, height: 1200 }); cv.toBlob = function (cb) { cb(new w.Blob(['x'], { type: 'image/jpeg' })); }; }
    if (mode === 'nobitmap') { w.createImageBitmap = async () => { throw new Error('unsupported'); }; cv.toBlob = function (cb) { cb(new w.Blob(['x'], { type: 'image/jpeg' })); }; }
    if (mode === 'nullblob') { w.createImageBitmap = async () => ({ width: 1600, height: 1200 }); cv.toBlob = function (cb) { cb(null); }; }
    if (mode === 'hang') { w.createImageBitmap = () => new Promise(() => {}); } } });
  await sleep(800); return dom.window; }
const txt = w => w.document.querySelector('#app').textContent.replace(/\s+/g, ' ');
for (const mode of ['normal', 'nobitmap', 'nullblob', 'hang']) {
  const w = await open(mode); w.eval("startCap('jaw')"); await sleep(500);
  const before = w.document.getElementById('goA'); ok(`[${mode}] Analyze starts disabled with no photo`, before && before.disabled);
  const inp = w.document.querySelectorAll('input[type=file]')[1], f = new w.File([new Uint8Array(2000)], 'jaw.jpg', { type: 'image/jpeg' });
  Object.defineProperty(inp, 'files', { value: [f] }); inp.dispatchEvent(new w.Event('change')); await sleep(700);
  const btn = w.document.getElementById('goA'); ok(`[${mode}] Analyze enables right after choosing a photo`, btn && !btn.disabled, btn && btn.outerHTML.slice(0, 120));
  if (mode === 'normal') { btn.click(); await sleep(2500); const t = txt(w);
    ok('results page shows the estimate, confidence and the reasoning sections', ['Estimate', 'Confidence', 'Can I shoot him?', 'Change in Hunting rules', 'Why this result', 'Rule applied', 'What the AI saw', 'How confident, and why', 'Other possibilities considered', 'To be more certain', 'How age classes are determined'].every(s => t.includes(s)), t.slice(0, 400)); } }
ok('no uncaught JS errors', errs.length === 0, errs.join(' | ')); console.log(fails ? fails + ' FAILED' : 'ALL PASSED'); process.exit(fails ? 1 : 0);
