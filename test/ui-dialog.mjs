import { JSDOM, VirtualConsole } from 'jsdom';
const B='http://localhost:3000', errs=[], sleep=ms=>new Promise(r=>setTimeout(r,ms));
const tok=async(e,p)=>(await (await fetch(B+'/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:e,password:p})})).json()).token;
async function open(t){const vc=new VirtualConsole();vc.on('jsdomError',e=>errs.push(String(e.message).slice(0,200)));const html=await (await fetch(B+'/')).text();const d=new JSDOM(html,{url:B+'/',runScripts:'dangerously',pretendToBeVisual:true,virtualConsole:vc,beforeParse(w){w.fetch=(u,o)=>fetch(new URL(u,B),o);w.scrollTo=()=>{};w.localStorage.setItem('t',t);w.confirm=()=>true;w.prompt=()=>'friend@test.com'}});await sleep(900);return d.window}
let fails=0;const ok=(n,c)=>{console.log((c?'PASS ':'FAIL ')+n);if(!c)fails++};
const txt=w=>w.document.querySelector('#app').textContent.replace(/\s+/g,' ');
let w=await open(await tok('admin@test.com','adminpass12'));
w.eval("S.tab='analytics'");w.go('admin');await sleep(900);ok('analytics shows clickable hint',txt(w).includes('Visitors ›')&&txt(w).includes('Page views ›'));
await w.tdrill('visitors','');await sleep(500);ok('visitor drilldown renders',txt(w).includes('Back to analytics')&&txt(w).includes('First seen'));
w.eval('window.__r=null;askOk("Sure?","Yes, start").then(v=>window.__r=v)');await sleep(100);
ok('dialog shows in page',w.document.body.textContent.includes('Sure?')&&w.document.body.textContent.includes('Yes, start'));
w.document.getElementById('okgo').click();await sleep(100);ok('confirm resolves true',w.__r===true);
w.eval('askOk("Again?").then(v=>window.__r=v)');await sleep(50);w.document.getElementById('okno').click();await sleep(100);ok('cancel resolves false',w.__r===false);
w.document.body.dispatchEvent(new w.Event('x'));w.eval('document.body.insertAdjacentHTML("beforeend","<button id=tb>go</button>")');const b=w.document.getElementById('tb');b.dispatchEvent(new w.MouseEvent('click',{bubbles:true}));ok('pressed class on tap',b.classList.contains('pressed'));
console.log(errs.join('|')||'no js errors');process.exit(fails?1:0)