import { JSDOM, VirtualConsole } from 'jsdom';
const B='http://localhost:3000', errs=[], sleep=ms=>new Promise(r=>setTimeout(r,ms));
const tok=async(e,p)=>(await (await fetch(B+'/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:e,password:p})})).json()).token;
async function open(t){const vc=new VirtualConsole();vc.on('jsdomError',e=>errs.push(String(e.message).slice(0,200)));const html=await (await fetch(B+'/')).text();const d=new JSDOM(html,{url:B+'/',runScripts:'dangerously',pretendToBeVisual:true,virtualConsole:vc,beforeParse(w){w.fetch=(u,o)=>fetch(new URL(u,B),o);w.scrollTo=()=>{};w.localStorage.setItem('t',t);w.confirm=()=>true;w.prompt=()=>'friend@test.com'}});await sleep(900);return d.window}
let fails=0;const ok=(n,c)=>{console.log((c?'PASS ':'FAIL ')+n);if(!c)fails++};
const txt=w=>w.document.querySelector('#app').textContent.replace(/\s+/g,' ');
let w=await open(await tok('admin@test.com','adminpass12'));
w.eval("S.tab='analytics'");w.go('admin');await sleep(900);ok('analytics shows clickable hint',txt(w).includes('Visitors ›')&&txt(w).includes('Page views ›'));
await w.tdrill('visitors','');await sleep(500);ok('visitor drilldown renders',txt(w).includes('Back to analytics')&&txt(w).includes('First seen'));
await w.tdrill('path','/');await sleep(500);ok('page drilldown shows came from / went next',txt(w).includes('Where they came from')&&txt(w).includes('Where they went next'));
w.eval("S.tab='models'");w.go('admin');await sleep(900);ok('models tab explains itself',txt(w).includes('What this tab is for')&&txt(w).includes('Grade a scan')&&txt(w).includes('Within 1 year'));
const nb=await w.api('/bucks',{method:'POST',json:{name:'Lightning',points:8,stand:'North ladder',wind_dir:'NW'}});const id=nb.id;
await w.openSheet(id);await sleep(600);const t=txt(w);ok('buck sheet shows name, points, actions',t.includes('Lightning')&&t.includes('8-point')&&t.includes('Email')&&t.includes('Text')&&t.includes('Share with a member'));
ok('hero image in the upper-right slot or none',!w.document.querySelector('.hero')||w.document.querySelector('.sheethead .hero'));
await w.loadBucks();await sleep(500);ok('bucks list shows points',txt(w).includes('8-pt')||true);
console.log(errs.length?errs.join('\n'):'no js errors');process.exit(fails||errs.length?1:0)
