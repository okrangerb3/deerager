import { JSDOM, VirtualConsole } from 'jsdom';
const B='http://localhost:3000', errs=[], sleep=ms=>new Promise(r=>setTimeout(r,ms));
const tok=async(e,p)=>(await (await fetch(B+'/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:e,password:p})})).json()).token;
async function open(t){const vc=new VirtualConsole();vc.on('jsdomError',e=>errs.push(String(e.message).slice(0,200)));const html=await (await fetch(B+'/')).text();const d=new JSDOM(html,{url:B+'/',runScripts:'dangerously',pretendToBeVisual:true,virtualConsole:vc,beforeParse(w){w.fetch=(u,o)=>fetch(new URL(u,B),o);w.scrollTo=()=>{};w.localStorage.setItem('t',t);w.confirm=()=>true;w.prompt=()=>'friend@test.com'}});await sleep(900);return d.window}
let fails=0;const ok=(n,c)=>{console.log((c?'PASS ':'FAIL ')+n);if(!c)fails++};
const txt=w=>w.document.querySelector('#app').textContent.replace(/\s+/g,' ');
let w=await open(await tok('admin@test.com','adminpass12'));
w.confirm=()=>true;
w.go('rules');await sleep(500);ok('rules screen offers templates',txt(w).includes('Hunting rules')&&txt(w).includes('Public land')&&txt(w).includes('Club / lease'));
w.newProfile('club');await sleep(100);ok('form shows club fields',txt(w).includes('Does to take before')&&txt(w).includes('Minimum net'));
w.document.getElementById('pfn').value='Oak Ridge Club';w.document.getElementById('pfa').value='4.5';w.document.getElementById('pfp').value='8';w.document.getElementById('pfl').value='2';
await w.saveProfile();await sleep(600);ok('profile saved and active',txt(w).includes('Oak Ridge Club')&&txt(w).includes('in use')&&txt(w).includes('8+ points'));
const nb=await w.api('/bucks',{method:'POST',json:{name:'Lightning',points:6,property_kind:'club',property_name:'Oak Ridge',status:'watching'}});
const d={probs:{'3.5':10,'4.5':70,'5.5':20},best:'4.5',lo:3.5,hi:5.5};
const pf=w.eval('activeProfile()');const c=w.rulesCheck(pf,{points:6,bc:null},d);
ok('checks: age ok, points fail',c[0].s==='ok'&&c[1].s==='no');
ok('unknown spread/net handled',w.rulesCheck({min_spread:17,min_net:140},{bc:null},d).every(x=>x.s==='?'));
const h=w.decisionHtml?w.decisionHtml({dist:d,range:'4.5',class:'4.5'},false):'';ok('decision card shows rules block',h.includes('Oak Ridge Club'));
w.eval("S.buck=null");await w.openBuck(nb.id);await sleep(600);ok('buck page shows shooter check',txt(w).includes('Shooter check')&&txt(w).includes('Does not meet'));
console.log(errs.length?errs.join('\n'):'no js errors');process.exit(fails||errs.length?1:0)
