import http from 'http'; const o = new Map();
http.createServer((req, res) => { const ch = []; req.on('data', d => ch.push(d)); req.on('end', () => { const k = req.url.split('?')[0];
  if (req.method === 'PUT') { o.set(k, { b: Buffer.concat(ch), t: req.headers['content-type'] }); res.writeHead(200, { etag: '"x"' }); return res.end(); }
  if (req.method === 'GET' && o.has(k)) { res.writeHead(200, { 'content-type': o.get(k).t }); return res.end(o.get(k).b); } res.writeHead(404); res.end(); }); }).listen(9000);
