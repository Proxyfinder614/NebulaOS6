
const fs = require('fs');

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;

const ACCESS_FILE = process.env.ACCESS_FILE || './nebula-users.json';

let users = [];
try {
  users = JSON.parse(fs.readFileSync(ACCESS_FILE, 'utf8'));
  if (!Array.isArray(users)) users = [];
} catch {}

function saveUsers() {
  fs.writeFileSync(ACCESS_FILE, JSON.stringify(users, null, 2));
}

function sign(value) {
  return crypto.createHmac('sha256', SESSION_SECRET)
    .update(value).digest('hex');
}

function getAuth(req) {
  if (!SESSION_SECRET) return null;
  const cookie = (req.headers.cookie || '')
    .split(';').map(x => x.trim())
    .find(x => x.startsWith('nebula_access='));

  if (!cookie) return null;

  const raw = cookie.slice('nebula_access='.length);
  const pos = raw.lastIndexOf('.');
  if (pos < 0) return null;

  const id = raw.slice(0, pos);
  const sig = raw.slice(pos + 1);
  const expected = sign(id);

  if (sig.length !== expected.length ||
      !crypto.timingSafeEqual(
        Buffer.from(sig), Buffer.from(expected)
      )) return null;

  if (id === 'owner') return { id, admin: true };

  const user = users.find(u => u.id === id && !u.blocked);
  return user ? { id, admin: false } : null;
}

function sendJSON(res, status, data) {
  res.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store'
  });
  res.end(JSON.stringify(data));
}

function readBody(req, callback) {
  let body = '';
  req.on('data', chunk => {
    body += chunk;
    if (body.length > 4096) req.destroy();
  });
  req.on('end', () => {
    try { callback(JSON.parse(body)); }
    catch { sendJSON(resPlaceholder(req), 400, { error: 'Invalid JSON' }); }
  });
}

function resPlaceholder(req) {
  return req.res;
}

const LOGIN_HTML = `<!doctype html>
<html><head><meta name="viewport" content="width=device-width">
<title>Nebula Access</title>
<style>
body{background:#080811;color:white;font:16px system-ui;
display:grid;place-items:center;min-height:100vh;margin:0}
main{background:#151522;border:1px solid #35354c;
border-radius:20px;padding:30px;width:min(350px,80vw)}
input,button{box-sizing:border-box;width:100%;padding:14px;
border-radius:12px;margin-top:12px;font:inherit}
input{background:#090914;color:white;border:1px solid #555}
button{background:#8174ff;color:white;border:0}
#error{color:#ff9999}
</style></head><body><main>
<h1>🌌 Nebula</h1>
<p>Enter your access code.</p>
<input id="code" type="password" placeholder="Access code">
<button onclick="login()">Enter Nebula</button>
<p id="error"></p>
<script>
async function login(){
 const r=await fetch('/access/login',{
  method:'POST',
  headers:{'content-type':'application/json'},
  body:JSON.stringify({code:document.querySelector('#code').value})
 });
 if(r.ok)location.href='/';
 else document.querySelector('#error').textContent='Invalid or blocked code';
}
</script></main></body></html>`;

const ADMIN_HTML = `<!doctype html>
<html><head><meta name="viewport" content="width=device-width">
<title>Nebula Admin</title>
<style>
body{background:#080811;color:#eee;font:16px system-ui;
max-width:700px;margin:30px auto;padding:20px}
button,input{padding:12px;border-radius:10px;margin:5px;
font:inherit}
button{background:#766bfa;color:white;border:0}
input{background:#171722;color:white;border:1px solid #444}
.user{padding:15px;margin:10px 0;background:#171722;
border-radius:12px}
</style></head><body>
<h1>🛡️ Nebula Admin</h1>
<p>Manage who can access your website.</p>
<input id="name" placeholder="User name">
<button onclick="createUser()">Create Access Code</button>
<p id="result"></p>
<h2>Users</h2><div id="users"></div>
<button onclick="location.href='/'">Back to Nebula</button>
<script>
async function api(path,method='GET',body){
 const r=await fetch(path,{
  method,headers:{'content-type':'application/json'},
  body:body?JSON.stringify(body):undefined
 });
 return r.json();
}
async function load(){
 const data=await api('/admin/users');
 const root=document.querySelector('#users');
 root.replaceChildren();
 for(const u of data.users||[]){
  const div=document.createElement('div');
  div.className='user';
  const name=document.createElement('strong');
  name.textContent=u.name+(u.blocked?' — BLOCKED':' — ACTIVE');
  const btn=document.createElement('button');
  btn.textContent=u.blocked?'Unblock':'Block';
  btn.onclick=async()=>{
   await api('/admin/users/'+encodeURIComponent(u.id),'PATCH',
    {blocked:!u.blocked});
   load();
  };
  div.append(name,document.createElement('br'),btn);
  root.append(div);
 }
}
async function createUser(){
 const name=document.querySelector('#name').value.trim();
 if(!name)return;
 const d=await api('/admin/users','POST',{name});
 document.querySelector('#result').textContent=
  d.code?'Give '+name+' this code: '+d.code:(d.error||'Error');
 load();
}
load();
</script></body></html>`;

function accessMiddleware(req, res, url) {
  const path = url.pathname;

  if (!ADMIN_PASSWORD || !SESSION_SECRET) {
    sendJSON(res, 503, {
      error: 'Configure ADMIN_PASSWORD and SESSION_SECRET in Render'
    });
    return true;
  }

  if (path === '/access/login' && req.method === 'POST') {
    let body = '';
    req.on('data', c => {
      body += c;
      if (body.length > 4096) req.destroy();
    });
    req.on('end', () => {
      let code = '';
      try { code = String(JSON.parse(body).code || ''); }
      catch {}

      let id = null;
      if (code === ADMIN_PASSWORD) id = 'owner';
      else {
        const hash = crypto.createHash('sha256')
          .update(code).digest('hex');
        const user = users.find(u => u.hash === hash && !u.blocked);
        if (user) id = user.id;
      }

      if (!id) return sendJSON(res, 401, { error: 'Invalid code' });

      res.setHeader('Set-Cookie',
        'nebula_access=' + id + '.' + sign(id) +
        '; HttpOnly; Secure; SameSite=Lax; Path=/');
      sendJSON(res, 200, { ok: true });
    });
    return true;
  }

  const auth = getAuth(req);

  if (!auth) {
    if (path === '/favicon.ico') {
      res.writeHead(204);
      res.end();
    } else {
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store'
      });
      res.end(LOGIN_HTML);
    }
    return true;
  }

  if (path === '/admin') {
    if (!auth.admin) {
      sendJSON(res, 403, { error: 'Owner only' });
    } else {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(ADMIN_HTML);
    }
    return true;
  }

  if (path === '/admin/users') {
    if (!auth.admin) {
      sendJSON(res, 403, { error: 'Owner only' });
      return true;
    }

    if (req.method === 'GET') {
      sendJSON(res, 200, {
        users: users.map(({id,name,blocked})=>({id,name,blocked}))
      });
      return true;
    }

    if (req.method === 'POST') {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        let name = '';
        try { name = String(JSON.parse(body).name || '').trim(); }
        catch {}
        if (!name || name.length > 40)
          return sendJSON(res, 400, {error:'Invalid name'});

        const code = crypto.randomBytes(12).toString('hex');
        const id = crypto.randomUUID();
        const hash = crypto.createHash('sha256')
          .update(code).digest('hex');

        users.push({id,name,hash,blocked:false});
        saveUsers();
        sendJSON(res, 200, {code});
      });
      return true;
    }
  }

  if (path.startsWith('/admin/users/') && req.method === 'PATCH') {
    if (!auth.admin) {
      sendJSON(res, 403, {error:'Owner only'});
      return true;
    }

    const id = path.slice('/admin/users/'.length);
    const user = users.find(u => u.id === id);
    if (!user) {
      sendJSON(res, 404, {error:'User not found'});
      return true;
    }

    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      let blocked;
      try { blocked = JSON.parse(body).blocked; }
      catch {}
      if (typeof blocked !== 'boolean')
        return sendJSON(res, 400, {error:'Invalid status'});

      user.blocked = blocked;
      saveUsers();
      sendJSON(res, 200, {ok:true});
    });
    return true;
  }

  return false;
}
