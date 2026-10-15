// All linking happens in an HttpOnly-cookie/CSRF-bound consent transaction. No token is
// accepted by an MCP tool, a URL parameter or an assistant message.
export function installLinks(app, { connections, csrf, saveTx, page, prefix, fail, finish, issuer }) {
  const html = value => String(value).replace(/[&<>"']/g, x => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[x]);
  const plugins = new Map(connections.map(c => [c.name, c.auth]));
  if (plugins.size !== connections.length || connections.some(c=>!/^[a-z][a-z0-9_-]{0,47}$/.test(c.name))) throw new Error('Invalid auth plugin registration');
  const hidden = (tx, name) => `<input type="hidden" name="csrf" value="${tx.csrf}"><input type="hidden" name="cli" value="${html(name)}">`;
  function show(res, tx, notice = '') {
    const forms = connections.map(({name,auth}) => {
      const state = tx.linkDevices?.[name];
      if (tx.linked?.[name]) return `<p>${html(name)}: connected</p>`;
      if (state) return `<p>${html(name)}: approve <strong>${html(state.userCode)}</strong> on <a href="${html(state.approval)}" target="_blank" rel="noopener noreferrer">its device approval page</a>.</p><form method="post" action="${prefix}/oauth/link/complete">${hidden(tx,name)}<button>Finish ${html(name)} approval</button></form>`;
      if (auth.type === 'token') return `<form method="post" action="${prefix}/oauth/link/token">${hidden(tx,name)}<label>${html(name)} token <input name="token" type="password" autocomplete="off" required maxlength="8192"></label><button>Connect ${html(name)}</button></form>`;
      return `<form method="post" action="${prefix}/oauth/link/start">${hidden(tx,name)}<button>Connect ${html(name)} as a gateway device</button></form>`;
    }).join('');
    return page(res, `<h2>Connect CLI accounts</h2><p>${html(notice)} The gateway stores each credential encrypted. Token entry belongs only on this page, never in chat. Optional accounts can be skipped.</p>${forms}<form method="post" action="${prefix}/oauth/link/finish"><input type="hidden" name="csrf" value="${tx.csrf}"><button>Continue</button></form>`,tx);
  }
  function get(req) {
    const tx = csrf(req); const name = req.body?.cli; const auth = plugins.get(name);
    if (!tx || tx.phase !== 'link' || !auth || tx.linked?.[name]) return null;
    return {tx,name,auth};
  }
  const sameAccount = (credential, tx) => credential.identity?.email === tx.credential.identity.email;
  app.post('/oauth/link/start', async (req,res) => {
    const step = get(req); if (!step || step.auth.type === 'token' || step.tx.linkDevices?.[step.name]) return fail(res);
    const {tx,name,auth} = step;
    // Save a lock before the await; repeated clicks must not create multiple devices.
    tx.phase = 'link_busy'; saveTx(tx);
    try {
      const device = await auth.start(`MCP gateway, ${tx.clientName}`);
      const approval = new URL(device.approval);
      if (approval.protocol !== 'https:' || approval.username || approval.password || !Number.isFinite(device.expiry)) throw new Error('Invalid device response');
      tx.linkDevices = {...tx.linkDevices,[name]:{...device,nextPoll:0}};
      tx.phase='link';saveTx(tx);return show(res,tx);
    } catch {tx.phase='link';saveTx(tx);return show(res,tx,'Device approval could not be started.');}
  });
  app.post('/oauth/link/complete', async (req,res) => {
    const step=get(req);if(!step||step.auth.type==='token')return fail(res);
    const {tx,name,auth}=step;const device=tx.linkDevices?.[name];
    if(!device||device.expiry<=Date.now())return fail(res,'expired_device');
    if(Date.now()<device.nextPoll)return fail(res,'slow_down',429);
    tx.phase='link_busy';device.nextPoll=Date.now()+device.interval*1000;saveTx(tx);
    try {
      const credential=await auth.poll(device.deviceCode);
      if(!sameAccount(credential,tx)){await auth.revoke(credential).catch(()=>{});throw new Error('Account mismatch');}
      tx.linked={...tx.linked,[name]:credential};delete tx.linkDevices[name];tx.phase='link';saveTx(tx);return show(res,tx);
    } catch {tx.phase='link';saveTx(tx);return show(res,tx,'Approval is pending or unavailable. Check the account and retry after the device interval.');}
  });
  app.post('/oauth/link/token',async(req,res)=>{
    const step=get(req);if(!step||step.auth.type!=='token'||!issuer.startsWith('https:'))return fail(res);
    const {tx,name,auth}=step;tx.phase='link_busy';saveTx(tx);
    try {
      const credential=await auth.accept(req.body.token,tx.credential);
      if(!sameAccount(credential,tx))throw new Error('Account mismatch');
      tx.linked={...tx.linked,[name]:credential};tx.phase='link';saveTx(tx);return show(res,tx);
    }catch{tx.phase='link';saveTx(tx);return show(res,tx,'Token could not be connected. Check its permissions.');}
    finally {delete req.body.token;}
  });
  app.post('/oauth/link/finish',(req,res)=>{
    const tx=csrf(req);if(!tx||tx.phase!=='link')return fail(res);
    return finish(req,res,tx,tx.credential);
  });
  return {show};
}
