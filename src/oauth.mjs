import { createHash, timingSafeEqual } from 'node:crypto';
import rateLimit from 'express-rate-limit';
import { digest, secret } from './store.mjs';
import { UpstreamError } from './upstream.mjs';
import { isIP } from 'node:net';
import { readFileSync } from 'node:fs';
import { validateUnlock, VAULT_SLOT } from './vault.mjs';
import { installLinks } from './links.mjs';
// The consent page runs @pocketshell/core's keyVault, bundled at a pinned commit by scripts/build-client.mjs.
function vaultAssets() {
  const read = path => readFileSync(new URL(path, import.meta.url), 'utf8');
  let core;
  try { core = read('../vendor/key-vault.mjs'); } catch { throw new Error('MCP_VAULT needs vendor/key-vault.mjs; run node scripts/build-client.mjs'); }
  return { 'vault-unlock.js': read('./browser/vault-unlock.js'), 'host-choices.js': read('./browser/host-choices.js'), 'key-vault.js': core };
}
// Consent forms end in a 303 to the client's callback, and CSP form-action also governs that redirect,
// so each transaction page allows exactly its own validated callback origin. Only the unlock page runs
// script: same-origin files, WebAssembly for Argon2id (hash-wasm inside core), same-origin fetch.
// Inline styles are allowed on these server-rendered pages because every dynamic value is
// HTML-escaped at its single insertion point; no user or client markup is ever interpolated.
const consentCsp = (tx, scripts = false) => `default-src 'none'; style-src 'unsafe-inline'; ${scripts ? "script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; " : ''}form-action 'self' ${new URL(tx.redirect).origin}; frame-ancestors 'none'; base-uri 'none'`;
export function validRedirect(value) {
  try {
    const u = new URL(value);
    const host = u.hostname.replace(/^\[|\]$/g, '');
    const loopback = host === 'localhost' || (isIP(host) === 4 && Number(host.split('.')[0]) === 127) || host === `${':'.repeat(2)}1`;
    return !u.username && !u.password && !u.hash && (u.protocol === 'https:' || (u.protocol === 'http:' && loopback));
  } catch { return false; }
}
const DAY = 86400000;
const equal = (a, b) => typeof a === 'string' && typeof b === 'string' && Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const html = value => String(value).replace(/[&<>"']/g, x => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[x]);
const fail = (res, code = 'invalid_request', status = 400) => res.status(status).json({ error: code });

export function installOAuth(app, { store, issuer, upstream, allowedEmails, redirectUris, rootApp = app, vault = null, tools, connections = [] }) {
  const resource = `${issuer}/mcp`;
  const issuerUrl = new URL(issuer);
  const origin = issuerUrl.origin;
  const prefix = issuerUrl.pathname.replace(/\/$/, '');
  const metadataUrl = `${origin}/.well-known/oauth-protected-resource${prefix}/mcp`;
  const redirectAllowed = uri => validRedirect(uri) && (!redirectUris.length || redirectUris.includes(uri));
  const cookieName = `mcp_tx_${digest(issuer).slice(0, 8)}`;
  const scope = 'mcp:tools'; // Legacy adapters retain their original grant.
  const supportedScopes = tools?.scopes || [scope];
  const readScopes = new Set(tools?.readScopes || [scope]);
  const validScope = value => typeof value === 'string' && value.length <= 16384 && value.split(' ').every(x => supportedScopes.includes(x));
  const limiter = rateLimit({ windowMs: 60000, limit: 60, standardHeaders: 'draft-8', legacyHeaders: false });
  app.use('/oauth', limiter);
  rootApp.get([`/.well-known/oauth-protected-resource${prefix}`, `/.well-known/oauth-protected-resource${prefix}/mcp`], (_req, res) => res.json({ resource, authorization_servers: [issuer], scopes_supported: supportedScopes, bearer_methods_supported: ['header'] }));
  rootApp.get(`/.well-known/oauth-authorization-server${prefix}`, (_req, res) => res.json({ issuer, authorization_endpoint: `${issuer}/oauth/authorize`, token_endpoint: `${issuer}/oauth/token`, registration_endpoint: `${issuer}/oauth/register`, revocation_endpoint: `${issuer}/oauth/revoke`, scopes_supported: supportedScopes, response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'], code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none'], authorization_response_iss_parameter_supported: true }));
  const challenge = (res) => res.set('WWW-Authenticate', `Bearer resource_metadata="${metadataUrl}", scope="${supportedScopes.join(' ')}"`).status(401).json({ error: 'invalid_token' });
  const brand = 'Operational MCP';
  // One shared shell for every consent and linking page: readable without any client
  // stylesheet, since the CSP admits only inline styles and no outside resources.
  const pageStyle = 'body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;line-height:1.5;color:#1a1a1a;background:#fff;margin:0}main{max-width:42rem;margin:2rem auto;padding:0 1rem}h1{font-size:1.6rem}h2{font-size:1.25rem;margin-top:2rem}.app-list{list-style:none;padding:0;display:grid;gap:0.75rem}.app{border:1px solid #c8c8c8;border-radius:0.5rem;padding:0.75rem 1rem}.app h3{margin:0;font-size:1.05rem}.app p{margin:0.3rem 0}.desc{color:#444}.status-connected{color:#0a6b1a;font-weight:bold}.status-missing{color:#8a5a00;font-weight:bold}button{font:inherit;padding:0.35rem 0.9rem;border-radius:0.4rem;border:1px solid #666;background:#f4f4f4;cursor:pointer}button:hover{background:#e6e6e6}input[type=password],input[type=text]{font:inherit;padding:0.3rem 0.5rem;border:1px solid #666;border-radius:0.4rem;max-width:16rem}form{margin:0.5rem 0 0}label{display:block;margin:0.3rem 0}.notice{background:#fff8e1;border:1px solid #e0c36a;border-radius:0.5rem;padding:0.5rem 1rem}.code{font-family:ui-monospace,monospace;font-size:1.1rem;letter-spacing:0.05em}';
  const page = (res, body, tx = null, scripts = false) => (tx ? res.set('Content-Security-Policy', consentCsp(tx, scripts)) : res).type('html').send(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${brand}</title><style>${pageStyle}</style><body><main><h1>${brand}</h1>${body}</main></body></html>`);
  const txNonce = req => Object.fromEntries((req.headers.cookie || '').split(';').map(x => x.trim().split('=')))[cookieName];
  const transaction = req => { const nonce = txNonce(req); return nonce && store.get('transaction', digest(nonce)); };
  const txCookie = (res, nonce) => res.cookie(cookieName, nonce, { httpOnly: true, secure: issuer.startsWith('https:'), sameSite: 'lax', path: `${prefix}/oauth`, maxAge: 600000 });
  function csrf(req) {
    const tx = transaction(req);
    return tx && req.get('origin') === origin && equal(req.body?.csrf, tx.csrf) ? tx : null;
  }
  function saveTx(tx) { store.put('transaction', tx.id, tx, tx.expiry); }
  app.post('/oauth/register', (req, res) => {
    const b = req.body;
    // DCR clients are untrusted. Validate redirect syntax, then require explicit browser consent.
    // Operators can optionally restrict callbacks further; no client brand is hardcoded.
    if (!b || !Array.isArray(b.redirect_uris) || b.redirect_uris.length < 1 || b.redirect_uris.length > 10 || b.redirect_uris.some(uri => !redirectAllowed(uri)) || !['none', undefined].includes(b.token_endpoint_auth_method) || (b.grant_types && (!Array.isArray(b.grant_types) || b.grant_types.some(x => !['authorization_code','refresh_token'].includes(x)))) || (b.response_types && JSON.stringify(b.response_types) !== '["code"]')) return fail(res, 'invalid_client_metadata');
    const client = { client_id: secret(), client_name: String(b.client_name || 'MCP client').slice(0, 80), redirect_uris: b.redirect_uris, token_endpoint_auth_method: 'none', grant_types: ['authorization_code','refresh_token'], response_types: ['code'] };
    // Keep client registration stable across all token lifetimes (no expiry/rotation policy).
    store.put('client', client.client_id, client, 8640000000000000);
    res.status(201).json(client);
  });
  app.get('/oauth/authorize', (req, res) => {
    const q = req.query;
    const client = typeof q.client_id === 'string' && store.get('client', q.client_id);
    if (!client || typeof q.redirect_uri !== 'string' || !client.redirect_uris.includes(q.redirect_uri) || !redirectAllowed(q.redirect_uri)) return fail(res);
    if (q.response_type !== 'code' || q.code_challenge_method !== 'S256' || typeof q.code_challenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(q.code_challenge) || q.resource !== resource || (q.scope !== undefined && !validScope(q.scope)) || (q.state !== undefined && (typeof q.state !== 'string' || q.state.length > 2048))) return fail(res);
    const nonce = secret();
    const tx = { id: digest(nonce), csrf: secret(), clientId: client.client_id, clientName: client.client_name, redirect: q.redirect_uri, state: q.state, challenge: q.code_challenge, resource, scope: q.scope || supportedScopes.join(' '), expiry: Date.now() + 600000, phase: 'consent' };
    saveTx(tx);
    txCookie(res, nonce);
    page(res, `<p>Client: ${html(client.client_name)}</p><p>Return address: ${html(tx.redirect)}</p><p>This grants the requested CLI commands within your account permissions. Each CLI tool may contain both reads and writes. Write commands require an approval marker. Choose read-only to refuse every write. Approve only a connection you just started.</p><form method="post" action="${prefix}/oauth/start"><input type="hidden" name="csrf" value="${tx.csrf}"><p><label><input type="checkbox" name="read_only" value="1"> Read-only: offer only tools that read, and refuse anything that starts, sends, stops or changes data</label></p><button>Continue to device approval</button></form>`);
  });
  app.post('/oauth/start', async (req, res) => {
    const tx = csrf(req);
    if (!tx || tx.phase !== 'consent') return fail(res);
    // Persist before awaiting to prevent concurrent starts for the same browser transaction.
    tx.phase = 'starting'; tx.readOnly = req.body.read_only === '1';
    if (tx.readOnly && tools?.scopes) tx.scope = tx.scope.split(' ').filter(x => readScopes.has(x)).join(' ');
    if (!tx.scope) return fail(res, 'invalid_scope');
    saveTx(tx);
    try {
      tx.device = await upstream.start(`MCP gateway, ${tx.clientName}`);
      tx.expiry = Math.min(tx.expiry, tx.device.expiry); tx.nextPoll = 0; tx.phase = 'pending'; saveTx(tx);
      page(res, `<p>Approve code <strong class="code">${html(tx.device.userCode)}</strong> in ${html(upstream.kind === 'gateway' ? 'PocketShell' : upstream.kind)}.</p><p><a href="${html(tx.device.approval)}" target="_blank" rel="noopener noreferrer">Open device approval</a></p><p>After approving, return here and continue. No token needs to be copied.</p><form method="post" action="${prefix}/oauth/complete"><input type="hidden" name="csrf" value="${tx.csrf}"><button>Finish connection</button></form>`, tx);
    } catch { store.delete('transaction', tx.id); fail(res, 'temporarily_unavailable', 503); }
  });
  app.post('/oauth/complete', async (req, res) => {
    const tx = csrf(req);
    if (!tx || tx.phase !== 'pending') return fail(res);
    if (Date.now() < tx.nextPoll) return fail(res, 'slow_down', 429);
    tx.nextPoll = Date.now() + tx.device.interval * 1000; tx.phase = 'polling'; saveTx(tx);
    try {
      const credential = await upstream.poll(tx.device.deviceCode);
      if (!allowedEmails.includes(credential.identity.email)) {
        await upstream.revoke(credential).catch(() => {}); store.delete('transaction', tx.id); return fail(res, 'access_denied', 403);
      }
      if (connections.length) {
        tx.phase = 'link'; tx.credential = credential; tx.expiry = Date.now() + 600000; saveTx(tx); txCookie(res, txNonce(req));
        return links.show(res, tx);
      }
      return finish(req, res, tx, credential);
    } catch (error) {
      if (stillPending(res, tx, error, 'pending', '/oauth/complete')) return;
      store.delete('transaction', tx.id); return fail(res, 'access_denied', 403);
    }
  });
  function stillPending(res, tx, error, phase, action) {
    if (!(error instanceof UpstreamError && ['authorization_pending', 'slow_down'].includes(error.code))) return false;
    if (error.code === 'slow_down') tx.device.interval = Math.min(60, tx.device.interval + 5);
    tx.phase = phase; tx.nextPoll = Date.now() + tx.device.interval * 1000; saveTx(tx);
    page(res, `<p class="notice">Approval is still pending. Wait ${tx.device.interval} seconds, approve in the other tab, then continue.</p><form method="post" action="${prefix}${action}"><input type="hidden" name="csrf" value="${tx.csrf}"><button>Check approval</button></form>`, tx);
    return true;
  }
  function finish(req, res, tx, credential) {
    if (tx.connect) return connected(res, tx);
    if (vault) {
      // Unlock before issuing the short-lived code. Linked credentials stay encrypted in tx.
      tx.phase = 'unlock'; tx.credential = credential; tx.expiry = Date.now() + 600000; saveTx(tx); txCookie(res, txNonce(req));
      return unlockPage(res, tx);
    }
    res.clearCookie(cookieName, { path: `${prefix}/oauth` }); res.redirect(303, issue(tx, credential));
  }
  const links = installLinks(app, { connections, csrf, saveTx, page, prefix, fail, finish, issuer });
  // "connect <cli>" after consent. A CLI tool hands the assistant a single-use link bound to its
  // grant. Whoever opens it first proves they own that grant with a one-time device approval in the
  // primary account (revoked as soon as the identity matches), so a leaked link cannot attach a
  // different account to this connection. Then the usual link step runs for that one CLI.
  const ticketKey = value => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value) ? digest(value) : '';
  function connectLink(grantId, cli) {
    if (!connections.some(c => c.name === cli)) return null;
    const ticket = secret();
    store.put('connect', digest(ticket), { grantId, cli }, Date.now() + 600000);
    return `${issuer}/oauth/connect?${new URLSearchParams({ ticket })}`;
  }
  app.get('/oauth/connect', (req, res) => {
    // GET never consumes the ticket, because chat clients may prefetch links.
    const ticket = store.get('connect', ticketKey(req.query.ticket));
    if (!ticket) return page(res, '<p>This connect link expired or was already used. Ask your assistant for a new one.</p>');
    page(res, `<p>Connect <strong>${html(ticket.cli)}</strong> to an existing assistant connection. First confirm it is you with a one-time device approval in your primary account. Credentials are entered only on these pages, never in chat.</p><form method="post" action="${prefix}/oauth/connect"><input type="hidden" name="ticket" value="${html(req.query.ticket)}"><button>Continue</button></form>`);
  });
  app.post('/oauth/connect', async (req, res) => {
    if (req.get('origin') !== origin) return fail(res);
    const key = ticketKey(req.body?.ticket);
    const ticket = store.transaction(() => { const value = store.get('connect', key); if (value) store.delete('connect', key); return value; });
    const grant = ticket && store.get('grant', ticket.grantId);
    if (!grant || grant.revoked) return fail(res);
    const nonce = secret(); const clientName = store.get('client', grant.clientId)?.client_name || 'MCP client';
    const tx = { id: digest(nonce), csrf: secret(), clientId: grant.clientId, clientName, redirect: issuer, connect: ticket, only: [ticket.cli], identity: grant.credential.identity, expiry: Date.now() + 600000, phase: 'confirming' };
    saveTx(tx); txCookie(res, nonce);
    try {
      tx.device = await upstream.start(`MCP gateway, ${clientName} (confirm ${ticket.cli})`);
      tx.expiry = Math.min(tx.expiry, tx.device.expiry); tx.nextPoll = 0; tx.phase = 'confirm'; saveTx(tx);
      page(res, `<p>Confirm it is you: approve code <strong class="code">${html(tx.device.userCode)}</strong>.</p><p><a href="${html(tx.device.approval)}" target="_blank" rel="noopener noreferrer">Open device approval</a></p><p>This approval is only a check and ends immediately afterwards.</p><form method="post" action="${prefix}/oauth/connect/complete"><input type="hidden" name="csrf" value="${tx.csrf}"><button>Continue</button></form>`, tx);
    } catch { store.delete('transaction', tx.id); fail(res, 'temporarily_unavailable', 503); }
  });
  app.post('/oauth/connect/complete', async (req, res) => {
    const tx = csrf(req);
    if (!tx || tx.phase !== 'confirm') return fail(res);
    if (Date.now() < tx.nextPoll) return fail(res, 'slow_down', 429);
    tx.nextPoll = Date.now() + tx.device.interval * 1000; tx.phase = 'confirm_busy'; saveTx(tx);
    let credential;
    try { credential = await upstream.poll(tx.device.deviceCode); }
    catch (error) { if (stillPending(res, tx, error, 'confirm', '/oauth/connect/complete')) return; store.delete('transaction', tx.id); return fail(res, 'access_denied', 403); }
    await upstream.revoke(credential).catch(() => store.put('revoke', secret(), { credential, attempts: 0 }, Date.now()));
    if (credential.identity.id !== tx.identity.id) { store.delete('transaction', tx.id); return fail(res, 'access_denied', 403); }
    delete tx.device; tx.phase = 'link'; tx.expiry = Date.now() + 600000; saveTx(tx); txCookie(res, txNonce(req));
    return links.show(res, tx);
  });
  async function connected(res, tx) {
    const { grantId, cli } = tx.connect; const credential = tx.linked?.[cli];
    store.delete('transaction', tx.id); res.clearCookie(cookieName, { path: `${prefix}/oauth` });
    const grant = store.get('grant', grantId);
    if (!grant || grant.revoked) { if (credential) await revokeCredentials(null, tx.linked).catch(() => {}); return fail(res, 'access_denied', 403); }
    if (!credential) return page(res, '<p>Nothing was connected. You can close this page.</p>');
    // No await between reading and writing the grant, so a concurrent revoke sees either state whole.
    const previous = grant.linked?.[cli];
    store.update('grant', grantId, { ...grant, linked: { ...grant.linked, [cli]: credential } });
    if (previous) await revokeCredentials(null, { [cli]: previous }).catch(() => store.put('revoke', secret(), { linked: { [cli]: previous }, attempts: 0 }, Date.now()));
    page(res, `<p class="status-connected">${html(cli)} is connected for ${html(tx.clientName)}.</p><p>Return to your assistant; its next call uses this account.</p>`);
  }
  async function revokeCredentials(credential, linked = {}) {
    const jobs = [];
    if (credential?.expiry > Date.now()) jobs.push(upstream.revoke(credential));
    for (const [name, value] of Object.entries(linked)) {
      const auth = connections.find(c => c.name === name)?.auth;
      if (auth?.revoke && value.expiry > Date.now()) jobs.push(auth.revoke(value));
    }
    const results = await Promise.allSettled(jobs);
    if (results.some(x => x.status === 'rejected' && !([401,404].includes(x.reason?.status)))) throw new Error('Revocation pending');
  }

  function issue(tx, credential, keys = []) {
    const code = secret();
    const grantId = secret();
    const grantExpiry = Math.min(credential.expiry, Date.now() + 30 * DAY);
    store.transaction(() => {
      store.put('grant', grantId, { credential, linked: tx.linked || {}, clientId: tx.clientId, resource, scope: tx.scope, revoked: false, readOnly: !!tx.readOnly }, grantExpiry);
      store.put('code', digest(code), { grantId, clientId: tx.clientId, redirect: tx.redirect, challenge: tx.challenge, resource }, Date.now() + 60000);
      store.delete('transaction', tx.id);
    });
    // Keys go to process memory only, never into the store above. They stay pending until the client
    // redeems the code, and drop with the code if it never does.
    if (keys.length) vault.sessions.put(grantId, keys, grantExpiry, { pendingMs: 60000 });
    const target = new URL(tx.redirect); target.searchParams.set('code', code); if (tx.state !== undefined) target.searchParams.set('state', tx.state); target.searchParams.set('iss', issuer);
    return target.href;
  }
  function unlockPage(res, tx) {
    const skip = `<form method="post" action="${prefix}/oauth/vault/finish"><input type="hidden" name="csrf" value="${tx.csrf}"><button>Continue without keys</button></form>`;
    const hosts = vault.hosts(tx.credential);
    if (!hosts.length) return page(res, `<p>No SSH hosts are configured for this connection. Tools that need an SSH key will report the vault as locked until you connect again.</p>${skip}`, tx);
    const data = JSON.stringify({ hosts, csrf: tx.csrf, prefix }).replace(/</g, '\\u003c');
    // Repeat who is asking: this page is where a consent-phishing link would ask for the passphrase.
    const client = store.get('client', tx.clientId);
    page(res, `<p>Client: ${html(client?.client_name || 'unknown')}</p><p>Return address: ${html(tx.redirect)}</p><h2>Unlock your key vault</h2><p>Your vault passphrase stays in this browser. Only the keys for the hosts you tick are sent to this ${html(upstream.kind)} connector, kept in its memory for at most ${Math.round(vault.sessions.ttl / 3600000 * 10) / 10} hours, and dropped when you revoke the connection.</p><form id="vault-unlock"><label>Vault passphrase <input id="vault-passphrase" type="password" autocomplete="current-password" required></label> <button id="vault-unlock-button">Unlock</button></form><form id="vault-select" hidden><div id="vault-hosts"></div><button id="vault-select-button">Unlock selected hosts</button></form><p id="vault-status" role="status"></p>${vault.resetUrl ? `<p><a href="${html(vault.resetUrl)}" target="_blank" rel="noopener noreferrer">Forgot passphrase?</a> A lost passphrase cannot be recovered; resetting the vault means uploading your keys again.</p>` : ''}${skip}<script type="application/json" id="vault-data">${data}</script><script type="module" src="${prefix}/oauth/vault/vault-unlock.js"></script>`, tx, true);
  }
  if (vault) {
    for (const [name, body] of Object.entries(vaultAssets())) app.get(`/oauth/vault/${name}`, (_req, res) => res.type('text/javascript').send(body));
    // Ciphertext reads and the verifier, proxied with this transaction's own upstream session.
    // Bounded per transaction: a header, up to 20 key blobs, and a few passphrase attempts.
    const vaultStep = (limit, action) => async (req, res) => {
      const tx = csrf(req);
      if (!tx || tx.phase !== 'unlock') return fail(res);
      tx.vaultRequests = (tx.vaultRequests || 0) + 1; saveTx(tx);
      if (tx.vaultRequests > limit) return fail(res, 'too_many_attempts', 429);
      try { res.json(await action(tx.credential, req.body)); }
      catch (error) { fail(res, error instanceof UpstreamError ? 'vault_unavailable' : 'invalid_request', error instanceof UpstreamError ? 502 : 400); }
    };
    // Only vault slots: never the host list ('main') or anything else on the account.
    app.post('/oauth/vault/pull', vaultStep(60, (credential, body) => { if (typeof body.slot !== 'string' || !VAULT_SLOT.test(body.slot)) throw new Error('invalid_slot'); return vault.source.pull(credential, body.slot); }));
    app.post('/oauth/vault/status', vaultStep(60, credential => vault.source.status(credential)));
    app.post('/oauth/vault/verify', vaultStep(60, (credential, body) => vault.source.verify(credential, body.auth)));
    app.post('/oauth/vault/finish', (req, res) => {
      const tx = csrf(req);
      if (!tx || tx.phase !== 'unlock') return fail(res);
      let keys = [];
      if (req.body.keys !== undefined) {
        try { keys = validateUnlock(req.body.keys, vault.hosts(tx.credential)); }
        catch { return fail(res, 'invalid_vault_keys'); }
      }
      const location = issue(tx, tx.credential, keys);
      res.clearCookie(cookieName, { path: `${prefix}/oauth` });
      if (req.is('application/json')) return res.json({ location });
      res.redirect(303, location);
    });
  }
  function mint(grantId, grant) {
    const access = secret(); const refresh = secret();
    const expiry = Math.min(grant.credential.expiry, Date.now() + 30 * DAY);
    store.put('access', digest(access), { grantId, clientId: grant.clientId, resource, scope: grant.scope || scope }, Math.min(expiry, Date.now() + 3600000));
    store.put('refresh', digest(refresh), { grantId, clientId: grant.clientId, resource }, expiry);
    return { access_token: access, token_type: 'Bearer', expires_in: Math.floor((Math.min(expiry, Date.now() + 3600000) - Date.now()) / 1000), refresh_token: refresh, scope: grant.scope || scope };
  }
  app.post('/oauth/token', (req, res) => {
    const b = req.body || {};
    if (!store.get('client', b.client_id)) return fail(res, 'invalid_client', 401);
    if (b.resource !== resource || (b.scope !== undefined && !validScope(b.scope))) return fail(res, 'invalid_target');
    const result = store.transaction(() => {
      if (b.grant_type === 'authorization_code') {
        const key = typeof b.code === 'string' ? digest(b.code) : '';
        const code = store.get('code', key);
        if (!code || code.clientId !== b.client_id || code.redirect !== b.redirect_uri || typeof b.code_verifier !== 'string' || !/^[A-Za-z0-9._~-]{43,128}$/.test(b.code_verifier) || !equal(code.challenge, createHash('sha256').update(b.code_verifier).digest('base64url'))) return null;
        const grant = store.get('grant', code.grantId);
        if (!grant || grant.revoked || (b.scope !== undefined && b.scope !== (grant.scope || scope))) return null;
        store.delete('code', key); vault?.sessions.activate(code.grantId); return mint(code.grantId, grant);
      }
      if (b.grant_type === 'refresh_token') {
        const key = typeof b.refresh_token === 'string' ? digest(b.refresh_token) : '';
        const token = store.get('refresh', key);
        if (!token || token.clientId !== b.client_id) return null;
        const grant = store.get('grant', token.grantId);
        if (!grant || grant.revoked || (b.scope !== undefined && b.scope !== (grant.scope || scope))) return null;
        if (token.used) { store.put('revoke', token.grantId, {credential:grant.credential,linked:grant.linked,attempts:0}, Date.now()); grant.revoked = true; store.put('grant', token.grantId, grant, grant.credential.expiry); vault?.sessions.drop(token.grantId); return null; }
        store.put('refresh', key, { ...token, used: true }, grant.credential.expiry);
        return mint(token.grantId, grant);
      }
      return null;
    });
    if (!result) return fail(res, 'invalid_grant');
    res.json(result);
  });
  app.post('/oauth/revoke', async (req, res) => {
    const b = req.body || {};
    const key = typeof b.token === 'string' ? digest(b.token) : '';
    const token = store.get('refresh', key) || store.get('access', key);
    if (token && token.clientId === b.client_id) {
      const grant = store.get('grant', token.grantId);
      if (grant) {
        grant.revoked = true; store.put('grant', token.grantId, grant, grant.credential.expiry);
        vault?.sessions.drop(token.grantId);
        await revokeCredentials(grant.credential, grant.linked).catch(() => { store.put('revoke', token.grantId, {credential:grant.credential, linked:grant.linked, attempts:0}, Date.now()); });
      }
    }
    res.json({});
  });
  return {
    resource, connectLink,
    // Kinds that only sweep() may delete; prune() must skip them.
    sweptKinds: ['transaction', 'revoke', 'grant'],
    // An unlock transaction that expired unused still holds a live upstream device session; revoke it.
    // A failed revoke is queued as an already-expired 'revoke' record and retried on the next sweep
    // until it succeeds or the upstream session expires by itself.
    async sweep() {
      const pending = [...store.takeExpired('grant').map(({id,value})=>({id,credential:value.credential,linked:value.linked,attempts:0})), ...store.takeExpired('transaction').map(({ id, value }) => ({ id, credential: value.credential, linked:value.linked, attempts: 0 })),
        ...store.takeExpired('revoke').map(({ id, value }) => ({ id, ...value }))];
      for (const job of pending) {
        if (!job.credential && !job.linked) continue;
        try { await revokeCredentials(job.credential, job.linked); }
        catch { store.put('revoke', job.id, { credential: job.credential, linked:job.linked, attempts: job.attempts + 1 }, Date.now()); }
      }
    },
    async authenticate(req, res, next) {
      const bearer = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.get('authorization') || '')?.[1];
      const token = bearer && store.get('access', digest(bearer));
      const grant = token && store.get('grant', token.grantId);
      if (!grant || grant.revoked || token.resource !== resource || token.scope !== (grant.scope || scope) || grant.credential.expiry <= Date.now()) { if (token) vault?.sessions.drop(token.grantId); return challenge(res); }
      try {
        // Live validation makes upstream logout / device-session revocation effective immediately.
        const identity = await upstream.identity(grant.credential);
        if (identity.id !== grant.credential.identity.id || !allowedEmails.includes(identity.email)) { vault?.sessions.drop(token.grantId); return challenge(res); }
        req.credential = grant.credential; req.grantId = token.grantId; req.readOnly = !!grant.readOnly; req.scopes = (grant.scope || scope).split(' '); req.linked = grant.linked || {}; next();
      } catch (error) {
        if (error instanceof UpstreamError && [401,403].includes(error.status)) { vault?.sessions.drop(token.grantId); return challenge(res); }
        return fail(res, 'temporarily_unavailable', 503);
      }
    },
  };
}
