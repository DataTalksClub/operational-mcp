import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Store } from './store.mjs';
import { pocketUpstream, dataopsUpstream } from './upstream.mjs';
import { pocketTools } from './pocketshell.mjs';
import { dataopsTools } from './dataops.mjs';
import { createApp } from './app.mjs';
process.umask(0o077);
const kind = process.env.MCP_SERVICE || 'pocketshell';
if (!['pocketshell','dataops'].includes(kind)) throw new Error('Unknown MCP_SERVICE');
const state = process.env.MCP_STATE_DIR || '/var/lib/pocketshell-mcp';
const storageKey = process.env.MCP_STORAGE_KEY_FILE ? readFileSync(process.env.MCP_STORAGE_KEY_FILE, 'utf8').trim() : process.env.MCP_STORAGE_KEY;
const store = new Store(join(state, 'oauth.sqlite'), storageKey);
const remoteConfig = { base: process.env.MCP_UPSTREAM_ORIGIN, webOrigin: process.env.MCP_WEB_ORIGIN, gatewayOrigin: process.env.MCP_GATEWAY_ORIGIN };
const remote = kind === 'pocketshell'
  ? pocketUpstream({ ...remoteConfig, core: await import('../vendor/client-core.mjs') })
  : dataopsUpstream(remoteConfig);
const tools = kind === 'pocketshell' ? pocketTools({ store, upstream: remote }) : dataopsTools({ upstream: remote });
const app = createApp({ store, upstream: remote, tools, issuer: process.env.MCP_ISSUER,
  allowedEmails: (process.env.MCP_ALLOWED_EMAILS || '').split(',').map(x=>x.trim().toLowerCase()).filter(Boolean),
  redirectUris: (process.env.MCP_REDIRECT_URIS || '').split(',').map(x=>x.trim()).filter(Boolean),
});
const server = app.listen(Number(process.env.PORT || 8080), process.env.MCP_BIND || 'localhost', () => console.log(`${kind} MCP listening`));
const timer = setInterval(() => store.prune(), 60000); timer.unref();
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { server.close(() => { clearInterval(timer); store.close(); process.exit(0); }); });
