import { z } from 'zod';
import { requestJson, UpstreamError } from './upstream.mjs';
import { digest } from './store.mjs';

// Pluggable per-CLI authentication. An auth type validates its own operator config block and
// creates two things for a registered CLI:
//   auth         the linking plugin the browser pages drive. Either
//                  { type:'device', start(label), poll(deviceCode), revoke(credential), identity?(credential) }
//                (the gateway logs in as its own device, labelled "MCP gateway, <assistant>"), or
//                  { type:'token', accept(token, primary), revoke() }
//                (pasted once on the gateway's HTTPS page, never in chat or tool arguments).
//   materialize  maps a stored credential to the files/environment the CLI expects inside its
//                worker. Nothing else in the worker sees the credential.
// A new auth type is one registerAuthType() call; plugins.mjs needs no change.
export const httpsOrigin = z.string().refine(value => { try { const u = new URL(value); return u.protocol === 'https:' && u.origin === value; } catch { return false; } }, 'Bare HTTPS origin required');
export const envName = z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/).refine(x => !/^(?:NODE_|LD_|DYLD_|PATH$|HOME$|XDG_)/.test(x), 'Reserved environment name');
// Relative to the worker's private HOME (also XDG_CONFIG_HOME): `name`, `.name` or `dir/name`.
export const workerFile = z.string().regex(/^\.?[a-zA-Z0-9_-][a-zA-Z0-9_.-]*(?:\/[a-zA-Z0-9_-][a-zA-Z0-9_.-]*)?$/);
const authTypes = new Map();
export function registerAuthType(name, { config, create }) {
  if (!/^[a-z][a-z0-9-]{0,31}$/.test(name) || authTypes.has(name) || typeof create !== 'function') throw new Error('Invalid auth type registration');
  authTypes.set(name, { config, create });
}
export function createAuth(raw, { origin }) {
  const type = authTypes.get(raw?.type);
  if (!type) throw new Error(`Unknown auth type: ${String(raw?.type).slice(0, 32)}`);
  return type.create(type.config.parse(raw), { origin });
}

// Replaces {token} and {origin} in every string of a JSON template.
function fill(template, values) {
  if (typeof template === 'string') return template.replace(/\{(token|origin)\}/g, (_, key) => values[key]);
  if (Array.isArray(template)) return template.map(x => fill(x, values));
  if (template && typeof template === 'object') return Object.fromEntries(Object.entries(template).map(([k, v]) => [k, fill(v, values)]));
  return template;
}
const mentionsToken = value => JSON.stringify(value ?? null).includes('{token}');

export function staticTokenAuth({ validate = async () => {}, lifetimeMs = 30 * 86400000 } = {}) {
  return { type:'token', async accept(token, primary) {
    if (typeof token !== 'string' || token.length < 12 || token.length > 8192 || /\s|[\x00-\x1f\x7f{}]/.test(token)) throw new Error('Invalid token');
    await validate(token);
    // A static token proves no identity of its own; it is bound to the account that pasted it.
    return {token,expiry:Date.now()+lifetimeMs,identity:primary.identity};
  }, async revoke() {} };
}

// Static token or API key, injected as environment variables and/or private config files.
// `tokenEnv` is shorthand for env: { NAME: '{token}' }.
registerAuthType('token', {
  config: z.strictObject({
    type: z.literal('token'), tokenEnv: envName.optional(),
    env: z.record(envName, z.string().max(1024)).default({}),
    files: z.record(workerFile, z.json()).default({}),
    validate: z.strictObject({ path: z.string().regex(/^\/[A-Za-z0-9/_-]+$/), scheme: z.enum(['Bearer', 'Token']).default('Bearer') }).optional(),
    lifetimeDays: z.number().int().min(1).max(365).default(30),
  }).refine(c => c.tokenEnv || mentionsToken(c.env) || mentionsToken(c.files), 'Token auth must inject {token} somewhere'),
  create(config, { origin }) {
    const env = { ...config.env, ...(config.tokenEnv ? { [config.tokenEnv]: '{token}' } : {}) };
    return {
      auth: staticTokenAuth({ lifetimeMs: config.lifetimeDays * 86400000, validate: async token => { if (config.validate) await requestJson(origin, config.validate.path, { token, scheme: config.validate.scheme }); } }),
      materialize: credential => {
        const values = { token: credential.token, origin };
        return { environment: fill(env, values), files: Object.fromEntries(Object.entries(config.files).map(([path, body]) => { const value = fill(body, values); return [path, typeof value === 'string' ? value : JSON.stringify(value)]; })) };
      },
    };
  },
});

export function dapierDeviceAuth(base) {
  httpsOrigin.parse(base);
  const call = (path, options) => requestJson(base, path, options);
  return { type:'device',
    async start(label) {
      const raw = await call('/api/agent/device/start', { method:'POST', body:{ label } });
      if (typeof raw.device_code !== 'string' || typeof raw.user_code !== 'string' || !/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(raw.user_code) || !Number.isInteger(raw.expires_in) || raw.expires_in < 1 || raw.expires_in > 3600) throw new UpstreamError(502, 'invalid_device_response');
      const approval = new URL('/device', base); approval.searchParams.set('code', raw.user_code);
      return { deviceCode:raw.device_code, userCode:raw.user_code, approval:approval.href, expiry:Date.now()+raw.expires_in*1000, interval:Math.max(1, Math.min(60, Number(raw.interval) || 5)) };
    },
    async poll(deviceCode) {
      const raw = await call('/api/agent/device/token', { method:'POST', body:{ device_code:deviceCode } });
      if (typeof raw.token !== 'string' || raw.token.length < 20 || typeof raw.email !== 'string' || !raw.email.includes('@') || !Number.isFinite(raw.expires_at) || raw.expires_at * 1000 <= Date.now()) throw new UpstreamError(502, 'invalid_token_response');
      return { token:raw.token, expiry:raw.expires_at*1000, identity:{ id:digest(`dapier:${raw.email.toLowerCase()}`), email:raw.email.toLowerCase() }, subject:raw.subject };
    },
    // Every CLI request itself goes through Dapier's live bearer/session check.
    async revoke(credential) { await call('/api/agent/device/revoke', { method:'POST', body:{}, token:credential.token }); },
  };
}
registerAuthType('dapier-device', {
  config: z.strictObject({ type: z.literal('dapier-device') }),
  create: (_config, { origin }) => ({
    auth: dapierDeviceAuth(origin),
    materialize: credential => ({ files: { 'dapier/session.json': JSON.stringify({ token:credential.token, kind:'device', subject:credential.subject, email:credential.identity.email, expires_at:credential.expiry/1000 }) } }),
  }),
});
