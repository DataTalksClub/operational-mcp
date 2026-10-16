import { z } from 'zod';
import { readFileSync } from 'node:fs';
import { dirname, isAbsolute } from 'node:path';
import { pocketDefinitions } from './pocketshell.mjs';
import { runWorker } from './worker.mjs';
export function pocketRegistration(tools) {
  const definitions = pocketDefinitions();
  const manifest = {version:1, namespace:'pocketshell', description:'Control PocketShell hosts and sessions.', commands: definitions.map(tool => {
    const inputSchema = z.toJSONSchema(tool.schema, { unrepresentable:'any' });
    delete inputSchema.$schema;
    const positional = Object.keys(inputSchema.properties).filter(x => ['host','session','tag'].includes(x));
    const flags = Object.fromEntries(Object.keys(inputSchema.properties).filter(x => !positional.includes(x)).map(x => [x, {field:x,kind: x === 'enter' || x === 'text' ? 'json' : 'value'}]));
    return {path:[tool.name],description:tool.description,inputSchema,positional,flags,read:tool.read,destructive:!!tool.destructive};
  })};
  return {manifest, execute: (parsed, credential, context) => {
    const name = parsed.command.path[0]; const definition = definitions.find(t=>t.name===name);
    return tools.call(name, definition.schema.parse(parsed.values), credential, context);
  }};
}
export function cliRegistration({manifest, command, prefix = [], mounts = [], environment = {}, auth, credentials, runtimeRoot, run = runWorker}) {
  if (!isAbsolute(command) || prefix.some(x=>typeof x!=='string')) throw new Error('Configured absolute CLI command required');
  return { manifest, auth, execute: async (parsed, credential, context) => {
    const material = await credentials(credential);
    return run({ command, prefix, mounts, argv:[...parsed.argv, ...(material.suffix || [])], runtimeRoot,
      files:material.files, environment:{...environment,...material.environment}, secretValues:[credential.token],
      signal:context?.signal,timeoutMs:parsed.command.timeoutMs,maxOutputBytes:parsed.command.maxOutputBytes,output:parsed.command.output });
  }};
}
export function dataopsRegistration({entrypoint, upstream, runtimeRoot, run, command = process.execPath}) {
  if (!isAbsolute(entrypoint)) throw new Error('Configured DataOps CLI entrypoint required');
  return cliRegistration({ manifest:JSON.parse(readFileSync(new URL('../manifests/dataops.json',import.meta.url))), command, prefix:[entrypoint], mounts:[dirname(dirname(entrypoint))], auth:upstream, runtimeRoot, run,
    credentials: credential => ({ suffix:['--json'], environment:{DATAOPS_URL:upstream.base,DATAOPS_CONFIG_DIR:'{worker}'},files:{'credentials.json':JSON.stringify({defaultUrl:upstream.base,profiles:{[upstream.base]:{token:credential.token,tokenId:credential.tokenId,expiresAt:new Date(credential.expiry).toISOString(),user:{email:credential.identity.email}}}})} }) });
}
export { staticTokenAuth } from './auth.mjs';
