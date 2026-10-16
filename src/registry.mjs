import { z } from 'zod';
import { compileManifest, parseCommand, commandHelp } from './manifest.mjs';
const schema = z.strictObject({ argv: z.array(z.string().max(32768)).max(64).default([]), approved: z.boolean().default(false) });
export function gatewayTools(registrations, { globalLimit = 8, perUserLimit = 2 } = {}) {
  const entries = new Map(); const active = new Map(); const writing = new Set(); let total = 0;
  for (const registration of registrations) {
    const manifest = compileManifest(registration.manifest);
    if (entries.has(manifest.namespace) || manifest.namespace === 'catalog') throw new Error('Duplicate CLI registration');
    entries.set(manifest.namespace, { ...registration, manifest });
  }
  const scopes = ['gateway:catalog', ...[...entries.values()].flatMap(e => e.manifest.commands.map(c => c.scope))];
  const readScopes = ['gateway:catalog', ...[...entries.values()].flatMap(e => e.manifest.commands.filter(c => c.read).map(c => c.scope))];
  return {
    scopes, readScopes,
    definitions: [{ name: 'catalog', description: 'List registered CLIs. Call a CLI with help for commands.', schema: z.strictObject({}), read: true },
      ...[...entries.values()].map(({manifest}) => ({ name: manifest.namespace, description: manifest.description + ' Use empty argv or help to discover commands.', schema, mixed: true, read: manifest.commands.every(c => c.read), destructive: manifest.commands.some(c => !c.read) }))],
    async call(name, input, primary, context = {}) {
      const granted = new Set(context.scopes || []);
      const permits = c => granted.has(c.scope) && (!context.readOnly || c.read);
      if (name === 'catalog') {
        if (!granted.has('gateway:catalog')) throw new Error('Insufficient scope');
        return { clis: [...entries.values()].map(({manifest}) => ({ name: manifest.namespace, description: manifest.description, connected: manifest.namespace === 'pocketshell' || !!context.linked?.[manifest.namespace], commands: manifest.commands.filter(permits).length })), usage: 'Call a CLI with empty argv, then help followed by a group or command path. Call a CLI with argv ["connect"] for a browser link that connects its account.' };
      }
      const entry = entries.get(name); if (!entry) throw new Error('Unknown CLI');
      const args = schema.parse(input); const parsed = parseCommand(entry.manifest, args.argv);
      if (parsed.help) return commandHelp(entry.manifest, parsed.help, permits);
      // The link is a single-use browser page bound to this grant; it never carries a credential.
      const connectLink = () => ({ cli: name, connect: context.connect?.(name) || null, message: 'Open this link in your browser to connect the account. It expires in 10 minutes and works once. Never paste credentials into chat.' });
      if (parsed.connect) {
        if (name === 'pocketshell') return { cli: name, connected: true, message: 'PocketShell is this connection\'s own login. Reconnect the connector to change it.' };
        if (!entry.manifest.commands.some(permits)) throw new Error('Insufficient command scope');
        return { ...connectLink(), connected: !!context.linked?.[name] };
      }
      const command = parsed.command;
      if (!permits(command)) throw new Error('Insufficient command scope');
      if (!command.read && !args.approved) return { approvalRequired: true, command: command.path.join(' '), scope: command.scope, destructive: command.destructive, message: 'Confirm this action with the user, then repeat with approved: true. A timeout may follow a completed write; do not retry blindly.' };
      const credential = name === 'pocketshell' ? primary : context.linked?.[name];
      if (!credential || credential.expiry <= Date.now()) return { connectionRequired: true, ...connectLink() };
      // Device tokens must still identify the same linked account. Static adapters may implement
      // a service-specific validation instead. No ambient credentials enter an execution adapter.
      if (entry.auth?.identity) {
        const identity = await entry.auth.identity(credential);
        if (identity.id !== credential.identity.id) throw new Error('Linked identity changed');
      }
      const user = primary.identity.id;
      if (total >= globalLimit || (active.get(user) || 0) >= perUserLimit || (!command.read && writing.has(user))) throw new Error('Worker concurrency limit');
      total++; active.set(user, (active.get(user) || 0) + 1); if (!command.read) writing.add(user);
      try { return await entry.execute(parsed, credential, context); }
      finally { total--; const remaining = active.get(user) - 1; if (remaining) active.set(user, remaining); else active.delete(user); if (!command.read) writing.delete(user); }
    },
  };
}
