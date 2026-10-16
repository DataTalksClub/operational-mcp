import { z } from 'zod';
const word = z.string().regex(/^[a-z][a-z0-9_-]{0,47}$/);
const argument = word;
const commandSchema = z.strictObject({
  path: z.array(word).min(1).max(5), description: z.string().min(1).max(240),
  inputSchema: z.record(z.string(), z.json()),
  positional: z.array(argument).max(12).default([]),
  flags: z.record(word, z.strictObject({ field: argument, kind: z.enum(['value', 'boolean', 'json']).default('value') })).default({}),
  read: z.boolean(), destructive: z.boolean().default(false),
  timeoutMs: z.number().int().min(100).max(120000).default(30000),
  maxOutputBytes: z.number().int().min(1024).max(1048576).default(262144),
  output: z.enum(['json', 'text']).default('json'),
});
const manifestSchema = z.strictObject({ version: z.literal(1), namespace: word, description: z.string().min(1).max(120), commands: z.array(commandSchema).min(1).max(200) });
const safeValue = value => typeof value === 'string' && value.length <= 32768 && !/^[\-@]|[\x00-\x1f\x7f]/.test(value);
export function compileManifest(raw) {
  const manifest = manifestSchema.parse(raw); const seen = new Set();
  for (const command of manifest.commands) {
    const key = command.path.join(' ');
    if (seen.has(key) || (command.read && command.destructive)) throw new Error('Conflicting command classification');
    // `help` and `connect` are gateway verbs on every CLI tool, so no command may shadow them.
    if (['help', 'connect'].includes(command.path[0])) throw new Error('Reserved command name');
    seen.add(key);
    if (command.inputSchema.type !== 'object' || command.inputSchema.additionalProperties !== false) throw new Error('Command schema must be a closed object');
    const fields = Object.keys(command.inputSchema.properties || {});
    const mapped = [...command.positional, ...Object.values(command.flags).map(f => f.field)];
    if (new Set(mapped).size !== mapped.length || fields.length !== mapped.length || mapped.some(x => !fields.includes(x))) throw new Error('Every field must have exactly one argv mapping');
    command.validate = z.fromJSONSchema(command.inputSchema);
    command.scope = `${manifest.namespace}:${command.path.join('.')}`;
  }
  return manifest;
}
// Describes one level: groups below `path` with counts, commands directly at it, and the full
// schema only for an exact command path. Large CLIs never dump every command into context.
export function commandHelp(manifest, path = [], allowed = () => true) {
  const below = manifest.commands.filter(c => allowed(c) && c.path.length >= path.length && path.every((part, i) => c.path[i] === part));
  const summary = c => ({ command: c.path.join(' '), description: c.description, read: c.read, destructive: c.destructive, requiresApproval: !c.read, scope: c.scope });
  const exact = below.filter(c => c.path.length === path.length).map(c => ({ ...summary(c), inputSchema: c.inputSchema, positional: c.positional, flags: c.flags, timeoutMs: c.timeoutMs }));
  const groups = new Map();
  for (const c of below.filter(c => c.path.length > path.length + 1)) {
    const name = c.path[path.length]; const group = groups.get(name) || { group: [...path, name].join(' '), commands: 0, writes: 0 };
    group.commands++; if (!c.read) group.writes++; groups.set(name, group);
  }
  return { cli: manifest.namespace, description: manifest.description, path,
    commands: [...exact, ...below.filter(c => c.path.length === path.length + 1).map(summary)], groups: [...groups.values()],
    usage: 'Pass argv as an array. Use help followed by a group or command path for the next level; a full command path shows its schema. Writes also require approved: true. Use connect to link this CLI account in the browser.' };
}
export function parseCommand(manifest, argv) {
  if (!Array.isArray(argv) || argv.length > 64 || argv.some(x => typeof x !== 'string' || x.length > 32768 || /[\x00-\x1f\x7f]/.test(x)) || Buffer.byteLength(JSON.stringify(argv)) > 65536) throw new Error('Invalid argv');
  if (!argv.length || argv[0] === 'help' || argv.includes('--help')) {
    const path = argv[0] === 'help' ? argv.slice(1) : argv.filter(x => x !== '--help');
    if (path.some(x => !/^[a-z][a-z0-9_-]*$/.test(x))) throw new Error('Invalid help path');
    return { help: path };
  }
  if (argv[0] === 'connect') { if (argv.length > 1) throw new Error('connect takes no arguments'); return { connect: true }; }
  const command = [...manifest.commands].sort((a, b) => b.path.length - a.path.length).find(c => c.path.every((part, i) => argv[i] === part));
  if (!command) throw new Error('Command is not registered; use help');
  const fields = {}; let pos = 0;
  for (let i = command.path.length; i < argv.length; i++) {
    const token = argv[i];
    if (token.startsWith('--')) {
      const at = token.indexOf('='); const name = token.slice(2, at < 0 ? undefined : at);
      const flag = command.flags[name];
      if (!Object.hasOwn(command.flags, name) || Object.hasOwn(fields, flag.field)) throw new Error('Unknown or duplicate option');
      if (flag.kind === 'boolean') { if (at >= 0) throw new Error('Boolean flag takes no value'); fields[flag.field] = true; continue; }
      const value = at < 0 ? argv[++i] : token.slice(at + 1);
      if (!safeValue(value)) throw new Error('Unsafe argument value');
      fields[flag.field] = flag.kind === 'json' ? JSON.parse(value) : value;
    } else {
      const field = command.positional[pos++];
      if (!field || !safeValue(token)) throw new Error('Unexpected positional argument');
      fields[field] = token;
    }
  }
  const values = command.validate.parse(fields);
  const result = [...command.path];
  for (const field of command.positional) if (values[field] !== undefined) result.push(String(values[field]));
  for (const [name, flag] of Object.entries(command.flags)) {
    const value = values[flag.field]; if (value === undefined || value === false) continue;
    result.push(flag.kind === 'boolean' ? `--${name}` : `--${name}=${flag.kind === 'json' ? JSON.stringify(value) : String(value)}`);
  }
  return { command, values, argv: result };
}
