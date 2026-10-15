// Run as the service user with the same encrypted store and key. Secrets only on stdin.
import { Store, digest } from '../src/store.mjs';
import { validateProfile } from '../src/pocketshell.mjs';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
process.umask(0o077);
const email = process.argv[2];
if (!email?.includes('@')) throw new Error('Usage: node scripts/provision-profile.mjs <account-email> < private-profile.json');
const profile = validateProfile(JSON.parse(readFileSync(0, 'utf8')));
const store = new Store(join(process.env.MCP_STATE_DIR || '/var/lib/pocketshell-mcp', 'oauth.sqlite'), process.env.MCP_STORAGE_KEY_FILE ? readFileSync(process.env.MCP_STORAGE_KEY_FILE, 'utf8').trim() : process.env.MCP_STORAGE_KEY);
store.put('profile', digest(`pocketshell:${email.toLowerCase()}`), profile, 8640000000000000);
store.close(); console.log('Encrypted SSH profile saved.');
