import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { build } from 'esbuild';
const clientCommit = '1384f1b8a0d30a5e227f0c1b2bf87594696f6b56';
const coreCommit = 'e87040d19773a710c6813307c98391209b3ddbe1';
const temp = process.argv[2] ? null : mkdtempSync(join(tmpdir(), 'mcp-build-'));
const client = process.argv[2] ? resolve(process.argv[2]) : join(temp, 'pocketshell-client');
function run(command, args, cwd) { execFileSync(command, args, { cwd, stdio: 'inherit' }); }
try {
  if (temp) {
    for (const [repo, directory, commit] of [['pocketshell-core', 'pocketshell-core', coreCommit], ['pocketshell-tui-client', 'pocketshell-client', clientCommit]]) {
      const dir = join(temp, directory);
      run('git', ['clone', '--quiet', `https://github.com/PocketShell-io/${repo}.git`, dir]);
      run('git', ['checkout', '--quiet', commit], dir);
      run('npm', ['ci', '--ignore-scripts'], dir);
      if (repo === 'pocketshell-core') run('npm', ['run', 'build'], dir);
    }
  }
  mkdirSync('vendor', { recursive: true });
  await build({ entryPoints: [join(client, 'src/cli.ts')], outfile: 'vendor/psc.mjs', bundle: true, platform: 'node', target: 'node24', format: 'esm', banner: { js: "import { createRequire as __pscCreateRequire } from 'node:module'; const require = __pscCreateRequire(import.meta.url);" } });
  await build({ entryPoints: [join(client, 'src/clientCore.ts')], outfile: 'vendor/client-core.mjs', bundle: true, platform: 'node', target: 'node24', format: 'esm', banner: { js: "import { createRequire as __pscCreateRequire } from 'node:module'; const require = __pscCreateRequire(import.meta.url);" } });
  console.log('Built shared PocketShell core and CLI runtimes (excluded from Git).');
} finally { if (temp) rmSync(temp, { recursive: true, force: true }); }
