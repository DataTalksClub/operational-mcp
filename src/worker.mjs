import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join, resolve, isAbsolute } from 'node:path';

// Bubblewrap inherits only the clean environment supplied by spawn. Credentials never enter argv.
export function sandboxCommand(command, args, { directory, mounts = [], sandbox = 'bwrap' }) {
  if (!isAbsolute(command) || !isAbsolute(directory)) throw new Error('Absolute runtime paths required');
  if (sandbox !== 'bwrap') throw new Error('An OS worker sandbox is required');
  const argv = ['--die-with-parent', '--new-session', '--unshare-user', '--unshare-pid', '--unshare-ipc', '--unshare-uts', '--cap-drop', 'ALL'];
  for (const path of ['/usr', '/bin', '/lib', '/lib64', '/etc/ssl', '/etc/resolv.conf', '/etc/hosts']) if (existsSync(path)) argv.push('--ro-bind', path, path);
  for (const path of mounts) {
    if (!isAbsolute(path) || path === '/' || path.startsWith('/proc') || path.startsWith('/run') || path.startsWith('/var')) throw new Error('Unsafe runtime mount');
    argv.push('--ro-bind', path, path);
  }
  argv.push('--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--bind', directory, directory, '--chdir', directory, '--', command, ...args);
  return { command: '/usr/bin/bwrap', args: argv };
}
export async function runWorker({ command, prefix = [], argv, runtimeRoot, mounts, files = {}, environment = {}, secretValues = [], timeoutMs, maxOutputBytes, output, signal, launch = sandboxCommand }) {
  await mkdir(runtimeRoot, { recursive: true, mode: 0o700 });
  const directory = await mkdtemp(join(resolve(runtimeRoot), 'worker-'));
  try {
    for (const [name, body] of Object.entries(files)) {
      if (!/^\.?[a-zA-Z0-9_-][a-zA-Z0-9_.-]*(?:\/[a-zA-Z0-9_-][a-zA-Z0-9_.-]*)?$/.test(name)) throw new Error('Unsafe credential filename');
      if (name.includes('/')) await mkdir(join(directory, name.split('/')[0]), {mode:0o700});
      await writeFile(join(directory, name), body, { mode: 0o600, flag: 'wx' });
    }
    const env = { PATH: '/usr/local/bin:/usr/bin:/bin', LANG: 'C.UTF-8', HOME: directory, XDG_CONFIG_HOME: directory, ...environment };
    for (const [key, value] of Object.entries(env)) {
      if (typeof value !== 'string' || /\x00/.test(value) || /^(?:NODE_OPTIONS|LD_|DYLD_|BASH_ENV|ENV$)/.test(key)) throw new Error('Unsafe worker environment');
      env[key] = value.replaceAll('{worker}', directory);
    }
    const target = launch(command, [...prefix, ...argv], { directory, mounts });
    return await new Promise((resolveRun, reject) => {
      const child = spawn(target.command, target.args, { env, cwd: directory, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
      let count = 0, failed = false; const chunks = [];
      const stop = () => { try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); } };
      const abort = () => {failed=true;stop();};
      signal?.addEventListener('abort',abort,{once:true}); if(signal?.aborted) abort();
      const timer = setTimeout(abort, timeoutMs); timer.unref();
      const bounded = data => { count += data.length; if (count > maxOutputBytes) { failed = true; stop(); return false; } return true; };
      child.stdout.on('data', data => { if (bounded(data)) chunks.push(data); }); child.stderr.on('data', bounded);
      child.once('exit', stop);
      child.once('error', () => { clearTimeout(timer); signal?.removeEventListener('abort',abort); reject(new Error('Worker unavailable')); });
      child.once('close', code => {
        clearTimeout(timer); signal?.removeEventListener('abort',abort);
        if (failed || code !== 0) return reject(new Error('CLI operation failed; inspect connection and command help before retrying'));
        const text = Buffer.concat(chunks).toString('utf8');
        if (secretValues.some(value => value && text.includes(value))) return reject(new Error('Credential output refused'));
        try { resolveRun(output === 'json' ? JSON.parse(text) : { text }); } catch { reject(new Error('Invalid CLI output')); }
      });
    });
  } finally { await rm(directory, { recursive: true, force: true }); }
}
