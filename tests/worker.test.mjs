import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runWorker, sandboxCommand } from '../src/worker.mjs';
const direct = (command,args) => ({command,args}); // Only the test harness can inject this launcher.
test('worker bounds diagnostics, refuses credential output and cleans private directories',async t=>{
 const runtimeRoot=await mkdtemp(join(tmpdir(),'mcp-worker-'));t.after(()=>rm(runtimeRoot,{recursive:true,force:true}));
 const opts={command:process.execPath,prefix:['-e'],runtimeRoot,timeoutMs:1000,maxOutputBytes:2048,output:'json',launch:direct};
 const result=await runWorker({...opts,argv:[`const fs=require('fs');console.log(JSON.stringify({mode:fs.statSync(process.env.HOME+'/credentials.json').mode&511,ambient:process.env.MCP_STORAGE_KEY||null}));`],files:{'credentials.json':'synthetic'}});
 assert.deepEqual(result,{mode:384,ambient:null});
 await assert.rejects(()=>runWorker({...opts,argv:[`console.log(JSON.stringify({secret:'synthetic-credential'}))`],secretValues:['synthetic-credential']}),/Credential output refused/);
 await assert.rejects(()=>runWorker({...opts,argv:[`process.stderr.write('x'.repeat(4096));setInterval(()=>{},100)`]}));
 await assert.rejects(()=>runWorker({...opts,argv:[`setInterval(()=>{},100)`],timeoutMs:100}));
 assert.deepEqual(await readdir(runtimeRoot),[]);
});
test('production launcher requires isolation and mounts only the call and approved runtime',()=>{
 assert.throws(()=>sandboxCommand('/usr/bin/node',[],{directory:'/tmp/call',sandbox:'none'}));
 assert.throws(()=>sandboxCommand('/usr/bin/node',[],{directory:'/tmp/call',mounts:['/']}));
 const target=sandboxCommand('/usr/bin/node',['/opt/example/cli.mjs'],{directory:'/tmp/call',mounts:['/opt/example']});
 assert.equal(target.command,'/usr/bin/bwrap');assert.ok(target.args.includes('--unshare-pid'));assert.ok(!target.args.includes('/home'));assert.ok(!target.args.includes('/var/lib'));
});
