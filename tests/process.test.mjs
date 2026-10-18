import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { secret } from '../src/store.mjs';
import { executePsc } from '../src/pocketshell.mjs';

test('SSH subprocess receives private isolated files, no credential environment, and cleans them after success/failure',async t=>{
 const root=await mkdtemp(join(tmpdir(),'mcp-child-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const entrypoint=join(root,'fixture.mjs'),runtimeRoot=join(root,'runtime');
 await writeFile(entrypoint,`import {readFileSync,statSync} from 'node:fs';import {join} from 'node:path';const root=process.env.XDG_CONFIG_HOME;const c=JSON.parse(readFileSync(join(root,'pocketshell/credentials.json'),'utf8'));const hosts=JSON.parse(readFileSync(join(root,'pocketshell-tui-client/hosts.json'),'utf8'));console.log(JSON.stringify({ok:true,accountPresent:!!c.access_token,gatewayServer:hosts.hosts[0].gateway.server,keyMode:statSync(hosts.hosts[0].gateway.identityFile).mode&511,pinMode:statSync(join(root,'pocketshell/gateway_known_hosts')).mode&511,credentialMode:statSync(join(root,'pocketshell/credentials.json')).mode&511,credentialInEnv:Object.keys(process.env).some(x=>/TOKEN|SECRET|STORAGE_KEY/.test(x))}));`);
 const options={profile:{hosts:[{name:'example-host',deviceId:'example-device',user:'example-user'}],privateKey:secret(),pins:'synthetic'},credential:{token:secret(),tokenId:'synthetic',expiry:Date.now()+10000,identity:{email:'operator@example.com'}},broker:'https://broker.example.com',gateway:'https://gateway.example.com',runtimeRoot,stdin:'',entrypoint};
 const result=await executePsc([],options);assert.deepEqual(result,{ok:true,accountPresent:true,gatewayServer:'wss://gateway.example.com',keyMode:384,pinMode:384,credentialMode:384,credentialInEnv:false});assert.deepEqual(await readdir(runtimeRoot),[]);
 await writeFile(entrypoint,`process.stderr.write('synthetic secret diagnostic');process.exit(1);`);
 await assert.rejects(()=>executePsc([],options),error=>!error.message.includes('synthetic secret diagnostic'));
 assert.deepEqual(await readdir(runtimeRoot),[]);
});
test('a timed-out SSH process tree is killed before private files are removed',async t=>{
 const root=await mkdtemp(join(tmpdir(),'mcp-timeout-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const entrypoint=join(root,'fixture.mjs'),pidFile=join(root,'child.pid'),runtimeRoot=join(root,'runtime');
 await writeFile(entrypoint,`import {spawn} from 'node:child_process';import {writeFileSync} from 'node:fs';const child=spawn(process.execPath,['-e','setInterval(()=>{},1000)']);writeFileSync(process.argv[2],String(child.pid));setInterval(()=>{},1000);`);
 await assert.rejects(()=>executePsc([pidFile],{profile:{hosts:[],privateKey:secret(),pins:'synthetic'},credential:{token:secret(),expiry:Date.now()+10000,identity:{email:'operator@example.com'}},broker:'https://broker.example.com',gateway:'https://gateway.example.com',runtimeRoot,stdin:'',entrypoint,timeoutMs:300}));
 assert.deepEqual(await readdir(runtimeRoot),[]);
 // Linux reports an orphaned killed child briefly as a zombie; no running process may remain.
 const {readFile}=await import('node:fs/promises');const pid=Number(await readFile(pidFile,'utf8'));
 for (let attempt=0;;attempt++) {
  try {const status=await readFile(`/proc/${pid}/status`,'utf8');if (/State:\s+Z/.test(status)) break;if(attempt>=50) assert.fail('Child process still running after kill');}
  catch(error){if(error.code==='ENOENT'||error.code==='ESRCH') break;throw error;}
  await new Promise(resolve=>setTimeout(resolve,20));
 }
});
