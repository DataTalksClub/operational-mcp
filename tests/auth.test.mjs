import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAuth, registerAuthType } from '../src/auth.mjs';
import { loadCliRegistrations } from '../src/plugins.mjs';
import { runWorker } from '../src/worker.mjs';
const origin='https://cli.example.com',primary={identity:{id:'one',email:'one@example.com'}};
const token='synthetic-token-0123456789';
test('token auth injects the pasted token as the env vars and private config files the CLI expects',async t=>{
 const {auth,materialize}=createAuth({type:'token',tokenEnv:'EXAMPLE_TOKEN',env:{EXAMPLE_HEADER:'Token {token}'},files:{'.examplerc':'token={token}\n','example/config.json':{url:'{origin}',auth:{token:'{token}'}}}},{origin});
 assert.equal(auth.type,'token');
 const credential=await auth.accept(token,primary);assert.deepEqual(credential.identity,primary.identity);
 const material=materialize(credential);
 assert.deepEqual(material.environment,{EXAMPLE_HEADER:`Token ${token}`,EXAMPLE_TOKEN:token});
 assert.deepEqual(JSON.parse(material.files['example/config.json']),{url:origin,auth:{token}});
 // The worker writes exactly those private files into the per-call home.
 const runtimeRoot=await mkdtemp(join(tmpdir(),'mcp-auth-'));t.after(()=>rm(runtimeRoot,{recursive:true,force:true}));
 const seen=await runWorker({command:process.execPath,prefix:['-e'],argv:[`const fs=require('fs');console.log(JSON.stringify({rc:fs.readFileSync(process.env.HOME+'/.examplerc','utf8').length,config:fs.statSync(process.env.HOME+'/example/config.json').mode&511,env:!!process.env.EXAMPLE_TOKEN}))`],
  runtimeRoot,files:material.files,environment:material.environment,timeoutMs:2000,maxOutputBytes:4096,output:'json',launch:(command,args)=>({command,args})});
 assert.deepEqual(seen,{rc:`token=${token}\n`.length,config:0o600,env:true});
 for(const bad of ['short','has space token value','brace{worker}token-value'])await assert.rejects(()=>auth.accept(bad,primary));
});
test('token validation calls only the configured origin with the declared scheme',async t=>{
 const original=globalThis.fetch;t.after(()=>{globalThis.fetch=original;});let request;
 globalThis.fetch=async(url,options)=>{request={url:String(url),authorization:options.headers.Authorization};return new Response('{}',{status:200});};
 const {auth}=createAuth({type:'token',tokenEnv:'EXAMPLE_TOKEN',validate:{path:'/api/me',scheme:'Token'}},{origin});
 await auth.accept(token,primary);assert.deepEqual(request,{url:`${origin}/api/me`,authorization:`Token ${token}`});
 globalThis.fetch=async()=>new Response('{"error":"invalid_token"}',{status:401});
 await assert.rejects(()=>auth.accept(token,primary));
});
test('auth configs are strict, and a new auth type is one registration',async t=>{
 for(const bad of [{type:'token'},{type:'token',env:{EXAMPLE:'static'}},{type:'token',tokenEnv:'PATH'},{type:'token',files:{'../escape':'{token}'}},{type:'token',tokenEnv:'X_TOKEN',extra:1},{type:'oauth-magic'}])assert.throws(()=>createAuth(bad,{origin}));
 assert.throws(()=>registerAuthType('token',{config:null,create(){}}));
 registerAuthType('example-header',{config:(await import('zod')).z.strictObject({type:(await import('zod')).z.literal('example-header')}),create:(_config,{origin})=>({auth:{type:'token',accept:async value=>({token:value,expiry:Date.now()+1000,identity:primary.identity}),revoke:async()=>{}},materialize:c=>({environment:{EXAMPLE_KEY:c.token,EXAMPLE_URL:origin}})})});
 const dir=await mkdtemp(join(tmpdir(),'mcp-plugins-'));t.after(()=>rm(dir,{recursive:true,force:true}));
 await writeFile(join(dir,'manifest.json'),JSON.stringify({version:1,namespace:'example',description:'Example',commands:[{path:['list'],description:'List',read:true,inputSchema:{type:'object',additionalProperties:false,properties:{}}}]}));
 await writeFile(join(dir,'config.json'),JSON.stringify([{manifestFile:join(dir,'manifest.json'),command:'/usr/bin/example',origin,originEnv:'EXAMPLE_ORIGIN',auth:{type:'example-header'}}]));
 const [registration]=loadCliRegistrations(join(dir,'config.json'),{runtimeRoot:dir});
 assert.equal(registration.auth.type,'token');
 await writeFile(join(dir,'config.json'),JSON.stringify([{manifestFile:join(dir,'manifest.json'),command:'/usr/bin/example',origin,originEnv:'EXAMPLE_ORIGIN',auth:{type:'unknown'}}]));
 assert.throws(()=>loadCliRegistrations(join(dir,'config.json'),{runtimeRoot:dir}),/Unknown auth type/);
});
