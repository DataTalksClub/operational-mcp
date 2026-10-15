// Real HTTPS + MCP Inspector. Upstream account approval is a synthetic fixture;
// this does not claim an account-level ChatGPT, Claude or Grok Bot acceptance test.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { once } from 'node:events';
import { execFile as execFileCallback, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { Store, secret } from '../src/store.mjs';
import { createApp } from '../src/app.mjs';
import { pocketTools } from '../src/pocketshell.mjs';
import { dataopsTools } from '../src/dataops.mjs';
const execFile=promisify(execFileCallback);
const inspector=resolve('node_modules/@modelcontextprotocol/inspector/clients/cli/build/index.js');
for(const kind of ['pocketshell','dataops']) test(`${kind}: real TLS, DCR/PKCE/device bridge and MCP Inspector tool discovery/call`,async t=>{
 const dir=await mkdtemp(join(tmpdir(),'mcp-inspector-'));
 const keyFile=join(dir,'key.pem'),certFile=join(dir,'cert.pem');
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',keyFile,'-out',certFile,'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],{stdio:'ignore'});
 const store=new Store(':memory:',randomBytes(32).toString('hex'));
 let app;
 const server=createServer({key:await readFile(keyFile),cert:await readFile(certFile)},(req,res)=>app(req,res));
 server.listen(0,'localhost');await once(server,'listening');
 const origin=`https://localhost:${server.address().port}`;const prefix=kind==='dataops'?'/dataops':'';const issuer=origin+prefix;
 const identity={id:'synthetic-account',email:'operator@example.com'};
 const upstream={kind,base:'https://portal.example.com',
  start:async()=>({deviceCode:secret(),userCode:'BCDF-GHJK',approval:'https://approval.example.com/device',expiry:Date.now()+600000,interval:1}),
  poll:async()=>({token:secret(),identity,tokenId:'synthetic',expiry:Date.now()+86400000}),identity:async()=>identity,revoke:async()=>{},devices:async()=>[],call:async()=>({items:[]})};
 const tools=kind==='pocketshell'?pocketTools({store,upstream}):dataopsTools({upstream});
 app=createApp({store,upstream,tools,issuer,allowedEmails:[identity.email],redirectUris:[]});
 t.after(async()=>{server.closeAllConnections();server.close();store.close();await rm(dir,{recursive:true,force:true});});
 // Trust only this generated test CA for the HTTP driver; TLS verification stays enabled.
 const { Agent, fetch: tlsFetch }=await import('undici');const dispatcher=new Agent({connect:{ca:await readFile(certFile)}});t.after(()=>dispatcher.close());
 const call=(path,body,headers={})=>tlsFetch(origin+path,{dispatcher,redirect:'manual',...(body?{method:'POST',body:JSON.stringify(body),headers:{'content-type':'application/json',...headers}}:{headers})});
 const unauthorized=await call(prefix+'/mcp',{});assert.equal(unauthorized.status,401);
 const metadata=await (await call(`/.well-known/oauth-protected-resource${prefix}/mcp`)).json();assert.deepEqual(metadata.authorization_servers,[issuer]);
 const auth=await (await call(`/.well-known/oauth-authorization-server${prefix}`)).json();assert.equal(auth.code_challenge_methods_supported[0],'S256');
 const registration=await call(prefix+'/oauth/register',{client_name:'Inspector synthetic fixture',redirect_uris:['http://localhost:9999/callback'],token_endpoint_auth_method:'none'});assert.equal(registration.status,201);const client=await registration.json();
 const verifier=secret(), state=secret();
 const authorize=await call(prefix+'/oauth/authorize?'+new URLSearchParams({response_type:'code',client_id:client.client_id,redirect_uri:client.redirect_uris[0],code_challenge_method:'S256',code_challenge:createHash('sha256').update(verifier).digest('base64url'),resource:issuer+'/mcp',state}));
 assert.equal(authorize.status,200);const cookie=authorize.headers.get('set-cookie').split(';')[0];const csrf=/name="csrf" value="([^"]+)"/.exec(await authorize.text())[1];const browser={cookie,origin};
 assert.equal((await call(prefix+'/oauth/start',{csrf},browser)).status,200);
 const complete=await call(prefix+'/oauth/complete',{csrf},browser);assert.equal(complete.status,303);const redirect=new URL(complete.headers.get('location'));assert.equal(redirect.searchParams.get('state'),state);
 const exchange=await call(prefix+'/oauth/token',{grant_type:'authorization_code',client_id:client.client_id,redirect_uri:client.redirect_uris[0],code:redirect.searchParams.get('code'),code_verifier:verifier,resource:issuer+'/mcp'});assert.equal(exchange.status,200);const token=await exchange.json();
 const config=join(dir,'inspector.json');await writeFile(config,JSON.stringify({mcpServers:{fixture:{type:'http',url:issuer+'/mcp',headers:{Authorization:`Bearer ${token.access_token}`}}}}),{mode:0o600});
 const run=async args=>{
  try {return await execFile(process.execPath,[inspector,'--config',config,'--server','fixture',...args],{env:{...process.env,NODE_EXTRA_CA_CERTS:certFile},timeout:20000,maxBuffer:1024*1024});}
  catch {assert.fail('Inspector process failed; raw diagnostics suppressed to protect credentials');}
 };
 const listed=await run(['--method','tools/list','--strict']);const discovered=JSON.parse(listed.stdout);assert.equal((discovered.tools||discovered).length,kind==='pocketshell'?7:3);
 const args=kind==='pocketshell'?['--method','tools/call','--tool-name','hosts']:['--method','tools/call','--tool-name','dataops_read','--tool-arg','route=/api/tasks'];
 const called=JSON.parse((await run(args)).stdout);assert.notEqual(called.isError,true);
});
