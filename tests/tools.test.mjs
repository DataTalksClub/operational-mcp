import test from 'node:test';
import assert from 'node:assert/strict';
import { pocketDefinitions, pocketTools, validateProfile } from '../src/pocketshell.mjs';
import { dataopsTools, validateRoute } from '../src/dataops.mjs';
import { dataopsUpstream, pocketUpstream, requestJson } from '../src/upstream.mjs';

test('PocketShell rejects local/option injection and passes text only as stdin',async()=>{
 const definitions=pocketDefinitions();const send=definitions.find(x=>x.name==='send');
 assert.throws(()=>send.schema.parse({host:'local',session:'s',text:'x'}));
 assert.throws(()=>send.schema.parse({host:'-H',session:'s',text:'x'}));
 assert.throws(()=>send.schema.parse({host:'host',session:'--help',text:'x'}));
 const profile={hosts:[{name:'test-host',deviceId:'test-device',user:'test-user'}],pins:'synthetic verified pin',privateKey:'synthetic PRIVATE KEY'};
 const calls=[];const tools=pocketTools({store:{get:()=>profile},upstream:{base:'https://broker.example.com'},execute:async(...a)=>{calls.push(a);return {ok:true};}});
 await tools.call('send',send.schema.parse({host:'test-host',session:'session',text:'--help; $(example)\nmore'}),{identity:{id:'test'}});
 assert.deepEqual(calls[0][0],['test-host','send','session','-','--json']);assert.equal(calls[0][1].stdin,'--help; $(example)\nmore');
 await assert.rejects(()=>tools.call('ls',{host:'other-host'},{identity:{id:'test'}}),/not configured/);
 assert.throws(()=>validateProfile({...profile,hosts:[{name:'local'}]}));
});
test('DataOps route guard blocks origin, traversal, credential routes and encoded separators',()=>{
 for(const route of ['https://external.example.com/api/tasks','//external.example.com/api/tasks','/api/../tokens','/api/auth/device','/api/tokens','/api/%2e%2e/tokens','/api/auth%2fdevice','/api/%61uth/device','/api/%74okens','/api/%2574okens','/api/tasks#fragment','/api/./tasks','/api/tasks\\other']) assert.throws(()=>validateRoute(route));
 assert.equal(validateRoute('/api/tasks?status=open'),'/api/tasks?status=open');
});
test('DataOps read/write use the same portal API seam as the CLI',async()=>{
 const requests=[];
 const remote=dataopsUpstream({base:'https://portal.example.com',webOrigin:'https://portal.example.com',fetcher:async(url,init)=>{requests.push({url:String(url),...init});return Response.json({items:[]});}});
 const tools=dataopsTools({upstream:remote});
 await tools.call('dataops_read',{route:'/api/tasks?status=open'},{token:'synthetic-token'});
 await tools.call('dataops_write',{method:'PATCH',route:'/api/tasks/test-id',body:{status:'done'}},{token:'synthetic-token'});
 assert.equal(requests[0].url,'https://portal.example.com/work/api/tasks?status=open');assert.equal(requests[1].method,'PATCH');assert.equal(requests[0].headers.Authorization,'Bearer synthetic-token');
 assert.equal(requests[0].redirect,'manual');
});
test('PocketShell OAuth adapter uses shared core device/auth implementations',async()=>{
 const calls=[];
 const core={validateBrokerUrl:x=>x,resolveEndpoint:x=>x,pendingDeviceLogin:raw=>({userCode:raw.userCode,verificationUriComplete:'https://approval.example.com/device?code=BCDF-GHJK'}),
 startDevice:async(...a)=>{calls.push(['start',...a]);return {deviceCode:'synthetic-code',userCode:'BCDF-GHJK',expiresIn:600,interval:5};},
 pollDevice:async(...a)=>{calls.push(['poll',...a]);return {status:200,data:{}};},
 parseDeviceToken:()=>({accessToken:'synthetic-token',tokenId:'test',expiresAt:Date.now()/1000+600}),
 getSession:async(...a)=>{calls.push(['session',...a]);return {tokenId:'test',email:'operator@example.com',expiresAt:Date.now()/1000+600};},
 logout:async()=>{},mintGatewayToken:async()=>({token:'synthetic-gateway-token'}),fetchDevices:async()=>[]};
 const remote=pocketUpstream({core,base:'https://broker.example.com',webOrigin:'https://approval.example.com',gatewayOrigin:'https://gateway.example.com'});
 const pending=await remote.start('test');assert.equal(pending.approval,'https://approval.example.com/device?code=BCDF-GHJK');
 const credential=await remote.poll(pending.deviceCode);assert.equal(credential.token,'synthetic-token');assert.deepEqual(calls.map(x=>x[0]),['start','poll','session']);
});
test('HTTP upstream never follows redirects and enforces a response size cap',async()=>{
 await assert.rejects(()=>requestJson('https://portal.example.com','https://external.example.com/api'),/Cross-origin/);
 await assert.rejects(()=>requestJson('https://portal.example.com','/api',{fetcher:async()=>new Response('x'.repeat(1024*1024+1))}),/upstream_response_too_large/);
});
