import test from 'node:test';
import assert from 'node:assert/strict';
import { gatewayTools } from '../src/registry.mjs';
import { pocketRegistration, dataopsRegistration } from '../src/adapters.mjs';
import { pocketTools } from '../src/pocketshell.mjs';
const credential=user=>({token:'synthetic-'+user,expiry:Date.now()+60000,identity:{id:user,email:user+'@example.com'}});
function fixture(execute) {
 const registration={manifest:{version:1,namespace:'example',description:'Example CLI.',commands:[{path:['list'],description:'Read items',read:true,inputSchema:{type:'object',additionalProperties:false,properties:{}}},{path:['delete'],description:'Delete items',read:false,destructive:true,inputSchema:{type:'object',additionalProperties:false,properties:{}}}]},execute};
 const tools=gatewayTools([registration]);return {tools,context:{scopes:tools.scopes,linked:{example:credential('one')}}};
}
test('one CLI tool progressively discovers commands and enforces scopes, read-only and approval',async()=>{
 let calls=0;const {tools,context}=fixture(async()=>{calls++;return {ok:true};});const user=credential('one');
 assert.deepEqual(tools.definitions.map(x=>x.name),['catalog','example']);
 assert.equal(tools.definitions[1].destructive,true);
 assert.equal((await tools.call('example',{},user,context)).commands.length,2);
 assert.equal((await tools.call('example',{argv:['delete']},user,context)).approvalRequired,true);assert.equal(calls,0);
 assert.deepEqual(await tools.call('example',{argv:['delete'],approved:true},user,context),{ok:true});assert.equal(calls,1);
 await assert.rejects(()=>tools.call('example',{argv:['delete'],approved:true},user,{...context,scopes:['example:list']}));
 await assert.rejects(()=>tools.call('example',{argv:['delete'],approved:true},user,{...context,readOnly:true}));
 const help=await tools.call('example',{},user,{...context,readOnly:true});assert.deepEqual(help.commands.map(x=>x.command),['list']);
 assert.equal((await tools.call('example',{argv:['list']},user,{scopes:tools.scopes})).connectionRequired,true);
});
test('credentials are supplied only for the current grant and writes are serialized per user',async()=>{
 let release;const gate=new Promise(resolve=>{release=resolve;});const seen=[];
 const {tools,context}=fixture(async(_parsed,c)=>{seen.push(c.identity.id);await gate;return {ok:true};});
 const one=tools.call('example',{argv:['delete'],approved:true},credential('one'),context);
 await assert.rejects(()=>tools.call('example',{argv:['delete'],approved:true},credential('one'),context),/concurrency/);
 const two=tools.call('example',{argv:['list']},credential('two'),{...context,linked:{example:credential('two')}});
 release();await Promise.all([one,two]);assert.deepEqual(seen,['one','two']);
});
test('PocketShell dispatch uses the existing core adapter; DataOps builds real CLI argv and private config',async()=>{
 let received;
 const pocket=pocketRegistration(pocketTools({store:{get:()=>null},upstream:{devices:async()=>[]}}));
 const dataops=dataopsRegistration({entrypoint:'/opt/dataops/bin/dataops.mjs',upstream:{base:'https://portal.example.com'},runtimeRoot:'/tmp/runtime',run:async options=>{received=options;return {tasks:[]};}});
 const tools=gatewayTools([pocket,dataops]),user=credential('one'),context={scopes:tools.scopes,linked:{dataops:user}};
 assert.deepEqual(await tools.call('pocketshell',{argv:['hosts']},user,context),{hosts:[]});
 assert.deepEqual(await tools.call('dataops',{argv:['tasks','list','--mine']},user,context),{tasks:[]});
 assert.deepEqual(received.argv,['tasks','list','--mine','--json']);assert.equal(received.environment.DATAOPS_URL,'https://portal.example.com');
 assert.ok(received.files['credentials.json'].includes(user.token));assert.ok(!JSON.stringify(received.argv).includes(user.token));assert.equal(received.environment.DATAOPS_TOKEN,undefined);
});
