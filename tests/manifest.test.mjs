import test from 'node:test';
import assert from 'node:assert/strict';
import { compileManifest, parseCommand, commandHelp } from '../src/manifest.mjs';
const sample = () => compileManifest({ version:1, namespace:'example', description:'Example CLI', commands:[{
 path:['items','create'],description:'Create item',read:false,inputSchema:{type:'object',additionalProperties:false,properties:{name:{type:'string'},title:{type:'string'}},required:['name','title']},positional:['name'],flags:{title:{field:'title'}}
}] });
test('manifest parses only reviewed paths/options and emits safe argv without shell interpretation',()=>{
 const m=sample(); const c=parseCommand(m,['items','create','record','--title','$(touch example); `x`']);
 assert.deepEqual(c.argv,['items','create','record','--title=$(touch example); `x`']);
 for(const args of [['api','GET'],['items','create','--url','x'],['items','create','@private','--title','x'],['items','create','record','--title','--url'],['items','create','record','--title','x','--title','y'],['items','create','record','--title','x\nsecret']]) assert.throws(()=>parseCommand(m,args));
});
test('progressive help includes scope and schemas only at the requested command',()=>{
 const m=sample();assert.deepEqual(parseCommand(m,[]),{help:[]});
 assert.equal(commandHelp(m).commands[0].inputSchema,undefined);
 const item=commandHelp(m,['items','create']).commands[0];assert.equal(item.requiresApproval,true);assert.equal(item.scope,'example:items.create');assert.ok(item.inputSchema);
 assert.equal(commandHelp(m,[],()=>false).commands.length,0);
});
test('rejects incomplete mappings, open schemas, duplicate paths and contradictory classifications',()=>{
 const m=sample();const raw=JSON.parse(JSON.stringify(m, (key,value)=>['validate','scope'].includes(key)?undefined:value));
 for(const mutate of [x=>x.commands[0].positional=[],x=>x.commands[0].inputSchema.additionalProperties=true,x=>x.commands.push(x.commands[0]),x=>{x.commands[0].read=true;x.commands[0].destructive=true;}]) {const value=structuredClone(raw);mutate(value);assert.throws(()=>compileManifest(value));}
});
