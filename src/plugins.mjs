import { readFileSync } from 'node:fs';
import { z } from 'zod';
import { cliRegistration, staticTokenAuth } from './adapters.mjs';
import { requestJson, UpstreamError } from './upstream.mjs';
import { digest } from './store.mjs';
const httpsOrigin = z.string().refine(value=>{try{const u=new URL(value);return u.protocol==='https:' && u.origin===value;}catch{return false;}});
const envName=z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/).refine(x=>!/^(?:NODE_|LD_|DYLD_|PATH$|HOME$|XDG_)/.test(x));
const pluginSchema=z.strictObject({
 manifestFile:z.string(),command:z.string(),prefix:z.array(z.string()).default([]),mounts:z.array(z.string()).default([]),
 origin:httpsOrigin,originEnv:envName,
 auth:z.discriminatedUnion('type',[
  z.strictObject({type:z.literal('token'),tokenEnv:envName,validatePath:z.string().regex(/^\/[A-Za-z0-9/_-]+$/).optional()}),
  z.strictObject({type:z.literal('dapier-device')})
 ])
});
export function dapierDeviceAuth(base) {
 httpsOrigin.parse(base);
 const call=(path,options)=>requestJson(base,path,options);
 return {type:'device',
  async start(label){
   const raw=await call('/api/agent/device/start',{method:'POST',body:{label}});
   if(typeof raw.device_code!=='string'||typeof raw.user_code!=='string'||!/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(raw.user_code)||!Number.isInteger(raw.expires_in)||raw.expires_in<1||raw.expires_in>3600)throw new UpstreamError(502,'invalid_device_response');
   const approval=new URL('/device',base);approval.searchParams.set('code',raw.user_code);
   return {deviceCode:raw.device_code,userCode:raw.user_code,approval:approval.href,expiry:Date.now()+raw.expires_in*1000,interval:Math.max(1,Math.min(60,Number(raw.interval)||5))};
  },
  async poll(deviceCode){
   const raw=await call('/api/agent/device/token',{method:'POST',body:{device_code:deviceCode}});
   if(typeof raw.token!=='string'||raw.token.length<20||typeof raw.email!=='string'||!raw.email.includes('@')||!Number.isFinite(raw.expires_at)||raw.expires_at*1000<=Date.now())throw new UpstreamError(502,'invalid_token_response');
   return {token:raw.token,expiry:raw.expires_at*1000,identity:{id:digest(`dapier:${raw.email.toLowerCase()}`),email:raw.email.toLowerCase()},subject:raw.subject};
  },
  // Every CLI request itself goes through Dapier's live bearer/session check.
  async revoke(credential){await call('/api/agent/device/revoke',{method:'POST',body:{},token:credential.token});}
 };
}
export function loadCliRegistrations(path,{runtimeRoot}) {
 if(!path)return [];
 return z.array(pluginSchema).max(16).parse(JSON.parse(readFileSync(path,'utf8'))).map(config=>{
  const manifest=JSON.parse(readFileSync(config.manifestFile,'utf8'));
  const auth=config.auth.type==='token'?staticTokenAuth({validate:async token=>{if(config.auth.validatePath)await requestJson(config.origin,config.auth.validatePath,{token});}}):dapierDeviceAuth(config.origin);
  return cliRegistration({manifest,command:config.command,prefix:config.prefix,mounts:config.mounts,runtimeRoot,auth,environment:{[config.originEnv]:config.origin},
   credentials:credential=>config.auth.type==='token'?{environment:{[config.auth.tokenEnv]:credential.token}}:
    {files:{'dapier/session.json':JSON.stringify({token:credential.token,kind:'device',subject:credential.subject,email:credential.identity.email,expires_at:credential.expiry/1000})}}
  });
 });
}
