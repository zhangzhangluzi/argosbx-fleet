const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const code = fs.readFileSync(path.join(__dirname,'..','bestcf-pages-sub.js'),'utf8');
function fixture(configured, response = new Response('proxies: []\n')) {
  const calls = [];
  const context = vm.createContext({URL, Headers, Response, AbortSignal,
    fetch:async (url,options)=>{calls.push({url,options});return response;}});
  vm.runInContext(code,context);
  const env = {KV:{get:async key=>key==='JP_SELF_SUB_URL'?configured:null}};
  return {call:(target,ua)=>context.japanSelfSubscription({},env,new URL('https://edge.example.com/sub?token=fixture'+target),ua),calls};
}
test('unconfigured project fails closed without exposing the old source',async()=>{
  const f=fixture(null);assert.equal((await f.call('','Stash/3.6.0')).status,503);assert.equal(f.calls.length,0);
});
test('Stash keeps the original country URL and requests only the Japan chain',async()=>{
  const f=fixture('https://sub.example.com/share/col/external-seven?token=fixture',new Response('#SUBSCRIBED https://other.example\nproxies: []\n'));
  const response=await f.call('&target=Stash','Stash/3.6.0');
  assert.equal(response.status,200);
  const value=await response.text();
  assert.match(value,/^#SUBSCRIBED https:\/\/edge\.example\.com\/sub\?token=fixture&target=Stash\n/);
  const upstream=new URL(f.calls[0].url);
  assert.equal(upstream.searchParams.get('only'),'jpself');
  assert.equal(upstream.searchParams.get('target'),'Stash');
  assert.equal(f.calls[0].options.redirect,'manual');
});
test('upstream errors do not fall back to raw CF exits',async()=>{
  const f=fixture('https://sub.example.com/share/col/external-seven?token=fixture',new Response('bad',{status:503}));
  assert.equal((await f.call('','Shadowrocket/2.2.70')).status,503);
});
test('invalid backend URLs are rejected',async()=>{
  const f=fixture('http://sub.example.com/share');
  assert.equal((await f.call('','FlClash/0.8')).status,503);assert.equal(f.calls.length,0);
});
