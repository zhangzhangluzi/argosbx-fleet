const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const code = fs.readFileSync(path.join(__dirname, '..', 'bestcf-chain.js'), 'utf8');
const base = {type:'vless', network:'ws', tls:true, uuid:'fixture', sni:'edge.example.com',
  server:'1.1.1.1', port:443, 'ws-opts':{path:'/fixture'}, 'skip-cert-verify':false};
const jp = {name:'JP-T-v4-VLESS-REALITY-Vision', type:'vless', tls:true, uuid:'fixture-jp',
  server:'8.8.8.8', port:443, 'reality-opts':{'public-key':'fixture'}, 'skip-cert-verify':false};
const feeds = {
  Mia:'1.1.1.1:443#BestCF.pages.dev banner\n8.8.8.8:443#Mia\n8.8.4.4:443#Mia\n8.8.8.8:443#duplicate\n10.0.0.1:443#private\n9.9.9.9:17000#other-port',
  Qilin:'1.1.1.1:443#BestCF.pages.dev banner\n9.9.9.9:443#one\n1.0.0.1:443#two',
};
function fixture(sourceData = feeds) {
  const cache = new Map();
  let time = 1000000, fail = false, failSource = '', hasJp = true, calls = 0;
  const context = vm.createContext({
    AbortController, setTimeout, clearTimeout,
    Date:{now:()=>time},
    scriptResourceCache:{get:k=>cache.get(k),set:(k,v)=>cache.set(k,v)},
    produceArtifact:async ()=>hasJp ? [jp] : [],
    fetch:async url=>{
      calls++;
      if (fail || (failSource === 'Mia' && url.includes('xinyitang3')) ||
          (failSource === 'Qilin' && url.includes('uouin'))) throw new Error('offline');
      const body = url.includes('xinyitang3') ? sourceData.Mia : sourceData.Qilin;
      return {ok:true,text:async()=>body};
    },
  });
  vm.runInContext(code, context);
  return {
    run:(entry=base)=>context.operator([entry]),
    offline:()=>{fail=true;},
    sourceOffline:id=>{failSource=id;},
    noJp:()=>{hasJp=false;},
    advance:ms=>{time+=ms;},
    calls:()=>calls,
  };
}
test('both sources preserve all valid addresses and original ports in Japan-only chains', async()=>{
  const result = await fixture().run();
  assert.equal(result.length, 10);
  for (let i = 0; i < result.length; i += 2) {
    assert.match(result[i].name, /^CF入口-(Mia|Qilin)-\d+(?:\.\d+){3}-\d+$/);
    assert.match(result[i+1].name, /^JP-T-v4-CF-自建-(Mia|Qilin)-\d+(?:\.\d+){3}-\d+$/);
    assert.equal(result[i+1]['dialer-proxy'], result[i].name);
    assert.equal(result[i+1].server, jp.server);
    assert.equal(result[i+1].udp, false);
    assert.equal(result[i]['ws-opts'].path, '/proxyip=8.8.8.8:443');
  }
  assert.ok(result.some(p=>p.name.startsWith('CF入口-Mia-') && p.port===17000));
});
test('sources are not silently capped and names stay stable after reordering', async()=>{
  const rows=Array.from({length:12},(_,i)=>`8.8.8.${i+1}:443#Mia`);
  const data={Mia:rows.join('\n'),Qilin:feeds.Qilin};
  const first=await fixture(data).run();
  const second=await fixture({...data,Mia:rows.reverse().join('\n')}).run();
  assert.equal(first.length,28);
  assert.deepEqual([...first.map(p=>p.name)].sort(),[...second.map(p=>p.name)].sort());
});
test('source failure uses recent cache then fails closed', async()=>{
  const f = fixture();
  assert.equal((await f.run()).length, 10);
  f.offline(); f.advance(31*60*1000);
  assert.equal((await f.run()).length, 10);
  f.advance(6*60*60*1000);
  assert.equal((await f.run()).length, 0);
});
test('one expired source does not remove the other source', async()=>{
  const f=fixture();
  await f.run();
  f.sourceOffline('Mia'); f.advance(7*60*60*1000);
  const result=await f.run();
  assert.equal(result.length,4);
  assert.ok(result.every(p=>p.name.includes('Qilin')));
});
test('missing Japan or unsafe CF template never generates exits', async()=>{
  const f = fixture();
  f.noJp();
  assert.equal((await f.run()).length, 0);
  const unsafe = {...base, 'skip-cert-verify':true};
  assert.equal((await fixture().run(unsafe)).length, 0);
});
test('fresh cached lists avoid repeated network requests', async()=>{
  const f = fixture();
  await f.run(); await f.run();
  assert.equal(f.calls(), 2);
  f.advance(61000);
  await f.run();
  assert.equal(f.calls(), 4);
});
test('refresh after the burst window observes upstream additions and removals', async()=>{
  const data={...feeds};
  const f=fixture(data);
  const first=await f.run();
  assert.ok(first.some(p=>p.name.includes('Mia-8.8.8.8-443')));
  data.Mia='4.2.2.2:443#updated';
  f.advance(61000);
  const next=await f.run();
  assert.ok(next.some(p=>p.name.includes('Mia-4.2.2.2-443')));
  assert.ok(!next.some(p=>p.name.includes('Mia-8.8.8.8-443')));
});
