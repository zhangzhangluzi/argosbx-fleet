import copy,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from test_core import fixtures
from protocols import adopt,render,export
from inbounds import reconcile,create
from reality_compat import migrate,xray_targets,LOCAL_DNS_RULE

def legacy():
 c,clients,s=fixtures();old=c['/test/x.json']['inbounds'].pop(0)
 old['settings']['decryption']='none';old['settings']['clients'][0]['flow']='xtls-rprx-vision';old['streamSettings']['network']='tcp';old['streamSettings']['realitySettings']['privateKey']='fixture-private'
 old['sniffing']={'enabled':True,'destOverride':['http','tls','quic'],'metadataOnly':False}
 c['/test/real.json']={'inbounds':[old],'outbounds':[{'protocol':'freedom','tag':'direct','settings':{'domainStrategy':'ForceIPv4v6'}}],'routing':{'rules':[{'type':'field','network':'tcp,udp','ip':['0.0.0.0/0','::/0'],'outboundTag':'direct'}]}}
 s['bindings']['reality'].update(path='/test/real.json',inbound=copy.deepcopy(old),service='real.service')
 s['native_sha256']={p:'fixture' for p in c}
 c['/test/s.json']['outbounds']=[{'type':'direct','tag':'direct'}]
 return c,clients,s

class RealityCompatibilityTests(unittest.TestCase):
 def test_migration_preserves_client_identity_and_removes_unused_engine(self):
  c,_,s=legacy();unchanged=copy.deepcopy((c,s));expected=export(c,s)
  after,state,retired=migrate(c,s)
  self.assertEqual((c,s),unchanged);self.assertEqual(export(after,state),expected)
  self.assertEqual(retired,[{'path':'/test/real.json','core':'xray','service':'real.service'}])
  self.assertNotIn('/test/real.json',after);b=state['bindings']['reality'];self.assertEqual(b['core'],'sing-box');self.assertEqual(b['service'],'s.service')
  real=next(n for n in after[b['path']]['inbounds'] if n['tag']==b['tag'])
  self.assertEqual(real['tls']['reality']['private_key'],'fixture-private');self.assertEqual(real['users'][0]['uuid'],'fixture-id')
  self.assertEqual(after,migrate(after,state)[0])
 def test_adopt_and_edit_sing_reality_without_certificate(self):
  c,_,s=legacy();after,state,_=migrate(c,s);nodes=export(after,state)['proxies']
  services={p:e['service'] for p,e in state['engines'].items()};adopted=adopt(after,nodes,services)
  self.assertEqual(adopted['bindings']['reality']['core'],'sing-box');self.assertEqual(export(after,adopted),{'proxies':nodes})
  desired=copy.deepcopy(state['protocols']);desired['reality'].update(port=5444,sni='new.example.com',cover_host='new.example.com',listen='0.0.0.0')
  changed=render(after,state,desired);b=state['bindings']['reality'];r=next(v for v in changed[b['path']]['inbounds'] if v['tag']==b['tag'])
  self.assertEqual(r['listen'],'::');self.assertEqual(r['listen_port'],5444);self.assertEqual(r['tls']['server_name'],'new.example.com');self.assertEqual(r['tls']['reality']['handshake']['server'],'new.example.com')
 def test_removing_migrated_reality_cleans_its_routes_and_resolver(self):
  c,_,s=legacy();after,state,_=migrate(c,s);desired=copy.deepcopy(state['protocols']);del desired['reality']
  result,state,_=reconcile(after,state,desired);sb=result['/test/s.json']
  self.assertFalse(sb['route']['rules']);self.assertFalse(sb['dns']['servers']);self.assertEqual(sb['outbounds'],[{'type':'direct','tag':'direct'}])
 def test_unsupported_policy_and_security_fields_fail_closed(self):
  for field in ['route','client','reality']:
   with self.subTest(field=field):
    c,_,s=legacy();r=c['/test/real.json']['inbounds'][0]
    if field=='route':c['/test/real.json']['routing']['rules'].insert(0,{'type':'field','port':22,'outboundTag':'block'})
    if field=='client':r['settings']['clients'][0]['level']=4
    if field=='reality':r['streamSettings']['realitySettings']['minClientVer']='26.1.1'
    snapshot=copy.deepcopy((c,s))
    with self.assertRaises(ValueError):migrate(c,s)
    self.assertEqual((c,s),snapshot)
 def test_new_reality_uses_existing_sing_engine(self):
  c,_,s=legacy();p=s['protocols']['reality'];native,aux,node=create('other',dict(p,type='reality'),{},keygen=lambda:('fixture-private','fixture-public'))
  self.assertEqual(native['type'],'vless');self.assertNotIn('protocol',native);self.assertEqual(native['tls']['reality']['private_key'],'fixture-private');self.assertEqual(node['reality-opts']['public-key'],'fixture-public')
 def test_disabled_reality_keeps_identity_for_future_enable(self):
  c,_,s=legacy();s['protocols']['reality']['enabled']=False;c['/test/real.json']['inbounds']=[]
  after,state,_=migrate(c,s);b=state['bindings']['reality'];self.assertEqual(b['core'],'sing-box');self.assertFalse(any(n['tag']==b['tag'] for n in after[b['path']]['inbounds']))
  desired=copy.deepcopy(state['protocols']);desired['reality']['enabled']=True;enabled=render(after,state,desired)
  n=next(v for v in enabled[b['path']]['inbounds'] if v['tag']==b['tag']);self.assertEqual(n['tls']['reality']['private_key'],'fixture-private')
 def test_cleanup_preserves_resolver_referenced_by_other_dns_server(self):
  c,_,s=legacy();after,state,_=migrate(c,s);sb=after['/test/s.json'];sb['dns']['servers'].append({'type':'https','tag':'custom','server':'dns.example.com','domain_resolver':'fleet-reality-local-dns'})
  desired=copy.deepcopy(state['protocols']);del desired['reality'];result,_,_=reconcile(after,state,desired)
  self.assertIn({'type':'local','tag':'fleet-reality-local-dns'},result['/test/s.json']['dns']['servers'])
 def test_xray_exception_only_allows_dns_stub_and_is_idempotent(self):
  before={'x':{'outbounds':[{'protocol':'freedom','settings':{'domainStrategy':'ForceIPv4v6'}}]}}
  after=xray_targets(before);self.assertNotIn('finalRules',before['x']['outbounds'][0]['settings'])
  self.assertEqual(after['x']['outbounds'][0]['settings']['finalRules'],[LOCAL_DNS_RULE]);self.assertEqual(xray_targets(after),after)
  before['x']['outbounds'][0]['settings']['finalRules']=[{'action':'block','ip':['127.0.0.0/8']}]
  with self.assertRaises(ValueError):xray_targets(before)
