import copy,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from test_reality_compat import legacy
from protocols import adopt,export,render
from inbounds import create,reconcile,engines
from reality_compat import migrate as migrate_reality,DNS_TAG
from vmess_compat import migrate,to_sing

def fixture():
 c,clients,s=legacy()
 c['/test/x.json']['outbounds']=[{'protocol':'freedom','tag':'direct','settings':{'domainStrategy':'ForceIPv4v6'}}]
 c['/test/x.json']['routing']={'rules':[{'type':'field','network':'tcp,udp','outboundTag':'direct'}]}
 c['/test/x.json']['inbounds'][0]['sniffing']={'enabled':True,'destOverride':['http','tls','quic'],'metadataOnly':False}
 return c,clients,s

class VMessCompatibilityTests(unittest.TestCase):
 def test_migration_preserves_every_exported_node_and_all_authentication(self):
  c,_,s=fixture();snapshot=copy.deepcopy((c,s));expected=export(c,s)
  after,state,retired=migrate(c,s)
  self.assertEqual((c,s),snapshot);self.assertEqual(export(after,state),expected)
  self.assertEqual(retired,[{'path':'/test/x.json','core':'xray','service':'x.service'}])
  self.assertEqual(state['bindings']['cf']['core'],'sing-box')
  cf=next(n for n in after['/test/s.json']['inbounds'] if n['type']=='vmess')
  self.assertEqual(cf['users'],[{'uuid':'fixture-id'}]);self.assertEqual(cf['transport'],{'type':'ws','path':'/test'})
  self.assertEqual(migrate(after,state)[0],after)
 def test_reality_and_cf_share_routes_without_removing_other_consumers(self):
  c,_,s=fixture();first,state,_=migrate_reality(c,s);after,state,_=migrate(first,state)
  desired=copy.deepcopy(state['protocols']);del desired['cf']
  removed,next_state,_=reconcile(after,state,desired)
  self.assertTrue(any(v.get('tag')==DNS_TAG for v in removed['/test/s.json']['dns']['servers']))
  del desired['reality'];removed,_,_=reconcile(removed,next_state,desired)
  self.assertFalse(removed['/test/s.json']['route']['rules']);self.assertFalse(removed['/test/s.json']['dns']['servers'])
 def test_adoption_and_parameter_edit_keep_original_client_path_spelling(self):
  c,_,s=fixture();s['protocols']['cf']['ws_path']='test';s['templates']['cf']['ws-opts']['path']='test'
  after,state,_=migrate(c,s);clients=export(after,state)['proxies']
  adopted=adopt(after,clients,{p:e['service'] for p,e in engines(state).items()})
  self.assertEqual(adopted['protocols']['cf']['ws_path'],'test')
  desired=copy.deepcopy(state['protocols']);desired['cf'].update(ws_path='changed-path',port=18083)
  result=render(after,state,desired);cf=next(n for n in result['/test/s.json']['inbounds'] if n['type']=='vmess')
  self.assertEqual(cf['transport']['path'],'/changed-path');self.assertEqual(cf['listen_port'],18083)
  state['protocols']=desired;node=next(n for n in export(result,state)['proxies'] if n['type']=='vmess')
  self.assertEqual(node['ws-opts']['path'],'changed-path');self.assertEqual(node['uuid'],'fixture-id')
 def test_disabled_inbound_reenables_with_same_identity(self):
  c,_,s=fixture();s['protocols']['cf']['enabled']=False;c['/test/x.json']['inbounds']=[]
  after,state,_=migrate(c,s);self.assertFalse(any(n.get('type')=='vmess' for n in after['/test/s.json']['inbounds']))
  desired=copy.deepcopy(state['protocols']);desired['cf']['enabled']=True;result=render(after,state,desired)
  node=next(n for n in result['/test/s.json']['inbounds'] if n.get('type')=='vmess');self.assertEqual(node['users'][0]['uuid'],'fixture-id')
 def test_custom_security_or_routing_fails_without_changing_input(self):
  for case in ['legacy-user','encryption-policy','socket-options','custom-route','sniff-policy']:
   c,_,s=fixture();n=c['/test/x.json']['inbounds'][0]
   if case=='legacy-user':n['settings']['clients'][0]['alterId']=16
   if case=='encryption-policy':n['settings']['disableInsecureEncryption']=True
   if case=='socket-options':n['streamSettings']['sockopt']={'acceptProxyProtocol':True}
   if case=='custom-route':c['/test/x.json']['routing']['rules'][0]['port']=22
   if case=='sniff-policy':n['sniffing']['routeOnly']=True
   snapshot=copy.deepcopy((c,s))
   with self.subTest(case=case),self.assertRaises(ValueError):migrate(c,s)
   self.assertEqual((c,s),snapshot)
 def test_new_cf_uses_stable_server_and_original_auto_client(self):
  _,_,s=fixture();native,aux,node=create('cf',s['protocols']['cf'],{})
  self.assertEqual(native['type'],'vmess');self.assertEqual(node['uuid'],native['users'][0]['uuid'])
  self.assertEqual(node['cipher'],'auto');self.assertTrue(node['tls']);self.assertEqual(aux,[])

if __name__=='__main__':unittest.main()
