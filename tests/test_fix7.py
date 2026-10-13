"""Regression coverage for country aggregation, onboarding and native edit boundaries."""
import copy,contextlib,io,json,os,runpy,socket,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch,Mock
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import acceptance,agent,country_routes,fleet,fleetctl,listeners,onboard,protocols,servers,tunnels
from test_core import fixtures,FakeCF

class ListenerTests(unittest.TestCase):
 def test_tcp_occupied_by_other_service_is_rejected(self):
  with socket.socket() as s:
   s.bind(('127.0.0.1',0));s.listen();port=s.getsockname()[1]
   with self.assertRaisesRegex(ValueError,'占用'):listeners.check({}, {'a':{'inbounds':[{'type':'anytls','listen':'127.0.0.1','listen_port':port}]}})
 def test_udp_occupied_is_rejected(self):
  with socket.socket(type=socket.SOCK_DGRAM) as s:
   s.bind(('127.0.0.1',0));port=s.getsockname()[1]
   with self.assertRaises(ValueError):listeners.check({}, {'a':{'inbounds':[{'type':'hysteria2','listen':'127.0.0.1','listen_port':port}]}})
 def test_unchanged_service_not_rebound(self):
  with socket.socket() as s:
   s.bind(('127.0.0.1',0));s.listen();c={'a':{'inbounds':[{'type':'anytls','listen':'127.0.0.1','listen_port':s.getsockname()[1]}]}}
   listeners.check(c,copy.deepcopy(c))
 def test_apply_rechecks_new_conflict_before_journal(self):
  c,_,s=fixtures()
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)
   with patch.object(agent,'PLAN',p/'plan'),patch.object(agent,'JOURNAL',p/'journal'),patch.object(agent,'load',return_value=s),patch.object(agent,'configs',return_value=c),patch.object(agent,'certificate_health',return_value={}),patch.object(listeners,'check',side_effect=ValueError('conflict')),patch.object(agent,'cmd') as cmd:
    s['native_sha256']={};(p/'plan').write_text(json.dumps({'state_before':s,'state_after':s,'services':[],'files':[]}))
    with self.assertRaises(ValueError):agent.apply()
    self.assertFalse((p/'journal').exists());cmd.assert_not_called()

class BindingTests(unittest.TestCase):
 def server(self):return onboard.defaults('jp2','JP','日本','192.0.2.1','2001:db8::1','example.com','/key','/known')
 def test_direct_loopback_and_multicast_rejected(self):
  for listen in ('127.0.0.1','::1','224.0.0.1','ff02::1'):
   p=self.server()['protocols']['anytls'];p['listen']=listen
   with self.subTest(listen=listen),self.assertRaises(ValueError):protocols.validate_settings({'anytls':p},True)
 def test_cf_loopback_origin_uses_exact_family(self):
  p=self.server()['protocols']['cf'];p['listen']='::1'
  self.assertEqual(tunnels.routes({'protocols':{'cf':p}})[0]['service'],'http://[::1]:18082')
 def test_cf_bad_path_rejected(self):
  for path in ('/x?ed=2048','/x#f','/x%3Fy','http://x','/x\\y'):
   p=self.server()['protocols']['cf'];p['ws_path']=path
   with self.subTest(path=path),self.assertRaises(ValueError):tunnels.routes({'protocols':{'cf':p}})
 def test_single_family_node_and_shadowrocket_match(self):
  s=self.server();s['status']='active';s['protocols']={'anytls':s['protocols']['anytls']};s['protocols']['anytls']['listen']='0.0.0.0'
  self.assertEqual(protocols.families('anytls',s['protocols']['anytls'],s),['ipv4'])
  js=(ROOT/'region-processor.js').read_text().replace('SPEC',json.dumps(fleet.region_spec(s)))
  nodes=[{'type':'anytls','name':'fleet.anytls','port':2447,'sni':s['protocols']['anytls']['sni']}]
  value=json.loads(subprocess.check_output(['node','-e',js+';console.log(JSON.stringify(operator('+json.dumps(nodes)+')));']))
  self.assertEqual(len(value),1);self.assertIn('-v4-',value[0]['name'])
 def test_xray_unspecified_is_dual_stack(self):
  s=self.server();p=s['protocols']['hy2'];p['listen']='0.0.0.0';self.assertEqual(protocols.families('hy2',p,s),['ipv4','ipv6'])
 def test_ipv4_migration_keeps_custom_cf_identity(self):
  s=self.server();s['protocols']['cf_alt']={**s['protocols']['cf'],'type':'cf','sni':'other.example.com','ws_path':'/other','port':18084}
  new=protocols.migrate_references(s,{'ipv4':'changed.example.com'})
  self.assertEqual(new['protocols'],s['protocols'])
  new=protocols.migrate_references(s,{'cf':'newedge.example.com'})
  self.assertEqual(new['protocols']['cf']['sni'],'newedge.example.com');self.assertEqual(new['protocols']['cf_alt']['sni'],'other.example.com')
 def test_domain_plan_routes_only_matching_reference(self):
  import domains
  s=self.server();s['protocols']['cf_alt']={**s['protocols']['cf'],'type':'cf','sni':'other.example.com','ws_path':'/other','port':18084}
  plan=domains.build(FakeCF(),'example.com',s,{'cf':'newedge.example.com'},'00000000-0000-0000-0000-000000000000')
  new=[r for r in plan['after']['ingress'] if r.get('hostname')=='newedge.example.com']
  self.assertEqual(len(new),1);self.assertTrue(new[0]['service'].endswith(':18082'))

class PendingTests(unittest.TestCase):
 def test_pending_excluded_from_generated_country_dns_and_sources(self):
  c=json.loads((ROOT/'templates/servers.example.json').read_text());s=onboard.defaults('us','US','美国','192.0.2.3',None,'example.com','/key','/known');c['servers'].append(s);c['purpose_order'].append('US')
  with tempfile.TemporaryDirectory() as d,patch.object(fleet,'STATE',Path(d)),patch.object(servers,'STATE',Path(d)):
   p=servers.generate(c)
  self.assertEqual(len(p['subscriptions']),1);self.assertEqual([x['name'] for x in p['collections']],['all','shadowrocket-jp'])
  self.assertNotIn('us4.example.com',json.dumps(p));self.assertNotIn('美国',json.dumps(p,ensure_ascii=False))
 def test_pending_not_inspected(self):
  c={'servers':[{'id':'active'},{'id':'pending','status':'pending','protocols':{'x':{}}}]}
  with patch.object(fleetctl,'remote') as call:servers.native_preflight(c)
  call.assert_not_called()
 def test_no_active_refused(self):
  with self.assertRaises(ValueError):fleet.active_config({'servers':[{'country':'JP','status':'pending'}]})
 def test_same_country_aggregation_includes_two_servers(self):
  c=json.loads((ROOT/'templates/servers.example.json').read_text());b=copy.deepcopy(c['servers'][0]);b['id']='jp2';b['name']='JP2';b['subscription']['name']='argo-jp2';c['servers'].append(b)
  with tempfile.TemporaryDirectory() as d,patch.object(fleet,'STATE',Path(d)),patch.object(servers,'STATE',Path(d)):p=servers.generate(c)
  self.assertEqual(next(x for x in p['collections'] if x['name']=='shadowrocket-jp')['subscriptions'],[s['subscription']['name'] for s in c['servers']])

class AcceptanceTests(unittest.TestCase):
 def test_missing_protocol_refuses_before_ssh(self):
  s=onboard.defaults('new','JP','日本','192.0.2.1',None,'example.com','/key','/known')
  with self.assertRaises(ValueError):acceptance.cases(s,[])
 def test_udp_failure_blocks_publish_and_activation(self):
  c,clients,state=fixtures();s={'id':'new','ipv4':'192.0.2.1','ipv6':None,'salamander_ipv6':False,'protocols':state['protocols']}
  results={'passed':False,'results':[{'name':'anytls/ipv4','https_ok':True,'exit_ok':True,'udp_ok':False}]}
  checks=[{'name':'anytls/ipv4'}]
  with patch.object(acceptance,'cases',return_value=checks),patch.object(acceptance,'ssh_args',return_value=['ssh','test']),patch.object(acceptance.subprocess,'run',return_value=Mock(returncode=0,stdout=json.dumps(results))),self.assertRaisesRegex(RuntimeError,'pending'):acceptance.verify_new_server({'coordinator':'old','servers':[{'id':'old','ipv4':'192.0.2.2'}]},s,clients)
 def test_verifier_requires_independent_server(self):
  with self.assertRaises(ValueError):acceptance.observers({'coordinator':'new','servers':[{'id':'new'}]},{'id':'new'},[])
 def test_ipv6_uses_an_independent_ipv6_peer(self):
  c={'coordinator':'us','servers':[{'id':'us','ipv4':'192.0.2.1'},{'id':'tw','ipv4':'192.0.2.2','ipv6':'2001:db8::1'},{'id':'jp','ipv6':'2001:db8::2'}]}
  checks=[{'name':'hy2/ipv4'},{'name':'hy2/ipv6'}]
  self.assertEqual(acceptance.observers(c,{'id':'jp'},checks),{'us':[checks[0]],'tw':[checks[1]]})
  c['servers'][1]['status']='pending'
  with self.assertRaisesRegex(ValueError,'ipv6'):acceptance.observers(c,{'id':'jp'},checks)
 def test_forged_pass_flag_and_wrong_node_set_refused(self):
  c={'coordinator':'old','servers':[{'id':'old','ipv4':'192.0.2.2'}]}
  for value in ({'passed':True,'results':[{'name':'test/ipv4','https_ok':True,'exit_ok':False,'udp_ok':True}]},{'passed':True,'results':[{'name':'other/ipv4','https_ok':True,'exit_ok':True,'udp_ok':True}]}):
   with self.subTest(value=value),patch.object(acceptance,'cases',return_value=[{'name':'test/ipv4'}]),patch.object(acceptance,'ssh_args',return_value=['ssh','test']),patch.object(acceptance.subprocess,'run',return_value=Mock(returncode=0,stdout=json.dumps(value))),self.assertRaises((ValueError,RuntimeError)):acceptance.verify_new_server(c,{'id':'new'},[])
 def test_numeric_reality_short_id_serialized_as_string(self):
  import probe
  n={'type':'vless','server':'192.0.2.1','port':443,'uuid':'id','flow':'xtls-rprx-vision','servername':'example.com','reality-opts':{'public-key':'key','short-id':1234}}
  self.assertEqual(probe.outbound(n)[0]['tls']['reality']['short_id'],'1234')
 def test_cf_probe_uses_public_edge_and_tls(self):
  import probe
  n={'type':'vmess','server':'edge.example.com','port':443,'uuid':'id','tls':True,'servername':'edge.example.com','ws-opts':{'path':'/x','headers':{'Host':'edge.example.com'}}}
  out=probe.outbound(n)[0];self.assertEqual(out['server_port'],443);self.assertEqual(out['tls']['server_name'],n['server']);self.assertNotIn('insecure',out['tls'])

class CountryRouteTests(unittest.TestCase):
 def fixture(self):
  return '''outside\n# BEGIN TI UNIFIED SUBSCRIPTION
 @ti_phone_jp_format query format=shadowrocket-jp
 route {
  handle @ti_phone_format {
   rewrite * /fixture/download/collection/all?target=URI
  }
  handle @ti_phone_jp_format {
   rewrite * /fixture/download/argo-jp?target=URI
   reverse_proxy 127.0.0.1:3001
  }
  respond @ti_bad_format "Unsupported format" 400
 }
# END TI UNIFIED SUBSCRIPTION\noutside2\n'''
 def test_generic_country_handler_preserves_auth_and_all(self):
  value=country_routes.render(self.fixture())
  self.assertIn('/fixture/download/collection/{query.format}?target=URI',value)
  self.assertIn('/fixture/download/collection/all?target=URI',value)
  self.assertNotIn('/download/argo-jp?',value);self.assertTrue(value.startswith('outside\n'));self.assertTrue(value.endswith('outside2\n'))
  self.assertEqual(country_routes.render(value),value)
 def test_unknown_layout_refuses(self):
  with self.assertRaises(ValueError):country_routes.render('not managed')
