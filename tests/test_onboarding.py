import copy,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from test_core import fixtures,FakeCF
from inbounds import reconcile
from protocols import render,export
from onboard import defaults
from storage import save
import tunnels,publication

class InboundLifecycleTests(unittest.TestCase):
    def test_second_inbound_credentials_and_remove(self):
        c,clients,s=fixtures();desired=copy.deepcopy(s['protocols'])
        desired['anytls_alt']={**desired['anytls'],'type':'anytls','port':2547}
        cfg,updated,changes=reconcile(c,s,desired)
        self.assertEqual(changes['added'],['anytls_alt'])
        rendered=render(cfg,updated,desired);nodes=export(rendered,updated)['proxies']
        self.assertEqual(nodes[:3],clients)
        self.assertNotEqual(nodes[0]['password'],nodes[-1]['password'])
        again,st,_=reconcile(rendered,updated,desired)
        self.assertEqual(again,rendered);self.assertEqual(st,updated)
        back,original,change=reconcile(rendered,updated,s['protocols'])
        self.assertEqual(change['removed'],['anytls_alt']);self.assertEqual(back,c)
    def test_second_listener_conflict(self):
        c,_,s=fixtures();d=copy.deepcopy(s['protocols']);d['second']={**d['anytls'],'type':'anytls'}
        c,s,_=reconcile(c,s,d)
        with self.assertRaises(ValueError):render(c,s,d)
    def test_type_cannot_replace_credentials(self):
        c,_,s=fixtures();d=copy.deepcopy(s['protocols']);d['anytls']={'type':'cf',**d['cf']}
        with self.assertRaises(ValueError):reconcile(c,s,d)
    def test_new_unregistered_family_and_shadowtls_cleanup(self):
        c,_,s=fixtures();d=copy.deepcopy(s['protocols']);p=defaults('test','JP','日本','192.0.2.1',None,'example.com','/test/key','/test/known')
        d['shadowtls']=p['protocols']['shadowtls'];c,s,_=reconcile(c,s,d)
        self.assertEqual(len(c['/test/s.json']['inbounds']),3)
        del d['shadowtls'];c,s,_=reconcile(c,s,d)
        self.assertEqual(len(c['/test/s.json']['inbounds']),1)
    def test_missing_core_is_not_silently_ignored(self):
        c,_,s=fixtures();del c['/test/s.json'];del s['bindings']['anytls'];del s['templates']['anytls'];del s['protocols']['anytls']
        d=copy.deepcopy(s['protocols']);d['other']={**fixtures()[2]['protocols']['anytls'],'type':'anytls','port':4447}
        with self.assertRaises(ValueError):reconcile(c,s,d)

class TunnelAPI(FakeCF):
    def __init__(self):super().__init__();self.tunnels=[];self.unknown_create=False
    def call(self,path,body=None,method=None):
        if path.endswith('/token'):return {'result':'fixture-connector-token'}
        if '/cfd_tunnel' in path and '/configurations' not in path:
            if method=='POST':
                self.tunnels.append({'id':'00000000-0000-0000-0000-000000000001','name':body['name']})
                if self.unknown_create:self.unknown_create=False;raise TimeoutError()
                return {'result':self.tunnels[-1]}
            if method=='DELETE':self.tunnels=[];return {'result':{}}
            return {'result':self.tunnels}
        return super().call(path,body,method)

class TunnelTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.path=Path(self.tmp.name)/'j.json';self.cf=TunnelAPI()
        self.server=defaults('new','JP','日本','192.0.2.1',None,'example.com','/test/key','/test/known')
    def test_unknown_tunnel_create_is_resumed_without_duplicate(self):
        self.cf.unknown_create=True
        with self.assertRaises(TimeoutError):tunnels.provision(self.cf,self.server,'example.com',self.path)
        result=tunnels.provision(self.cf,self.server,'example.com',self.path)
        self.assertEqual(len(self.cf.tunnels),1);self.assertEqual(len(self.cf.records),3)
        tunnels.provision(self.cf,self.server,'example.com',self.path)
        self.assertEqual(len(self.cf.records),3)
        tunnels.remove_owned(self.cf,self.path);self.assertFalse(self.cf.records);self.assertFalse(self.cf.tunnels)
    def test_existing_dns_refuses_before_tunnel(self):
        self.cf.records=[{'name':self.server['domains']['cf']}]
        with self.assertRaises(ValueError):tunnels.provision(self.cf,self.server,'example.com',self.path)
        self.assertFalse(self.cf.tunnels)
    def test_two_cf_paths_independent_and_duplicate_refused(self):
        p=self.server['protocols'];p['cf_alt']={**p['cf'],'type':'cf','port':18083,'ws_path':'/another'}
        self.assertEqual(len(tunnels.routes(self.server)),3)
        p['cf_alt']['ws_path']=p['cf']['ws_path']
        with self.assertRaises(ValueError):tunnels.routes(self.server)
    def test_changed_inventory_cannot_resume(self):
        tunnels.provision(self.cf,self.server,'example.com',self.path);self.server['ipv4']='192.0.2.2'
        with self.assertRaises(ValueError):tunnels.provision(self.cf,self.server,'example.com',self.path)

class CreatedSourceRecoveryTests(unittest.TestCase):
    def test_created_source_removed_after_unknown_post(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'j';config={'subscription':{'backend_url':'test'}};after={'name':'new','url':'private'};state={'current':after}
            save(path,{'backend_sha256':'test','attempted':[{'kind':'sub','name':'new','before':None,'after':after}],'temporary':[]})
            def request(*args,**kwargs):
                self.assertEqual(args[-1],'DELETE');state['current']=None
            publication.recover(path,config,lambda *a:state['current'],request,lambda x:x)
            self.assertIsNone(state['current']);self.assertFalse(path.exists())
