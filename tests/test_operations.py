"""Failure-oriented tests for publication ownership, cleanup, and inventory isolation."""
import copy,io,json,os,ssl,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import agent,fleet,lease,publication,servers
from storage import save

class LeaseTests(unittest.TestCase):
    def test_lost_lock_stops_request_before_network(self):
        token=lease._active.set(Mock(poll=Mock(return_value=255)))
        try:
            with patch.object(servers.urllib.request,'urlopen') as http,self.assertRaisesRegex(RuntimeError,'协调锁'):
                servers.request({'subscription':{'backend_url':'https://example.com'}},'/api/sub/x',{},'PATCH')
            http.assert_not_called()
        finally:lease._active.reset(token)

    def test_lost_lock_during_request_rejects_success_receipt(self):
        token=lease._active.set(Mock(poll=Mock(side_effect=[None,255])))
        try:
            with patch.object(servers.urllib.request,'urlopen',return_value=io.BytesIO(b'{"status":"success"}')) as http,self.assertRaisesRegex(RuntimeError,'协调锁'):
                servers.request({'subscription':{'backend_url':'https://example.com'}},'/api/sub/x',{},'PATCH')
            self.assertEqual(http.call_count,1)
        finally:lease._active.reset(token)

class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'journal';self.config={'subscription':{'backend_url':'backend'}}
        self.names={'server-check-a','server-check-b'};self.deletes=[];self.mode='normal'
        j=publication.begin(self.path,self.config,lambda x:x);j['temporary']=[['sub',n] for n in sorted(self.names)];save(self.path,j)
    def request(self,config,path,value=None,method=None):
        if method=='DELETE':
            name=path.rsplit('/',1)[1];self.deletes.append(name)
            if self.mode=='blocked' and name.endswith('a'):raise PermissionError()
            if self.mode!='ignored':self.names.discard(name)
            if self.mode=='lost':raise TimeoutError()
            return None
        return [{'name':n} for n in self.names]
    def recover(self):return publication.recover(self.path,self.config,None,self.request,lambda x:x)
    def test_already_deleted_or_never_created_is_idempotent(self):
        self.names.clear();self.recover();self.assertFalse(self.deletes);self.assertFalse(self.path.exists())
    def test_lost_delete_response_verified_by_inventory(self):
        self.mode='lost';self.recover();self.assertFalse(self.path.exists());self.assertFalse(self.names)
    def test_partial_cleanup_records_progress_and_retries_only_remaining(self):
        self.mode='blocked'
        with self.assertRaises(RuntimeError):self.recover()
        self.assertEqual(json.loads(self.path.read_text())['temporary'],[['sub','server-check-a']])
        self.mode='normal';self.recover()
        self.assertEqual(self.deletes.count('server-check-b'),1)
    def test_success_response_without_actual_delete_retains_journal(self):
        self.mode='ignored'
        with self.assertRaises(RuntimeError):self.recover()
        self.assertTrue(self.path.exists())
    def test_conflict_preflight_prevents_partial_rollback(self):
        j=json.loads(self.path.read_text());j['temporary']=[]
        j['attempted']=[{'kind':'file','name':'a','before':1,'after':2},{'kind':'file','name':'b','before':3,'after':4}];save(self.path,j)
        write=Mock()
        with self.assertRaises(RuntimeError):
            publication.recover(self.path,self.config,lambda c,k,n:99 if n=='a' else 4,write,lambda x:x)
        write.assert_not_called()
    def test_plan_wont_overwrite_unfinished_transaction(self):
        with patch.object(servers,'JOURNAL',self.path),patch.object(servers,'native_preflight') as preflight,self.assertRaises(ValueError):servers.prepare(self.config)
        preflight.assert_not_called()

class ConfigIsolationTests(unittest.TestCase):
    def test_explicit_inventory_and_dns_hosts_change_in_same_process(self):
        one=json.loads((ROOT/'templates/servers.example.json').read_text());two=copy.deepcopy(one)
        two['servers'][0]['ipv4']='192.0.2.42';two['servers'][0]['domains']['ipv4']='new4.example.com'
        with tempfile.TemporaryDirectory() as d,patch.object(fleet,'STATE',Path(d)),patch.object(servers,'STATE',Path(d)),patch.object(fleet,'read',side_effect=AssertionError('ambient inventory accessed')):
            a=servers.generate(one);b=servers.generate(two)
            def clash(payload):return next(f for f in payload['files'] if f['name']=='clash')['process'][0]['args']['content']
            self.assertIn('jp4.example.com',clash(a));self.assertNotIn('new4.example.com',clash(a))
            self.assertIn('new4.example.com',clash(b));self.assertNotIn('jp4.example.com',clash(b))
            self.assertIn('192.0.2.42',clash(b))
            sr=next(f['content'] for f in b['files'] if f['name']=='shadowrocket-config')
            self.assertIn('new4.example.com = 192.0.2.42',sr);self.assertNotIn('jp4.example.com =',sr)
            self.assertEqual((Path(d)/'substore-payload.json').stat().st_mode&0o777,0o600)

class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.root=Path(cls.tmp.name)
        for name in ('one','two'):
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(cls.root/(name+'.key')),'-out',str(cls.root/(name+'.crt')),'-days','3','-subj','/CN=tls.example.com'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def state(self):return {'protocols':{'hy2':{'enabled':True,'certificate':'tls','sni':'tls.example.com'}},'certificates':{'tls':{'certificate_file':str(self.root/'one.crt'),'key_file':str(self.root/'one.key')}}}
    def test_real_cert_key_and_sni_checked_without_reload(self):
        health=agent.certificate_health(self.state())['tls']
        self.assertTrue(health['usable']);self.assertTrue(health['renewal_due']);self.assertGreaterEqual(health['days_remaining'],1)
    def test_wrong_sni_key_and_expiry_block_readiness(self):
        s=self.state();s['protocols']['hy2']['sni']='wrong.example.com';self.assertFalse(agent.certificate_health(s)['tls']['usable'])
        s=self.state();s['certificates']['tls']['key_file']=str(self.root/'two.key');self.assertFalse(agent.certificate_health(s)['tls']['usable'])
        with patch('time.time',return_value=time.time()+86400*4):self.assertFalse(agent.certificate_health(self.state())['tls']['usable'])
        with patch('time.time',return_value=time.time()-86400):self.assertFalse(agent.certificate_health(self.state())['tls']['usable'])
    def test_invalid_certificate_blocks_apply_before_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);state=self.state();state['native_sha256']={}
            with patch.object(agent,'STATE',p/'state'),patch.object(agent,'PLAN',p/'plan'),patch.object(agent,'JOURNAL',p/'journal'),patch.object(agent,'certificate_health',return_value={'tls':{'usable':False}}):
                save(agent.STATE,state);save(agent.PLAN,{'state_before':state,'state_after':state,'services':[],'files':[]})
                with self.assertRaises(ValueError):agent.apply()
                self.assertFalse(agent.JOURNAL.exists())
    def test_publication_blocks_unusable_certificate(self):
        import fleetctl
        s={'id':'jp','protocols':{'hy2':{'enabled':True}},'certificates':{}}
        live={**s,'native_configuration_matches':True,'services_active':True,'source_matches':True,'unfinished_transactions':[],'certificate_health':{'tls':{'usable':False}}}
        with patch.object(fleetctl,'remote',return_value=live),self.assertRaises(ValueError):servers.native_preflight({'servers':[s]})
