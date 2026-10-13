import copy,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from protocols import adopt,render,export,validate_settings
import publication
from storage import save,lock
from domains import build,stage,recover
import fleet

# Synthetic fixtures only: no production hosts, passwords or UUIDs.
def fixtures():
    configs={'/test/x.json':{'inbounds':[{'protocol':'vless','tag':'custom-reality','port':5443,'listen':'::','settings':{'clients':[{'id':'fixture-id'}]},'streamSettings':{'security':'reality','realitySettings':{'serverNames':['cover.example.com'],'target':'cover.example.com:443','shortIds':['abc123']}}}, {'protocol':'vmess','tag':'custom-cf','listen':'127.0.0.1','port':18082,'settings':{'clients':[{'id':'fixture-id'}]},'streamSettings':{'network':'ws','wsSettings':{'path':'/test'}}}]}, '/test/s.json':{'inbounds':[{'type':'anytls','tag':'custom-anytls','listen':'::','listen_port':2447,'users':[{'password':'fixture-password'}],'padding_scheme':[],'tls':{'certificate_path':'/test/cert.pem','key_path':'/test/key.pem'}}]}}
    clients=[{'name':'anytls','type':'anytls','port':2447,'password':'fixture-password','sni':'tls.example.com'}, {'name':'cf','type':'vmess','network':'ws','tls':True,'port':443,'server':'edge.example.com','servername':'edge.example.com','uuid':'fixture-id','ws-opts':{'path':'/test','headers':{'Host':'edge.example.com'}}}, {'name':'real','type':'vless','port':5443,'uuid':'fixture-id','servername':'cover.example.com','reality-opts':{'public-key':'fixture-public','short-id':'abc123'}}]
    state=adopt(configs,clients,{'/test/x.json':'x.service','/test/s.json':'s.service'})
    return configs,clients,state

class ProtocolTests(unittest.TestCase):
    def test_custom_tags_ports_and_reordered_clients(self):
        c,n,s=fixtures();self.assertEqual(export(c,s),{'proxies':n});self.assertEqual(render(c,s,s['protocols']),c)
    def test_port_and_cover_reference_update(self):
        c,n,s=fixtures();d=copy.deepcopy(s['protocols']);d['reality'].update(port=443,sni='new.example.com',cover_host='new.example.com')
        rendered=render(c,s,d);s['protocols']=d
        node=next(n for n in export(rendered,s)['proxies'] if n['type']=='vless')
        self.assertEqual(node['port'],443);self.assertEqual(node['servername'],'new.example.com')
    def test_disable_and_reenable_native_inbound(self):
        c,n,s=fixtures();d=copy.deepcopy(s['protocols']);d['anytls']['enabled']=False
        after=render(c,s,d);self.assertEqual(after['/test/s.json']['inbounds'],[])
        disabled=copy.deepcopy(s);disabled['protocols']=d
        self.assertEqual(len(export(after,disabled)['proxies']),2)
        self.assertEqual(render(after,disabled,s['protocols']),c)
    def test_port_conflict_rejected(self):
        c,n,s=fixtures();d=copy.deepcopy(s['protocols']);d['anytls']['port']=5443
        with self.assertRaises(ValueError):render(c,s,d)
    def test_unknown_field_cannot_silently_pass(self):
        with self.assertRaises(ValueError):validate_settings({'reality':{'typo':True}})
    def test_cf_origin_cannot_be_public(self):
        with self.assertRaises(ValueError):validate_settings({'cf':{'listen':'0.0.0.0'}})
    def test_duplicate_protocol_not_positional(self):
        c,n,s=fixtures()
        with self.assertRaises(ValueError):adopt(c,n+[n[0]],{'/test/x.json':'x','/test/s.json':'s'})
    def test_credentials_come_from_native(self):
        c,n,s=fixtures();c['/test/s.json']['inbounds'][0]['users'][0]['password']='rotated'
        self.assertEqual(export(c,s)['proxies'][0]['password'],'rotated')

class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.path=Path(self.t.name)/'journal';self.config={'subscription':{'backend_url':'https://example.com/private'}};self.digest=lambda x:x
        self.item={'kind':'file','name':'clash','before':{'value':1},'after':{'value':2}}
    def journal(self):
        j=publication.begin(self.path,self.config,self.digest);j['attempted']=[self.item];save(self.path,j)
    def test_crash_after_write_before_response_restores(self):
        self.journal();values=[self.item['after'],self.item['before']];writes=[]
        publication.recover(self.path,self.config,lambda *a:values.pop(0),lambda *a,**k:writes.append(a),self.digest)
        self.assertEqual(writes[0][2],self.item['before']);self.assertFalse(self.path.exists())
    def test_conflict_retains_journal_and_does_not_overwrite(self):
        self.journal();writes=[]
        with self.assertRaises(RuntimeError):publication.recover(self.path,self.config,lambda *a:{'value':3},lambda *a,**k:writes.append(a),self.digest)
        self.assertTrue(self.path.exists());self.assertFalse(writes)
    def test_staging_unknown_create_cleaned_after_crash(self):
        j=publication.begin(self.path,self.config,self.digest);j['temporary']=[['sub','server-check-random']];save(self.path,j);writes=[]
        publication.recover(self.path,self.config,None,lambda *a,**k:writes.append((a,k)),self.digest)
        self.assertEqual(writes[0][1]['method'],'DELETE')
    def test_second_transaction_refused(self):
        self.journal()
        with self.assertRaises(ValueError):publication.begin(self.path,self.config,self.digest)
    def test_lock_excludes_second_process(self):
        with lock(self.path):
            with self.assertRaises(RuntimeError):
                with lock(self.path):pass
    def test_private_state(self):
        save(self.path,{'private':'value'});self.assertEqual(self.path.stat().st_mode&0o777,0o600)

class FakeCF:
    def __init__(self):self.records=[];self.config={'ingress':[{'hostname':'old.example.com','service':'http://127.0.0.1:18082'},{'service':'http_status:404'}]};self.fail_after_post=False
    def zones(self):return [{'name':'example.com','id':'zone','status':'active','account':{'id':'account'}}]
    def call(self,path,body=None,method=None):
        from urllib.parse import parse_qs,urlsplit
        if 'configurations' in path:
            if body:self.config=body['config']
            return {'result':{'config':copy.deepcopy(self.config)}}
        if method=='POST':
            self.records.append({**body,'id':str(len(self.records)+1)})
            if self.fail_after_post:raise TimeoutError()
            return {'result':self.records[-1]}
        if method=='DELETE':self.records=[r for r in self.records if r['id']!=path.rsplit('/',1)[1]];return {'result':{}}
        query=parse_qs(urlsplit(path).query)
        return {'result':[r for r in self.records if all(r.get(k)==v[0] for k,v in query.items() if k in ('name','type'))]}

class DomainTests(unittest.TestCase):
    def setUp(self):
        self.cf=FakeCF();self.s={'id':'new','ipv4':'192.0.2.1','ipv6':'2001:db8::1','protocols':{'cf':{'port':18082}}};self.names={'ipv4':'new4.example.com','ipv6':'new6.example.com','cf':'edge-new.example.com','certificate':'tls-new.example.com'}
    def plan(self):return build(self.cf,'example.com',self.s,self.names,'00000000-0000-0000-0000-000000000000')
    def test_additive_domain_plan_preserves_old_route(self):
        p=self.plan();self.assertEqual(p['after']['ingress'][1:],p['before']['ingress']);self.assertEqual(len(p['records']),5)
    def test_conflicting_dns_refused(self):
        self.cf.records=[{'name':'new4.example.com','type':'A','content':'192.0.2.55','proxied':False}]
        with self.assertRaises(ValueError):self.plan()
    def test_domain_outside_zone_refused(self):
        self.names['cf']='external.test'
        with self.assertRaises(ValueError):self.plan()
    def test_stage_then_rollback_dns_and_tunnel(self):
        with tempfile.TemporaryDirectory() as d:
            j=Path(d)/'journal';before=copy.deepcopy(self.cf.config);stage(self.cf,self.plan(),j)
            self.assertEqual(len(self.cf.records),5);recover(self.cf,j)
            self.assertEqual(self.cf.records,[]);self.assertEqual(self.cf.config,before)
    def test_lost_post_response_reconciles_owned_record(self):
        self.cf.fail_after_post=True
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(TimeoutError):stage(self.cf,self.plan(),Path(d)/'journal')
            self.assertEqual(self.cf.records,[])
    def test_rollback_wont_delete_concurrent_record(self):
        with tempfile.TemporaryDirectory() as d:
            j=Path(d)/'journal';stage(self.cf,self.plan(),j);self.cf.records[-1]['content']='192.0.2.55'
            with self.assertRaises(ValueError):recover(self.cf,j)
            self.assertTrue(j.exists())

if __name__=='__main__':unittest.main()

class ReleaseTests(unittest.TestCase):
    def test_release_installs_idempotently_and_rejects_tampering(self):
        import release,install,hashlib
        with tempfile.TemporaryDirectory() as d:
            archive=release.package(Path(d)/'dist');digest=hashlib.sha256(Path(archive).read_bytes()).hexdigest();dest=Path(d)/'install'
            self.assertEqual(install.install(archive,digest,dest)['service_restarts'],0)
            self.assertEqual(install.install(archive,digest,dest)['installed'],json.loads((Path(__file__).resolve().parents[1]/'versions.json').read_text())['version'])
            self.assertTrue((dest/'current'/'agent.py').exists())
            with self.assertRaises(ValueError):install.install(archive,'0'*64,dest)
    def test_tar_path_traversal_is_rejected(self):
        import install,tarfile,io,hashlib
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'bad.tar.gz'
            with tarfile.open(path,'w:gz') as t:
                i=tarfile.TarInfo('../escape');i.size=1;t.addfile(i,io.BytesIO(b'x'))
            with self.assertRaises(ValueError):install.install(path,hashlib.sha256(path.read_bytes()).hexdigest(),Path(d)/'install')

class RoutingTests(unittest.TestCase):
    def test_domestic_dns_matches_routing_and_play_exception(self):
        import importlib,yaml
        with patch.object(fleet,'host_map',return_value={}):
            sys.modules.pop('dns_policy',None);dns=importlib.import_module('dns_policy')
        for fmt in ('clash','stash'):
            base=yaml.safe_load((Path(__file__).resolve().parents[1]/'templates'/('base-'+fmt+'.yaml')).read_text());v=dns.harden_config(base,fmt)
            policy=v['dns']['nameserver-policy']
            key='rule-set:国内域名' if fmt=='clash' else 'geosite:cn'
            self.assertTrue(policy[key][0].startswith('https://223.6.6.6/'))
            self.assertIn('1.1.1.1',policy['+.googleapis.cn'][0])
            self.assertTrue(v['rules'].index('DOMAIN-SUFFIX,googleapis.cn,日常线路')<v['rules'].index('DOMAIN-SUFFIX,cn,DIRECT'))
            self.assertEqual(v['rules'][0],'DST-PORT,53,REJECT')
            self.assertIn('DOMAIN-SUFFIX,feishucdn.com,DIRECT',v['rules'])
    def test_health_policy_rejects_accidental_5_minutes(self):
        config=json.loads((Path(__file__).resolve().parents[1]/'templates/servers.example.json').read_text());config['health']={'interval':300}
        with self.assertRaises(ValueError):fleet.validate(config)
        config['health']['interval']=1800;fleet.validate(config)

class NativeApplyTests(unittest.TestCase):
    def test_default_apply_refuses_restart_before_mutation(self):
        import agent
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);state={'native_sha256':{}};p={'state_before':state,'files':[],'services':['x.service']}
            with patch.object(agent,'STATE',base/'state'),patch.object(agent,'PLAN',base/'plan'),patch.object(agent,'JOURNAL',base/'journal'),patch.object(agent,'cmd') as cmd:
                save(agent.STATE,state);save(agent.PLAN,p)
                with self.assertRaises(ValueError):agent.apply()
                self.assertFalse(agent.JOURNAL.exists());cmd.assert_not_called()
    def test_recovery_of_written_native_file_preserves_external_changes(self):
        import agent
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);target=base/'native';target.write_text('external');j={'files':[{'path':str(target),'before':'old','after':'new'}],'state_before':{},'restarts_attempted':[]}
            with patch.object(agent,'STATE',base/'state'),patch.object(agent,'JOURNAL',base/'journal'),patch.object(agent,'cmd') as cmd:
                save(agent.JOURNAL,j)
                with self.assertRaises(RuntimeError):agent.restore()
                self.assertEqual(target.read_text(),'external');cmd.assert_not_called()

class ShadowrocketRoutingTests(unittest.TestCase):
    def test_direct_dns_and_domain_set_with_remote_final(self):
        import importlib
        with patch.object(fleet,'host_map',return_value={}):
            sys.modules.pop('dns_policy',None);dns=importlib.import_module('dns_policy')
        original=(Path(__file__).resolve().parents[1]/'templates/base-shadowrocket.conf').read_text()
        result=dns.harden_shadowrocket(original)
        self.assertIn('dns-server = https://223.6.6.6/dns-query\n',result)
        self.assertNotIn('fallback-dns-server = system',result)
        self.assertIn('DOMAIN-SET,https://raw.githubusercontent.com/blackmatrix7/',result)
        self.assertLess(result.index('DOMAIN-SUFFIX,googleapis.cn'),result.index('DOMAIN-SET,'))
        self.assertIn('FINAL,日常线路',result)
