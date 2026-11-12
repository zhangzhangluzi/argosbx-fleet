import contextlib,copy,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import ad_delivery,lease,onboard,publication,servers,storage

class OnboardingTransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.inventory=self.root/'servers.json'
        self.before={'coordinator':'coordinator','subscription':{'backend_url':'https://example.invalid'},'servers':[{'id':'new','status':'pending'}]}
        storage.save(self.inventory,self.before)
        self.online={'status':'pending','marker':None,'sync_rules':0,'sync_countries':0}
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        for name,value in [('STATE',self.root),('PUBLICATION',self.root/'onboarding-publication.json')]:self.stack.enter_context(patch.object(onboard,name,value))
        for name,value in [('JOURNAL',self.root/'publication-journal.json'),('STAGING',self.root/'staging-journal.json'),('PLAN',self.root/'server-plan.json')]:self.stack.enter_context(patch.object(servers,name,value))
        self.stack.enter_context(patch.object(onboard,'inventory_file',return_value=self.inventory))
        self.stack.enter_context(patch.object(onboard,'read',side_effect=lambda path:json.loads(Path(path).read_text())))
        self.stack.enter_context(patch.object(lease,'coordinator',side_effect=lambda *a,**k:contextlib.nullcontext()))
        self.stack.enter_context(patch.object(onboard,'marker',side_effect=self.marker))
        self.stack.enter_context(patch.object(servers,'prepare',side_effect=self.prepare))
        self.stack.enter_context(patch.object(servers,'publish',side_effect=self.publish))
        self.stack.enter_context(patch.object(servers,'commit_deferred',side_effect=self.commit))
        self.stack.enter_context(patch.object(servers,'verify_committed_plan',side_effect=self.verify))
        self.stack.enter_context(patch.object(servers,'get',side_effect=lambda *a:{'status':self.online['status']}))
        self.stack.enter_context(patch.object(servers,'request',side_effect=self.request))
        self.rules=self.stack.enter_context(patch.object(servers,'sync_standard_rules',side_effect=self.rules_ok))
        self.countries=self.stack.enter_context(patch.object(servers,'sync_retired_countries',side_effect=self.countries_ok))

    def marker(self,config,ident,remove=False):
        if self.online['marker'] not in (None,ident):raise ValueError('marker conflict')
        self.online['marker']=None if remove else ident
    def prepare(self,config,owner=None):storage.save(servers.PLAN,{'inventory_sha256':servers.digest(config)})
    def publish(self,config,defer_commit=False,owner=None):
        self.assertTrue(defer_commit)
        item={'kind':'file','name':'fixture','before':{'status':'pending'},'after':{'status':'active'}}
        storage.save(servers.JOURNAL,{'owner':owner,'backend_sha256':servers.digest(config['subscription']['backend_url']),'attempted':[item],'temporary':[]})
        self.online['status']='active'
        return {'发布成功':True,'待接入提交':True}
    def commit(self,config,owner):self.assertEqual(json.loads(servers.JOURNAL.read_text())['owner'],owner);self.verify(config);servers.JOURNAL.unlink()
    def verify(self,config):
        self.assertEqual(self.online['status'],'active')
        self.assertEqual(json.loads(servers.PLAN.read_text())['inventory_sha256'],servers.digest(config))
    def rules_ok(self,config):self.online['sync_rules']+=1;return {'status':'verified'}
    def countries_ok(self,config):self.online['sync_countries']+=1;return {'status':'verified'}
    def request(self,config,path,value=None,method=None,**kwargs):self.online['status']=value['status']
    def current(self):return json.loads(self.inventory.read_text())

    def test_normal_commit_runs_both_hooks_and_clears_fences(self):
        result=onboard.publish_server(copy.deepcopy(self.before),'new')
        self.assertTrue(result['publication']['发布成功']);self.assertEqual(self.current()['servers'][0]['status'],'active')
        self.assertEqual((self.online['sync_rules'],self.online['sync_countries']),(1,1))
        self.assertIsNone(self.online['marker']);self.assertFalse(onboard.PUBLICATION.exists());self.assertFalse(servers.JOURNAL.exists())

    def test_failed_inventory_save_rolls_back_and_can_retry(self):
        def save(path,value):
            if Path(path)==self.inventory and value['servers'][0]['status']=='active':raise OSError('fixture disk failure')
            storage.save(path,value)
        with patch.object(onboard,'save',side_effect=save):
            with self.assertRaises(OSError):onboard.publish_server(copy.deepcopy(self.before),'new')
        self.assertEqual(self.current(),self.before);self.assertEqual(self.online['status'],'active');self.assertTrue(servers.JOURNAL.exists())
        self.assertFalse(onboard.resume_publication(self.current(),'new')['published'])
        self.assertEqual(self.online['status'],'pending');self.assertIsNone(self.online['marker'])
        self.assertTrue(onboard.publish_server(self.current(),'new')['publication']['发布成功'])

    def test_failure_after_inventory_save_restores_both_sides(self):
        with patch.object(servers,'commit_deferred',side_effect=OSError('fixture crash')):
            with self.assertRaises(OSError):onboard.publish_server(copy.deepcopy(self.before),'new')
        self.assertEqual(self.current()['servers'][0]['status'],'active');self.assertTrue(servers.JOURNAL.exists())
        self.assertFalse(onboard.resume_publication(self.current(),'new')['published'])
        self.assertEqual(self.current(),self.before);self.assertEqual(self.online['status'],'pending')

    def test_failed_post_sync_resumes_without_undoing_published_nodes(self):
        with patch.object(servers,'sync_standard_rules',return_value={'status':'failed'}):
            with self.assertRaises(RuntimeError):onboard.publish_server(copy.deepcopy(self.before),'new')
        self.assertFalse(servers.JOURNAL.exists());self.assertEqual(self.current()['servers'][0]['status'],'active')
        self.assertTrue(onboard.resume_publication(self.current(),'new')['published'])
        self.assertEqual(self.online['status'],'active');self.assertFalse(onboard.PUBLICATION.exists());self.assertIsNone(self.online['marker'])

    def test_external_inventory_change_blocks_all_recovery_writes(self):
        with patch.object(servers,'commit_deferred',side_effect=OSError('fixture crash')):
            with self.assertRaises(OSError):onboard.publish_server(copy.deepcopy(self.before),'new')
        changed=self.current();changed['other']='external';storage.save(self.inventory,changed)
        with self.assertRaises(ValueError):onboard.resume_publication(changed,'new')
        self.assertEqual(self.current(),changed);self.assertTrue(servers.JOURNAL.exists());self.assertEqual(self.online['status'],'active')

    def test_rejected_preflight_never_uploads_tools(self):
        config={'servers':[{'id':'new','status':'pending','onboarding':{}}]}
        with patch.object(onboard,'preflight_host',side_effect=ValueError('occupied')),patch.object(onboard,'upload_tools') as upload:
            with self.assertRaises(ValueError):onboard.install(config,'new')
            upload.assert_not_called()

class CoordinatorFenceTests(unittest.TestCase):
    def test_marker_creation_is_idempotent_and_conflicts_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker=Path(tmp)/'fence';own='a'*32;other='b'*32
            def local(config,ident,args,payload=None,timeout=600):
                script=args[-1].replace('/etc/argosbx-fleet/onboarding-publication.id',str(marker))
                p=subprocess.run([sys.executable,'-B','-c',script],input=payload,text=True,capture_output=True)
                if p.returncode:raise ValueError('marker conflict')
                return p.stdout
            with patch.object(onboard,'command',side_effect=local):
                onboard.marker({'coordinator':'us'},own);onboard.marker({'coordinator':'us'},own)
                self.assertEqual(marker.read_text(),own);self.assertEqual(marker.stat().st_mode&0o777,0o600)
                with self.assertRaises(ValueError):onboard.marker({'coordinator':'us'},other)
                self.assertEqual(marker.read_text(),own)
                onboard.marker({'coordinator':'us'},own,remove=True)
                self.assertFalse(marker.exists())

    def test_persistent_marker_blocks_other_publishers_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker=Path(tmp)/'fence';own='a'*32;other='b'*32
            def allowed(owner=None):return subprocess.run(['/bin/sh','-c',lease.marker_check(marker,owner)],capture_output=True).returncode==0
            self.assertTrue(allowed());self.assertTrue(allowed(own))
            marker.write_text(own)
            self.assertFalse(allowed());self.assertTrue(allowed(own));self.assertFalse(allowed(other))
            marker.unlink();marker.symlink_to(Path(tmp)/'missing')
            self.assertFalse(allowed());self.assertFalse(allowed(own))

    def test_owner_mismatch_never_recovers_another_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'journal';storage.save(path,{'owner':'other','backend_sha256':'fixture','attempted':[]})
            with self.assertRaises(ValueError):publication.recover(path,{'subscription':{'backend_url':'fixture'}},None,None,lambda x:x,owner='ours')
            self.assertTrue(path.exists())

    def test_automatic_ad_refresh_waits_for_onboarding_transaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker=Path(tmp)/'fence';ad_delivery.check_onboarding(marker)
            marker.write_text('a'*32)
            with self.assertRaises(ValueError):ad_delivery.check_onboarding(marker)
