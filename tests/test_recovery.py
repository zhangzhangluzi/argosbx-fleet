"""Crash boundaries and explicit parameter semantics, without production services."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import agent,fleet,fleetctl,protocols,servers
from storage import save
from test_core import fixtures


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        for key,name in [('STATE','state.json'),('PLAN','plan.json'),('JOURNAL','journal.json'),('TARGET','source.yaml')]:
            self.stack.enter_context(patch.object(agent,key,self.root/name))
        self.native=self.root/'native.json';self.native.write_text('new')
        self.before={'value':'old'};self.after={'value':'new'}
        save(agent.STATE,self.after);save(agent.PLAN,{'retained':True})
        agent.TARGET.write_text('new-source')
        self.j={'files':[{'path':str(self.native),'before':'old','after':'new'}],
                'state_before':self.before,'state_after':self.after,'restarts_attempted':[],
                'source':{'before':'old-source','after':'new-source','mode':0o640,'uid':os.getuid(),'gid':os.getgid()}}
        save(agent.JOURNAL,self.j)

    def test_export_and_plan_refuse_interrupted_transaction_even_with_plan(self):
        original=agent.PLAN.read_bytes()
        with self.assertRaises(ValueError):agent.export_source()
        with self.assertRaises(ValueError):agent.plan({})
        self.assertEqual(agent.TARGET.read_text(),'new-source')
        self.assertEqual(agent.PLAN.read_bytes(),original)

    def test_recover_restores_native_state_and_source_and_clears_plan(self):
        with patch.object(agent,'cmd') as command:
            self.assertEqual(agent.restore(),{'recovery':'restored'})
            command.assert_not_called()
        self.assertEqual(self.native.read_text(),'old')
        self.assertEqual(json.loads(agent.STATE.read_text()),self.before)
        self.assertEqual(agent.TARGET.read_text(),'old-source')
        self.assertEqual(agent.TARGET.stat().st_mode&0o777,0o640)
        self.assertFalse(agent.PLAN.exists());self.assertFalse(agent.JOURNAL.exists())
        self.assertEqual(agent.restore(),{'recovery':'nothing'})

    def test_recovery_requires_explicit_restart_before_any_write(self):
        self.j['restarts_attempted']=['x.service'];save(agent.JOURNAL,self.j)
        with patch.object(agent,'cmd') as command:
            with self.assertRaises(ValueError):agent.restore()
            command.assert_not_called()
        self.assertEqual(self.native.read_text(),'new');self.assertTrue(agent.JOURNAL.exists())
        with patch.object(agent,'cmd') as command:
            agent.restore(allow_restart=True)
            command.assert_called_once_with(['systemctl','restart','x.service'])

    def test_any_conflict_prevents_all_partial_restoration(self):
        other=self.root/'other';other.write_text('external')
        self.j['files'].insert(0,{'path':str(other),'before':'old','after':'new'});save(agent.JOURNAL,self.j)
        with self.assertRaises(RuntimeError):agent.restore()
        self.assertEqual(self.native.read_text(),'new')
        self.assertEqual(json.loads(agent.STATE.read_text()),self.after)
        self.assertEqual(agent.TARGET.read_text(),'new-source')

    def test_changed_source_or_registry_cannot_be_overwritten(self):
        for target,body in [(agent.TARGET,'external'),(agent.STATE,'{"value":"external"}')]:
            old=target.read_text();target.write_text(body)
            with self.assertRaises(RuntimeError):agent.restore()
            self.assertEqual(target.read_text(),body);self.assertEqual(self.native.read_text(),'new')
            target.write_text(old)

    def test_native_publication_preflight_blocks_journal_or_stale_export(self):
        s={'id':'jp','protocols':{'anytls':{'enabled':True}},'certificates':{}}
        healthy={**s,'native_configuration_matches':True,'services_active':True,'source_matches':True,'unfinished_transactions':[],'certificate_health':{'cert':{'usable':True}}}
        for change in [{'source_matches':False},{'unfinished_transactions':['apply-journal.json']}]:
            with patch.object(fleetctl,'remote',return_value={**healthy,**change}),self.assertRaises(ValueError):
                servers.native_preflight({'servers':[s]})
        with patch.object(fleetctl,'remote',return_value=healthy):servers.native_preflight({'servers':[s]})


class ParameterTests(unittest.TestCase):
    def test_cleared_client_option_and_alpn_do_not_reappear_from_template(self):
        c,n,s=fixtures()
        s['templates']['anytls'].update({'fast-open':True,'idle-session-timeout':30,'alpn':['h2']})
        s['protocols']['anytls'].update(client={},alpn=[])
        p=next(x for x in protocols.export(c,s)['proxies'] if x['type']=='anytls')
        for key in ('fast-open','idle-session-timeout','alpn'):self.assertNotIn(key,p)

    def test_protocol_inapplicable_and_missing_fields_rejected(self):
        c,n,s=fixtures()
        wrong=copy.deepcopy(s['protocols']);wrong['reality']['alpn']=['h2']
        with self.assertRaises(ValueError):protocols.render(c,s,wrong)
        missing=copy.deepcopy(s['protocols']);del missing['cf']['ws_path']
        with self.assertRaises(ValueError):protocols.render(c,s,missing)
        with self.assertRaises(ValueError):protocols.validate_settings({'shadowtls':{'client':{'udp-over-tcp-version':True}}})

    def test_partial_protocol_registration_matches_shadowrocket_groups(self):
        config=json.loads((ROOT/'templates/servers.example.json').read_text())
        config['schema']=2
        config['servers'][0]['protocols']={'anytls':{'enabled':True,'port':2447,'listen':'::','certificate':'cert','sni':'tls.example.com','alpn':[],'padding_scheme':[],'client':{}}}
        config['servers'][0]['certificates']={'cert':{'certificate_file':'/test/cert','key_file':'/test/key'}}
        fleet.validate(config);captured={}
        def capture(path,content,*args,**kwargs):captured['payload']=content
        with patch.object(fleet,'read',return_value=config),patch('storage.save',side_effect=capture),patch.dict(sys.modules),contextlib.redirect_stdout(io.StringIO()):
            sys.modules.pop('dns_policy',None);runpy.run_path(str(ROOT/'generate.py'))
        sr=next(x['content'] for x in captured['payload']['files'] if x['name']=='shadowrocket-config')
        group=next(x for x in sr.splitlines() if x.startswith('地区-日本 ='))
        self.assertIn('JP-T-v4-AnyTLS',group);self.assertIn('JP-T-v6-AnyTLS',group)
        for label in ['REALITY','Hysteria2','ShadowTLS','CF入口']:self.assertNotIn(label,group)
        import subprocess
        script=(ROOT/'region-processor.js').read_text().replace('SPEC',json.dumps(fleet.region_spec(config['servers'][0])))
        source=[{'type':'anytls','port':2447,'sni':'tls.example.com'},{'type':'hysteria2','port':2446}]
        p=subprocess.run(['node','-e',script+';console.log(JSON.stringify(operator('+json.dumps(source)+')));'],text=True,capture_output=True,check=True)
        self.assertEqual([n['type'] for n in json.loads(p.stdout)],['anytls','anytls'])
        config['servers'][0]['protocols']['anytls']['enabled']=False
        with self.assertRaises(ValueError):fleet.validate(config)


class DomainBoundaryTests(unittest.TestCase):
    def test_interrupted_certificate_stage_cannot_commit(self):
        config={'servers':[{'id':'jp'}],'cloudflare':{'token_file':'private'}}
        with tempfile.TemporaryDirectory() as d,patch.object(fleetctl,'STATE',Path(d)),patch.object(fleetctl,'read',return_value=config),patch.object(fleetctl,'Cloudflare'),patch.object(fleetctl,'remote') as remote:
            save(Path(d)/'jp-domain-journal.json',{'ready':True,'certificate':None,'plan':{'inventory':config,'names':{'certificate':'new.example.com'}}})
            with patch.object(sys,'argv',['fleetctl','domain-commit','--server','jp']),self.assertRaisesRegex(ValueError,'证书阶段'):
                fleetctl.main()
            remote.assert_not_called()

    def test_protocol_recover_passes_restart_authorization(self):
        with patch.object(fleetctl,'read',return_value={'servers':[{'id':'jp'}]}),patch.object(fleetctl,'remote',return_value={}) as remote,contextlib.redirect_stdout(io.StringIO()):
            for allowed in (False,True):
                argv=['fleetctl','protocol-recover','--server','jp']+(['--allow-restart'] if allowed else [])
                with patch.object(sys,'argv',argv):fleetctl.main()
                self.assertEqual(remote.call_args.kwargs,{'allow_restart':allowed})


class InstalledReleaseTests(unittest.TestCase):
    def test_existing_modified_release_is_rejected_without_switching(self):
        import install,release
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);a=Path(release.package(root/'dist'));digest=hashlib.sha256(a.read_bytes()).hexdigest()
            install.install(a,digest,root/'install');current=root/'install/current';target=current.resolve()
            (target/'agent.py').write_text('tampered')
            with self.assertRaisesRegex(ValueError,'Installed release file checksum'):
                install.install(a,digest,root/'install')
            self.assertEqual(current.resolve(),target)

class ApplyCrashTests(unittest.TestCase):
    def test_crash_after_registry_and_source_write_recovers_both(self):
        import yaml
        from storage import atomic
        with tempfile.TemporaryDirectory() as d,contextlib.ExitStack() as stack:
            root=Path(d);c,n,state=fixtures();mapped={}
            for old,body in c.items():
                new=str(root/Path(old).name);mapped[new]=body
                for binding in state['bindings'].values():
                    if binding['path']==old:binding['path']=new
                save(new,body)
            state['native_sha256']={p:agent.sha(Path(p).read_text()) for p in mapped}
            for key,name in [('STATE','state'),('PLAN','plan'),('JOURNAL','journal'),('TARGET','source')]:stack.enter_context(patch.object(agent,key,root/name))
            save(agent.STATE,state);before=yaml.safe_dump(protocols.export(mapped,state),allow_unicode=True,sort_keys=False);agent.TARGET.write_text(before)
            after=copy.deepcopy(state);after['protocols']['anytls']['client']={'fast-open':False}
            save(agent.PLAN,{'state_before':state,'state_after':after,'files':[],'services':[]})
            stack.enter_context(patch.object(agent,'cmd',return_value=''))
            stack.enter_context(patch.object(agent,'certificate_health',return_value={'cert':{'usable':True}}))
            import grp
            stack.enter_context(patch.object(agent.grp,'getgrnam',return_value=grp.getgrgid(os.getgid())))
            def crash(body,*args):
                atomic(agent.TARGET,body,0o640)
                raise KeyboardInterrupt('simulated process exit after source rename')
            with patch.object(agent,'write_source',side_effect=crash),self.assertRaises(KeyboardInterrupt):agent.apply()
            self.assertTrue(agent.JOURNAL.exists())
            self.assertNotEqual(agent.TARGET.read_text(),before)
            self.assertEqual(json.loads(agent.STATE.read_text())['protocols'],after['protocols'])
            agent.restore()
            self.assertEqual(agent.TARGET.read_text(),before)
            self.assertEqual(json.loads(agent.STATE.read_text()),state)
            self.assertFalse(agent.JOURNAL.exists());self.assertFalse(agent.PLAN.exists())
