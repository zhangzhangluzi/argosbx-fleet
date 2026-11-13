import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import subscription_mss as mss

def fixture():
    opt={'tcp option':{'name':'maxseg','field':'size'}}
    expr=[
        {'match':{'op':'!=','left':{'payload':{'protocol':'ip','field':'saddr'}},'right':{'prefix':{'addr':'127.0.0.0','len':8}}}},
        {'match':{'op':'==','left':{'payload':{'protocol':'tcp','field':'dport'}},'right':8443}},
        {'match':{'op':'==','left':{'&':[{'payload':{'protocol':'tcp','field':'flags'}},['syn','rst']]},'right':'syn'}},
        {'match':{'op':'>','left':opt,'right':1200}},
        {'counter':{'packets':1,'bytes':60}},
        {'mangle':{'key':opt,'value':1200}},
    ]
    return {'nftables':[{'table':{'family':'ip','name':'argosbx_sub_mss'}},
                        {'chain':{'hook':'prerouting','type':'filter','policy':'accept','prio':-150}},
                        {'rule':{'family':'ip','table':'argosbx_sub_mss','chain':'preroute','expr':expr}}]}

class SubscriptionMssTest(unittest.TestCase):
    def test_rule_only_changes_new_ipv4_subscription_connections(self):
        rule=mss.RULE_SOURCE.read_text()
        for token in ('table ip argosbx_sub_mss','ip saddr != 127.0.0.0/8','tcp dport 8443',
                      'tcp flags & (syn | rst) == syn','tcp option maxseg size > 1200',
                      'tcp option maxseg size set 1200'):
            self.assertIn(token,rule)
        self.assertNotIn('drop',rule);self.assertNotIn('reject',rule)
        unit=mss.UNIT_SOURCE.read_text()
        self.assertIn('/usr/sbin/nft -f /etc/argosbx-fleet/argosbx-sub-mss.nft',unit)
        self.assertIn('ExecStop=/usr/sbin/nft delete table ip argosbx_sub_mss',unit)

    def test_live_table_validation_rejects_wrong_scope_or_extra_action(self):
        good=fixture();self.assertTrue(mss.valid_table(good))
        cases=[]
        wrong=copy.deepcopy(good);wrong['nftables'][2]['rule']['expr'][1]['match']['right']=443;cases.append(wrong)
        wrong=copy.deepcopy(good);wrong['nftables'][2]['rule']['expr'][3]['match']['right']=1400;cases.append(wrong)
        wrong=copy.deepcopy(good);wrong['nftables'][2]['rule']['expr'][0]['match']['right']['prefix']['len']=16;cases.append(wrong)
        wrong=copy.deepcopy(good);wrong['nftables'][2]['rule']['expr'].append({'drop':None});cases.append(wrong)
        wrong=copy.deepcopy(good);wrong['nftables'][1]['chain']['prio']=0;cases.append(wrong)
        for value in cases:
            with self.subTest(value=value):self.assertFalse(mss.valid_table(value))

    def test_exclusive_file_creation_never_overwrites_existing_content(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'owned';mss.create(path,b'original')
            with self.assertRaises(FileExistsError):mss.create(path,b'replacement')
            self.assertEqual(path.read_bytes(),b'original')

    def test_recover_refuses_to_remove_modified_files(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);journal=root/'journal.json';journal.write_text('{}');rule=root/'rule';rule.write_text('someone changed it')
            with patch.multiple(mss,JOURNAL=journal,RULE=rule,UNIT=root/'unit'), \
                 patch.object(mss,'run',side_effect=AssertionError('must not touch system')):
                with self.assertRaises(ValueError):mss.recover()
            self.assertEqual(rule.read_text(),'someone changed it');self.assertTrue(journal.exists())

    def test_stage_refuses_an_existing_transaction_without_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            journal=Path(d)/'journal.json';journal.write_text('{}')
            with patch.object(mss.os,'geteuid',return_value=0),patch.object(mss,'JOURNAL',journal), \
                 patch.object(mss,'run',side_effect=AssertionError('must not touch system')):
                with self.assertRaises(ValueError):mss.stage()
            self.assertTrue(journal.exists())

    def test_commit_refuses_changed_protected_processes(self):
        with tempfile.TemporaryDirectory() as d:
            journal=Path(d)/'journal.json';journal.write_text(json.dumps({'protected':{'x':'old'},
                'rule_sha256':mss.digest(mss.RULE_SOURCE.read_bytes()),'unit_sha256':mss.digest(mss.UNIT_SOURCE.read_bytes())}))
            with patch.object(mss,'JOURNAL',journal),patch.object(mss,'owned_files'), \
                 patch.object(mss,'verify',return_value={'verified':True}),patch.object(mss,'protected',return_value={'x':'new'}), \
                 patch.object(mss,'run',side_effect=AssertionError('rollback timer must remain')):
                with self.assertRaises(ValueError):mss.commit()
            self.assertTrue(journal.exists())

    def test_recover_removes_only_owned_files_after_interrupted_stage(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);journal=root/'journal.json';journal.write_text('{}');rule=root/'rule';unit=root/'unit'
            rule.write_bytes(mss.RULE_SOURCE.read_bytes());unit.write_bytes(mss.UNIT_SOURCE.read_bytes());other=root/'other';other.write_text('keep')
            def run(args,body=None,check=True):
                return subprocess.CompletedProcess(args,0,'not-found\n' if args[1]=='show' else '','')
            with patch.multiple(mss,JOURNAL=journal,RULE=rule,UNIT=unit),patch.object(mss,'table',return_value=None),patch.object(mss,'run',side_effect=run):
                self.assertEqual(mss.recover(),{'recovered':True})
            self.assertFalse(journal.exists());self.assertFalse(rule.exists());self.assertFalse(unit.exists());self.assertEqual(other.read_text(),'keep')

    def transaction(self,fail_start=False):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name)
        paths={'JOURNAL':root/'journal','RULE':root/'rule','UNIT':root/'unit'}
        state={'timer':False,'service':False,'table':False,'commands':[]}
        def run(args,body=None,check=True):
            state['commands'].append(args)
            code=0;out=''
            if args[:3]==['nft','-j','list']:
                code=0 if state['table'] else 1;out=json.dumps(fixture()) if state['table'] else ''
            elif args[:2]==['ss','-Hltnp']:out='LISTEN users:(("caddy"))\n'
            elif args[0]=='systemd-run':state['timer']=True
            elif args[:2]==['systemctl','is-active']:
                code=0 if state['timer' if args[-1]==mss.TIMER else 'service'] else 3
            elif args[:2]==['systemctl','is-enabled']:code=0 if state['service'] else 1
            elif args[:3]==['systemctl','enable','--now']:
                state['service']=True;state['table']=True
                if fail_start:raise RuntimeError('simulated post-apply failure')
            elif args[:2]==['systemctl','show']:out='loaded\n' if state['service'] else 'not-found\n'
            elif args[:3]==['systemctl','disable','--now']:state['service']=False;state['table']=False
            elif args[:2]==['systemctl','stop']:state['timer']=False
            elif args[:3]==['nft','delete','table']:state['table']=False
            if check and code:raise RuntimeError('simulated command failure')
            return subprocess.CompletedProcess(args,code,out,'')
        return paths,state,run

    def test_stage_and_commit_keep_rule_and_stop_only_rollback_timer(self):
        paths,state,run=self.transaction()
        with patch.multiple(mss,**paths),patch.object(mss.os,'geteuid',return_value=0), \
             patch.object(mss,'protected',return_value={'caddy':{'MainPID':'42'}}),patch.object(mss,'run',side_effect=run):
            self.assertTrue(mss.stage()['staged']);self.assertTrue(state['timer']);self.assertTrue(paths['JOURNAL'].exists())
            self.assertTrue(mss.commit()['committed'])
        self.assertTrue(state['table']);self.assertTrue(state['service']);self.assertFalse(state['timer'])
        self.assertFalse(paths['JOURNAL'].exists());self.assertTrue(paths['RULE'].exists());self.assertTrue(paths['UNIT'].exists())
        self.assertFalse(any(x[:2]==['systemctl','restart'] for x in state['commands']))

    def test_stage_failure_after_apply_recovers_owned_changes(self):
        paths,state,run=self.transaction(fail_start=True)
        with patch.multiple(mss,**paths),patch.object(mss.os,'geteuid',return_value=0), \
             patch.object(mss,'protected',return_value={'caddy':{'MainPID':'42'}}),patch.object(mss,'run',side_effect=run):
            with self.assertRaises(RuntimeError):mss.stage()
        self.assertFalse(state['table']);self.assertFalse(state['service']);self.assertFalse(state['timer'])
        self.assertFalse(paths['JOURNAL'].exists());self.assertFalse(paths['RULE'].exists());self.assertFalse(paths['UNIT'].exists())

if __name__=='__main__':unittest.main()
