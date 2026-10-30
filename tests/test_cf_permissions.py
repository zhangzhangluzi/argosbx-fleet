"""Dashboard policy binding and reversible isolated write evidence."""
import copy
import contextlib
import io
import datetime
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit,parse_qs

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import cf_audit,cf_probe,domains,fleetctl
from storage import save
from test_diagnostics_audit import FakeCF
import test_diagnostics_audit as fixtures


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.path=Path(self.tmp.name)/'policy'
        self.cf=FakeCF(metadata=False);self.now=datetime.datetime.now(datetime.timezone.utc)
        allowed=FakeCF();meta=allowed.call('/user/tokens/'+allowed.token)['result']
        meta['id']=self.cf.token
        self.value={'schema':1,'source':'cloudflare-dashboard','observed_at':self.now.isoformat(),
                    'token_sha256':hashlib.sha256(self.cf.token.encode()).hexdigest(),'metadata':meta}
        save(self.path,self.value)
    def test_current_snapshot_binds_to_actual_token_and_changes_evidence_source(self):
        result=cf_audit.audit(self.cf,fixtures.CloudflareAuditTests.server,self.path)
        self.assertEqual(result['status'],'passed');self.assertFalse(result['metadata_read'])
        self.assertEqual(result['metadata_source'],'dashboard_snapshot');self.assertFalse(result['writes_tested'])
        self.assertNotIn('/user/tokens/'+self.cf.token,self.cf.calls)
    def test_identity_age_and_file_permissions_cannot_be_silently_accepted(self):
        for key,value in [('token_sha256','incorrect'),('observed_at',(self.now-datetime.timedelta(days=2)).isoformat())]:
            candidate=copy.deepcopy(self.value);candidate[key]=value;save(self.path,candidate)
            with self.subTest(key=key),self.assertRaises(ValueError):cf_audit.snapshot_metadata(self.cf,self.cf.token,self.path)
        save(self.path,self.value)
        with self.assertRaises(ValueError):cf_audit.snapshot_metadata(self.cf,'wrong-id',self.path)
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):cf_audit.snapshot_metadata(self.cf,self.cf.token,self.path)
    def test_expired_snapshot_returns_unverified_instead_of_missing_permissions(self):
        self.value['observed_at']=(self.now-datetime.timedelta(days=2)).isoformat();save(self.path,self.value)
        result=cf_audit.audit(self.cf,fixtures.CloudflareAuditTests.server,self.path)
        self.assertEqual(result['status'],'partial');self.assertEqual(result['snapshot_error'],'policy_snapshot_expired')
        self.assertEqual(result['write_policy_status'],'not_verified')
    def test_rest_and_legacy_ip_condition_names_have_identical_meaning(self):
        condition={'in':['192.0.2.1/32'],'not_in':[]}
        a=cf_audit.ip_restrictions({'condition':{'request_ip':condition}})
        b=cf_audit.ip_restrictions({'condition':{'request.ip':condition}})
        self.assertEqual(a,b);self.assertTrue(a['configured']);self.assertEqual(a['mode'],'restricted')
        self.assertEqual(cf_audit.ip_restrictions({'condition':{}})['mode'],'allow_all')
    def test_403_is_classified_as_separate_token_management_scope(self):
        original=self.cf.call
        def call(path,*args,**kwargs):
            if path.endswith('/tokens/'+self.cf.token):raise domains.CloudflareAPIError(403,[9109])
            return original(path,*args,**kwargs)
        with patch.object(self.cf,'call',side_effect=call):r=cf_audit.audit(self.cf,fixtures.CloudflareAuditTests.server)
        self.assertEqual(r['metadata_error']['reason'],'token_management_read_not_granted')
        self.assertEqual(r['metadata_error']['required_permission'],'API Tokens Read')
        self.assertEqual(r['status'],'partial')


class WriteCF:
    token='fixture-secret-only'
    def __init__(self,lose=None):self.dns={};self.tunnels={};self.calls=[];self.lose=lose;self.delete_block=False;self.connector_rows=[]
    def zones(self):return FakeCF().zones()
    def call(self,path,body=None,method=None):
        method=method or 'GET';self.calls.append((method,path));parts=urlsplit(path);query=parse_qs(parts.query)
        if '/dns_records' in parts.path:
            ident=parts.path.split('/dns_records',1)[1].lstrip('/')
            if method=='POST':
                self.dns['d1']={'id':'d1',**body}
                if self.lose=='dns-create':raise TimeoutError()
                return {'result':self.dns['d1']}
            if method=='PATCH':self.dns[ident].update(body);return {'result':self.dns[ident]}
            if method=='DELETE':
                if self.delete_block:raise TimeoutError()
                self.dns.pop(ident,None);return {'result':{}}
            if ident:return {'result':self.dns[ident]}
            return {'result':[r for r in self.dns.values() if r['name']==query.get('name',[None])[0]]}
        if '/cfd_tunnel' in parts.path:
            tail=parts.path.split('/cfd_tunnel',1)[1].lstrip('/')
            if method=='POST':
                self.tunnels['t1']={'id':'t1',**body,'status':'inactive'}
                if self.lose=='tunnel-create':raise TimeoutError()
                return {'result':self.tunnels['t1']}
            if tail.endswith('/connections'):return {'result':self.connector_rows}
            if tail.endswith('/configurations'):
                if method=='PUT':
                    if self.lose=='tunnel-config-denied':raise domains.CloudflareAPIError(403,[10000])
                    self.tunnels['t1']['config']=copy.deepcopy(body['config'])
                    if self.lose=='tunnel-config':raise TimeoutError()
                if 'config' not in self.tunnels['t1']:raise domains.CloudflareAPIError(404)
                return {'result':{'config':self.tunnels['t1']['config']}}
            if method=='DELETE':self.tunnels.pop(tail,None);return {'result':{}}
            if tail:return {'result':self.tunnels[tail]}
            return {'result':[r for r in self.tunnels.values() if r['name']==query.get('name',[None])[0]]}
        raise AssertionError(path)


class WriteTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.journal=Path(self.tmp.name)/'journal'
    def test_complete_round_trip_touches_only_disposable_resources(self):
        cf=WriteCF();result=cf_probe.verify(cf,fixtures.CloudflareAuditTests.server,self.journal)
        self.assertTrue(result['passed']);self.assertTrue(result['cleanup_verified'])
        self.assertFalse(cf.dns);self.assertFalse(cf.tunnels);self.assertFalse(self.journal.exists())
        self.assertFalse(result['production_dns_changed']);self.assertFalse(result['production_tunnels_changed'])
        self.assertFalse(result['results'][1]['connectors_started'])
        self.assertFalse(any(path.endswith('/token') for _,path in cf.calls))

    def test_cli_marks_explicit_write_mode_and_default_never_writes(self):
        config={'servers':[{'id':'us'}],'cloudflare':{'token_file':'fixture'}}
        for explicit in (False,True):
            args=['fleetctl','cf-audit','--server','us']+(['--verify-writes'] if explicit else [])
            with patch.object(fleetctl,'read',return_value=config),patch.object(fleetctl,'Cloudflare'),patch.object(cf_audit,'audit',return_value={'read_only':True}),patch.object(cf_probe,'verify',return_value={'passed':True}) as verify,patch.object(sys,'argv',args),contextlib.redirect_stdout(io.StringIO()) as output:
                fleetctl.main()
            r=json.loads(output.getvalue());self.assertEqual(r['read_only'],not explicit)
            self.assertEqual(verify.call_count,1 if explicit else 0)
    def test_lost_post_and_put_responses_find_and_clean_owned_resources(self):
        for phase in ('dns-create','tunnel-create','tunnel-config','tunnel-config-denied'):
            cf=WriteCF(phase)
            with self.subTest(phase=phase),self.assertRaises(RuntimeError):cf_probe.verify(cf,fixtures.CloudflareAuditTests.server,self.journal)
            self.assertFalse(cf.dns);self.assertFalse(cf.tunnels);self.assertFalse(self.journal.exists())
    def test_failed_cleanup_retains_intent_and_can_be_retried(self):
        cf=WriteCF();cf.delete_block=True
        with self.assertRaises(TimeoutError):cf_probe.verify(cf,fixtures.CloudflareAuditTests.server,self.journal)
        self.assertTrue(self.journal.exists());self.assertTrue(cf.dns)
        self.assertEqual(self.journal.stat().st_mode&0o777,0o600)
        cf.delete_block=False;self.assertTrue(cf_probe.recover(cf,self.journal)['cleaned'])
        self.assertFalse(cf.dns);self.assertFalse(cf.tunnels)
    def test_third_party_change_and_token_mismatch_prevent_cleanup(self):
        cf=WriteCF();cf.delete_block=True
        with self.assertRaises(TimeoutError):cf_probe.verify(cf,fixtures.CloudflareAuditTests.server,self.journal)
        cf.delete_block=False;cf.dns['d1']['content']='changed-by-someone-else'
        with self.assertRaises(ValueError):cf_probe.recover(cf,self.journal)
        self.assertTrue(cf.dns);self.assertTrue(self.journal.exists())
        cf.token='different-token'
        with self.assertRaises(ValueError):cf_probe.recover(cf,self.journal)
    def test_unfinished_probe_blocks_a_second_allocation(self):
        save(self.journal,{'intent':'pending'})
        with self.assertRaises(ValueError):cf_probe.verify(WriteCF(),fixtures.CloudflareAuditTests.server,self.journal)

    def test_retired_detail_field_cannot_hide_an_active_connector(self):
        cf=WriteCF();cf.connector_rows=[{'id':'unexpected-connector','conns':[{'id':'live'}]}]
        with self.assertRaises(ValueError):cf_probe.verify(cf,fixtures.CloudflareAuditTests.server,self.journal)
        self.assertTrue(self.journal.exists());self.assertTrue(cf.tunnels);self.assertTrue(cf.dns)
        self.assertFalse(any(method=='DELETE' for method,_ in cf.calls))
        cf.connector_rows=[];self.assertTrue(cf_probe.recover(cf,self.journal)['cleaned'])

    def test_unknown_connections_response_or_read_denial_never_allows_delete(self):
        for response in [None,{},'invalid']:
            cf=WriteCF();cf.connector_rows=response
            with self.subTest(response=response),self.assertRaises(ValueError):cf_probe.verify(cf,fixtures.CloudflareAuditTests.server,self.journal)
            self.assertTrue(self.journal.exists());self.assertFalse(any(method=='DELETE' for method,_ in cf.calls))
            cf.connector_rows=[];cf_probe.recover(cf,self.journal)
        cf=WriteCF();original=cf.call
        def denied(path,*args,**kwargs):
            if path.endswith('/connections'):raise domains.CloudflareAPIError(403,[10000])
            return original(path,*args,**kwargs)
        with patch.object(cf,'call',side_effect=denied),self.assertRaises(domains.CloudflareAPIError):cf_probe.verify(cf,fixtures.CloudflareAuditTests.server,self.journal)
        self.assertTrue(self.journal.exists());self.assertFalse(any(method=='DELETE' for method,_ in cf.calls))

    def test_used_or_reconfigured_test_tunnel_is_not_deleted(self):
        cf=WriteCF()
        original=cf.call
        def call(path,body=None,method=None):
            result=original(path,body,method)
            if method=='PUT':
                cf.tunnels['t1']['config']={'ingress':[{'service':'http://127.0.0.1:1234'}]}
                raise TimeoutError()
            return result
        with patch.object(cf,'call',side_effect=call),self.assertRaises(RuntimeError):
            cf_probe.verify(cf,fixtures.CloudflareAuditTests.server,self.journal)
        self.assertTrue(self.journal.exists());self.assertTrue(cf.tunnels)
        self.assertFalse(any(method=='DELETE' and path.endswith('/t1') for method,path in cf.calls))


if __name__=='__main__':unittest.main()
