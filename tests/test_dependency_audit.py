"""Dependency acceptance must not mutate production or overstate renewal evidence."""
import contextlib
import copy
import hashlib
import http.server
import io
import json
import os
import pathlib
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock,patch

ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import acceptance,certificates,cf_audit,cf_probe,cf_transport,dependency_audit as audit,domains,fleetctl


def healthy():
    return {'native_matches':True,'protected':{'processes':{'caddy-sub.service':{'MainPID':'10','ActiveState':'active'}},'native_sha256':{'fixture':'digest'}},
            'caddy':{'hosts':['jp.example.com'],'policies':[{'issuers':[{'http01_enabled':True,'dns01_enabled':False}]}],
                     'storage_writable':True,'storage_supported':True,'ca_directories':[{'passed':True}]},
            'certificate_reload':[{'file_reference':True,'hot_reload':True}],
            'connector':{'distinct_from_management':True,'token_file_private':True},'other_renewal_jobs':{'active_certbot_with_configs':False,'active_acme_sh_cron':False}}


class NativeFactsTests(unittest.TestCase):
    def test_caddy_model_extracts_all_hosts_without_dns_or_ca_credentials(self):
        value={'apps':{'http':{'servers':{'a':{'routes':[{'match':[{'host':['one.example.com']}],'handle':[{'routes':[{'match':[{'host':['two.example.com']}]}]}]}]}}},
                       'tls':{'automation':{'policies':[{'subjects':['one.example.com','two.example.com'],'issuers':[{'module':'acme','ca':'https://PRIVATE:PRIVATE@ca.example.com/directory?PRIVATE','challenges':{'dns':{'provider':{'name':'cloudflare','api_token':'PRIVATE'}}}}]}]}}}}
        value['apps']['http']['servers']['a']['response']={'match':{'status_code':[200]}}
        result=audit.caddy_model(value);self.assertEqual(result['hosts'],['one.example.com','two.example.com'])
        self.assertNotIn('PRIVATE',json.dumps(result));issuer=result['policies'][0]['issuers'][0]
        self.assertTrue(issuer['dns01_enabled']);self.assertFalse(issuer['http01_enabled']);self.assertEqual(issuer['dns_provider'],'cloudflare')

    def test_healthy_http01_has_no_management_relay_dependency(self):
        result=audit.local_checks(healthy());self.assertTrue(result['passed']);self.assertFalse(result['renewal_requires_management_relay'])

    def test_storage_dns01_reload_connector_and_external_jobs_cannot_pass_silently(self):
        changes=[lambda v:v.update(native_matches=False),lambda v:v['caddy'].update(storage_writable=False),
                 lambda v:v['caddy']['policies'][0]['issuers'][0].update(dns01_enabled=True),
                 lambda v:v['certificate_reload'][0].update(hot_reload=False),lambda v:v['connector'].update(distinct_from_management=False),
                 lambda v:v['connector'].update(token_file_private=False),lambda v:v['other_renewal_jobs'].update(active_certbot_with_configs=True),
                 lambda v:v['caddy'].update(automatic_https_disabled=True),lambda v:v['caddy'].update(ca_directories=[{'passed':False}])]
        for change in changes:
            v=healthy();change(v)
            with self.subTest(change=change):self.assertFalse(audit.local_checks(v)['passed']);self.assertIsNone(audit.local_checks(v)['renewal_requires_management_relay'])

    def test_connector_digest_comparison_keeps_both_credentials_out_of_result(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);(root/'42').mkdir();token=root/'connector';token.write_text('connector-PRIVATE');token.chmod(0o600)
            (root/'42/cmdline').write_bytes(('cloudflared\0--token-file\0'+str(token)+'\0').encode())
            result=audit.connector_identity(42,hashlib.sha256(b'management-PRIVATE').hexdigest(),root)
            self.assertTrue(result['distinct_from_management']);self.assertTrue(result['token_file_private']);self.assertNotIn('PRIVATE',json.dumps(result))
            same=audit.connector_identity(42,hashlib.sha256(token.read_bytes()).hexdigest(),root);self.assertFalse(same['distinct_from_management'])
            token.chmod(0o644);self.assertFalse(audit.connector_identity(42,'a'*64,root)['token_file_private'])

    def test_ca_preflight_rejects_credentials_query_and_plain_http_without_request(self):
        for url in ['http://ca.example.com/directory','https://PRIVATE@ca.example.com/directory','https://ca.example.com/?PRIVATE']:
            with patch.object(audit.urllib.request,'build_opener') as opener:
                result=audit._acme_directory(url);self.assertFalse(result['passed']);self.assertNotIn('PRIVATE',json.dumps(result));opener.assert_not_called()

    def test_real_http404_is_reachability_not_an_acme_order(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def version_string(self):return 'Caddy'
            def do_GET(self):self.send_response(404);self.end_headers()
            def log_message(self,*args):pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        real=audit.http.client.HTTPConnection
        try:
            with patch.object(audit.http.client,'HTTPConnection',side_effect=lambda ip,port,timeout:real(ip,server.server_port,timeout=timeout)):
                row=audit.http_checks([{'name':'a/ipv4','ip':'127.0.0.1','host':'example.com'}])[0]
            self.assertTrue(row['passed']);self.assertEqual(row['status'],404);self.assertFalse(row['real_acme_validation'])
        finally:server.shutdown();server.server_close();thread.join(5)

    def test_http_failure_and_invalid_host_are_redacted_and_never_pass(self):
        with patch.object(audit.http.client,'HTTPConnection',side_effect=TimeoutError('PRIVATE')):
            row=audit.http_checks([{'name':'x','ip':'192.0.2.1','host':'example.com'}])[0]
        self.assertFalse(row['passed']);self.assertNotIn('PRIVATE',json.dumps(row))

    def test_real_snapshot_uses_process_config_and_never_returns_provider_secrets(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);proc=root/'proc';(proc/'10').mkdir(parents=True);(proc/'20').mkdir()
            config=root/'Caddyfile';config.write_text('fixture');connector=root/'connector';connector.write_text('connector-PRIVATE');connector.chmod(0o600)
            (proc/'10/cmdline').write_bytes(('caddy\0run\0--config\0'+str(config)+'\0--adapter\0caddyfile\0').encode());(proc/'10/environ').write_bytes(b'HOME=/var/lib/caddy-sub\0CF_API_TOKEN=manager-PRIVATE\0');(proc/'10/exe').symlink_to(sys.executable)
            (proc/'20/cmdline').write_bytes(('cloudflared\0--token-file\0'+str(connector)+'\0').encode())
            native=root/'native.json';native.write_text(json.dumps({'inbounds':[{'streamSettings':{'tlsSettings':{'certificates':[{'certificateFile':'file','keyFile':'file'}]}}}]}))
            state={'server_id':'jp','bindings':{},'native_sha256':{str(native):hashlib.sha256(native.read_bytes()).hexdigest()},'engines':{str(native):{'core':'xray'}}}
            model={'apps':{'http':{'servers':{'one':{'routes':[{'match':[{'host':['example.com']}]}]}}},'tls':{'automation':{'policies':[{'issuers':[{'module':'acme','challenges':{'dns':{'provider':{'name':'cloudflare','api_token':'manager-PRIVATE'}}}}]}]}}}}
            processes={'caddy-sub.service':{'MainPID':'10','User':'fixture','ActiveState':'active'},'argo.service':{'MainPID':'20','ActiveState':'active'}}
            with patch.object(audit,'_processes',return_value=processes),patch.object(audit,'_run',return_value=json.dumps(model)),patch.object(audit,'_acme_directory',return_value={'passed':True}),patch.object(audit.subprocess,'run',side_effect=lambda args,**kw:Mock(returncode=0 if args[0]=='runuser' else 1)):
                result=audit.snapshot(state,hashlib.sha256(b'manager-PRIVATE').hexdigest(),root=proc)
            self.assertTrue(result['native_matches']);self.assertTrue(result['caddy']['dns_uses_management_token']);self.assertTrue(result['connector']['distinct_from_management']);self.assertNotIn('PRIVATE',json.dumps(result))
            (proc/'10/cmdline').write_bytes(('caddy\0run\0--config\0'+str(config)+'\0').encode())
            with patch.object(audit,'_processes',return_value=processes),patch.object(audit,'_run',return_value=json.dumps(model)) as adapt,patch.object(audit.subprocess,'run',return_value=Mock(returncode=1)):
                audit.snapshot(state,hashlib.sha256(b'manager-PRIVATE').hexdigest(),probe_acme=False,root=proc)
            self.assertNotIn('--adapter',adapt.call_args.args[0])


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.config=json.loads((ROOT/'templates/servers.example.json').read_text());self.server=self.config['servers'][0]
        self.server['protocols']={'cf':{'enabled':True,'port':18082,'listen':'127.0.0.1','sni':'edge.example.com','ws_path':'/fixture'}}
        self.config['cloudflare']={'management_server':self.server['id'],'token_file':'fixture'}
        self.cf=Mock(token='PRIVATE');self.cf.zones.return_value=[{'id':'zone'}]
        self.cf.transport_info.return_value={'verified':True,'direct_fallback':False,'observed_ipv4':'192.0.2.10'}
        self.remote=Mock(side_effect=lambda config,sid,command,payload=None:copy.deepcopy(healthy()) if command=='dependency-snapshot' else {'nodes':[]})
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(domains.Cloudflare,'from_config',return_value=self.cf))
        self.stack.enter_context(patch.object(audit,'negative_source',return_value={'passed':True,'http_status':403}))
        self.stack.enter_context(patch.object(audit,'references',return_value={'passed':True}))
        self.stack.enter_context(patch.object(audit,'http_ingress',return_value={'passed':True}))
        self.stack.enter_context(patch.object(certificates,'run',return_value={'passed':True}))
        self.stack.enter_context(patch.object(cf_audit,'audit',return_value={'status':'partial','metadata_error':{'http_status':403},'read_access_passed':True}))
        self.stack.enter_context(patch.object(acceptance,'verify_new_server',return_value={'passed':True,'results':[]}))
        self.zones=self.stack.enter_context(patch.object(cf_probe,'zones_for',return_value=[{'id':'zone','account':{'id':'account'}}]))
        self.verify=self.stack.enter_context(patch.object(cf_probe,'verify',return_value={'passed':True,'cleanup_verified':True,'writes_tested':True}))

    def test_default_is_read_only_and_missing_policy_metadata_is_not_forged(self):
        value=audit.run(self.config,[self.server],self.remote)
        self.assertTrue(value['passed']);self.assertTrue(value['read_only']);self.assertFalse(value['writes_tested']);self.verify.assert_not_called()
        self.assertEqual(value['servers'][0]['cloudflare_policy']['status'],'partial');self.assertIsNone(value['servers'][0]['write_access']['passed'])
        self.assertNotIn('PRIVATE',json.dumps(value));self.cf.close.assert_called_once()

    def test_explicit_writes_are_deduplicated_per_scope_and_recoverable(self):
        second=copy.deepcopy(self.server);second['id']='second'
        value=audit.run(self.config,[self.server,second],self.remote,True)
        self.assertTrue(value['passed']);self.assertTrue(value['writes_tested']);self.assertFalse(value['read_only']);self.assertEqual(self.verify.call_count,1)
        self.assertIn('cf-audit',value['servers'][0]['write_recovery_command'])

    def test_write_failure_never_returns_success_and_keeps_attempt_evidence(self):
        self.verify.side_effect=TimeoutError('PRIVATE')
        value=audit.run(self.config,[self.server],self.remote,True)
        self.assertFalse(value['passed']);self.assertTrue(value['writes_tested']);self.assertNotIn('PRIVATE',json.dumps(value))

    def test_relay_failure_does_not_skip_independent_certificate_checks_or_send_writes(self):
        self.cf.zones.side_effect=OSError('PRIVATE')
        value=audit.run(self.config,[self.server],self.remote,True)
        self.assertFalse(value['passed']);self.verify.assert_not_called();self.assertTrue(value['servers'][0]['certificates']['passed'])
        self.assertFalse(value['writes_tested']);self.assertNotIn('PRIVATE',json.dumps(value))

    def test_process_or_configuration_drift_during_check_blocks_acceptance(self):
        count=0
        def remote(config,sid,command,payload=None):
            nonlocal count
            if command!='dependency-snapshot':return {'nodes':[]}
            count+=1;value=healthy()
            if count>1:value['protected']['processes']['caddy-sub.service']['MainPID']='20'
            return value
        self.assertFalse(audit.run(self.config,[self.server],remote)['passed'])

    def test_only_known_read_lock_contention_is_retried_and_mutations_are_rejected(self):
        read=Mock(side_effect=[RuntimeError('jp: 另一个维护事务正在运行'),{'read_only':True}])
        with patch.object(audit.time,'sleep'):
            self.assertTrue(audit.read_remote(read,self.config,'jp','dependency-snapshot',{})['read_only'])
        self.assertEqual(read.call_count,2)
        with self.assertRaises(ValueError):audit.read_remote(read,self.config,'jp','apply',{})
        read=Mock(side_effect=RuntimeError('PRIVATE network error'))
        with self.assertRaises(RuntimeError):audit.read_remote(read,self.config,'jp','dependency-snapshot',{})
        self.assertEqual(read.call_count,1)

    def test_fixed_management_relay_is_required_before_any_api_call(self):
        self.config['cloudflare'].pop('management_server')
        with self.assertRaises(ValueError):audit.run(self.config,[self.server],self.remote)
        self.cf.zones.assert_not_called()

    def test_observer_selection_does_not_depend_on_us_coordinator_for_tw_jp(self):
        c={'coordinator':'us','servers':[{'id':'tw','ipv4':'192.0.2.1','ipv6':'2001:db8::1'},{'id':'jp','ipv4':'192.0.2.2','ipv6':'2001:db8::2'},{'id':'us','ipv4':'192.0.2.3','ipv6':None}]}
        selected,peer=audit.observer_config(c,c['servers'][0]);self.assertEqual(peer,'jp');self.assertEqual(selected['coordinator'],'jp');self.assertEqual(c['coordinator'],'us')

    def test_cli_all_filter_private_report_exit_status_and_restart_guard(self):
        self.config['servers'].append({**copy.deepcopy(self.server),'id':'pending','status':'pending'})
        with tempfile.TemporaryDirectory() as d:
            path=pathlib.Path(d)/'report.json'
            for passed in [True,False]:
                args=['fleetctl','dependency-audit','--server','all','--output',str(path)]
                with patch.object(fleetctl,'read',return_value=self.config),patch.object(audit,'run',return_value={'passed':passed}) as run,patch.object(sys,'argv',args),contextlib.redirect_stdout(io.StringIO()):code=fleetctl.main()
                self.assertEqual(code,0 if passed else 2);self.assertEqual(len(run.call_args.args[1]),1);self.assertEqual(path.stat().st_mode&0o777,0o600)
        for option in ['--allow-restart','--recover-writes']:
            with patch.object(fleetctl,'read',return_value=self.config),patch.object(sys,'argv',['fleetctl','dependency-audit','--server','all',option]),self.assertRaises(ValueError):fleetctl.main()
        for protected in [self.server['ssh']['known_hosts'],self.config['cloudflare']['token_file']]:
            with patch.object(fleetctl,'read',return_value=self.config),patch.object(audit,'run') as run,patch.object(sys,'argv',['fleetctl','dependency-audit','--server','all','--output',protected]),self.assertRaises(ValueError):fleetctl.main()
            run.assert_not_called()


class NegativeSourceTests(unittest.TestCase):
    def test_only_verified403_proves_the_second_source_is_denied(self):
        config={'cloudflare':{'management_server':'us','token_file':'fixture'},'servers':[{'id':'us','ipv4':'192.0.2.1'},{'id':'jp','ipv4':'192.0.2.2'}]}
        for status in [403,401,None]:
            cf=Mock();cf.transport_info.return_value={'verified':True};cf.zones.side_effect=domains.CloudflareAPIError(status)
            with patch.object(domains,'Cloudflare',return_value=cf),patch.object(cf_transport,'SSHTransport'):
                value=audit.negative_source(config)
            self.assertEqual(value['passed'],status==403);cf.close.assert_called_once()


if __name__=='__main__':unittest.main()
