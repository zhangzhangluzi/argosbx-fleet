"""Failure-oriented transport, renewal and token-scope acceptance."""
import copy
import io
import json
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import agent,certificates,cf_audit,diagnostics,domains,fleetctl,probe


class NetworkTests(unittest.TestCase):
    def test_real_tcp_handshake_does_not_probe_udp_by_scanning(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));listener.listen(4)
            node={'type':'anytls','server':'127.0.0.1','port':listener.getsockname()[1]}
            rows=diagnostics.tcp_checks([{'name':'tcp/v4','node':node},{'name':'quic/v4','node':{**node,'type':'hysteria2'}}])
        self.assertEqual(len(rows),1);self.assertTrue(rows[0]['connected'])
        self.assertEqual(len(rows[0]['attempts']),2)

    def test_timeout_never_proves_ip_wide_censorship_or_leaks_exception_text(self):
        cases=[{'name':'tcp/v4','node':{'type':'anytls','server':'192.0.2.1','port':443}}]
        with patch.object(socket,'create_connection',side_effect=TimeoutError('PRIVATE token')):
            raw=diagnostics.tcp_checks(cases)
        r=diagnostics.classify(cases,raw,{'results':[{'name':'tcp/v4','https_ok':False}]})
        self.assertEqual(r['observations'][0]['layer'],'tcp_connect_failed')
        self.assertEqual(r['ip_wide_block'],'not_proven');self.assertFalse(r['mainland_path_tested'])
        self.assertNotIn('PRIVATE',json.dumps(raw))

    def test_icmp_is_observation_not_tcp_or_udp_reachability(self):
        cases=[{'node':{'server':'192.0.2.1'}},{'node':{'server':'edge.example.com'}}]
        with patch('shutil.which',return_value='/bin/ping'),patch.object(subprocess,'run',return_value=Mock(stdout='2 packets transmitted, 1 received, 50% packet loss',returncode=0)) as run:
            rows=diagnostics.ping_checks(cases)
        self.assertEqual(rows,[{'address':'192.0.2.1','reply_observed':True,'transmitted':2,'received':1,'status':'sampled'}])
        self.assertEqual(run.call_count,1)
        with patch('shutil.which',return_value=None):
            self.assertIsNone(diagnostics.ping_checks(cases)[0]['reply_observed'])

    def test_udp_forwarding_over_tcp_is_separate_from_udp_entry(self):
        cases=[{'name':'tcp/v4','node':{'type':'anytls'}},{'name':'udp/v4','node':{'type':'hysteria2'}}]
        native={'results':[{'name':'tcp/v4','https_ok':True,'exit_ok':True,'udp_ok':True},
                           {'name':'udp/v4','https_ok':False,'udp_ok':False}]}
        r=diagnostics.classify(cases,[],native)['observations']
        self.assertEqual(r[0]['transport'],'tcp');self.assertEqual(r[1]['transport'],'udp')
        self.assertTrue(r[0]['udp_forwarding_ok']);self.assertIsNone(r[1]['entry_reachable'])

    def test_counter_deltas_preserve_unknown_boot_reset_and_socket_identity(self):
        before={'boot_id':'one','monotonic':1,'counters':{'UdpRcvbufErrors':1461},
                'services':{'sb':{'pid':10}},'sockets':[{'service':'sb','inode':'100','transport':'udp','drops':5,'port':443,'family':4}]}
        after=copy.deepcopy(before);after['monotonic']=4
        r=diagnostics.delta(before,after)
        self.assertEqual(r['host_counter_delta']['UdpRcvbufErrors'],0)
        self.assertEqual(r['socket_drop_delta'][0]['drops'],0)
        after['boot_id']='two';self.assertFalse(diagnostics.delta(before,after)['valid'])
        after['boot_id']='one';after['services']['sb']['pid']=20
        self.assertFalse(diagnostics.delta(before,after)['processes_preserved'])
        self.assertFalse(diagnostics.delta(before,after)['socket_drop_delta'])
        after['counters']['UdpRcvbufErrors']=1
        self.assertIsNone(diagnostics.delta(before,after)['host_counter_delta']['UdpRcvbufErrors'])

    def test_proc_snapshot_scopes_socket_drops_to_registered_processes(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'net').mkdir();(root/'10/fd').mkdir(parents=True)
            (root/'10/fd/5').symlink_to('socket:[100]')
            (root/'net/udp').write_text('header\n0: 00000000:01BB 00000000:0000 07 00000000:00000002 00:0 0 0 0 100 2 0 7\n')
            (root/'net/snmp').write_text('Udp: InDatagrams RcvbufErrors\nUdp: 2 1461\n')
            (root/'sys/kernel/random').mkdir(parents=True);(root/'sys/kernel/random/boot_id').write_text('boot')
            service=Mock(stdout='MainPID=10\nActiveState=active\n')
            with patch.object(subprocess,'run',return_value=service):
                r=diagnostics.snapshot({'bindings':{'a':{'service':'sb'}}},root)
            self.assertEqual(r['sockets'][0]['drops'],7)
            self.assertEqual(r['counters']['UdpRcvbufErrors'],1461)
            self.assertFalse(r['packet_capture_performed'])

    def test_unrelated_or_ipv4_only_observer_is_rejected(self):
        server={'id':'tw'};case={'name':'hy2/ipv6'}
        remote=Mock(return_value={'nodes':[]})
        with patch('acceptance.cases',return_value=[case]):
            with self.assertRaises(ValueError):diagnostics.run({'servers':[{'id':'us','ipv6':None}]},server,remote,'us')


class RenewalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name)
        key=cls.root/'key.pem'
        for name in ('old','new'):
            args=['openssl','req','-x509','-nodes','-days','3','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-out',str(cls.root/(name+'.pem'))]
            args+=['-newkey','rsa:2048','-keyout',str(key)] if name=='old' else ['-key',str(key)]
            subprocess.run(args,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def test_whole_certificate_pin_detects_same_key_new_leaf(self):
        old=certificates.leaf(self.root/'old.pem')[1];new=certificates.leaf(self.root/'new.pem')[1]
        self.assertNotEqual(old,new)
        n={'type':'hysteria2','server':'127.0.0.1','port':443,'sni':'localhost','password':'fixture',
           '_certificate_sha256':new,'obfs':'salamander','obfs-password':'fixture-only'}
        config=probe.certificate_client(n,12345)
        stream=config['outbounds'][0]['streamSettings']
        self.assertEqual(stream['tlsSettings']['pinnedPeerCertSha256'],new)
        self.assertNotIn('allowInsecure',stream['tlsSettings'])
        self.assertEqual(stream['network'],'hysteria')
        self.assertEqual(stream['finalmask']['udp'][0]['type'],'salamander')

    def test_real_tls_certificate_comparison(self):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(4);port=listener.getsockname()[1]
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(self.root/'old.pem',self.root/'key.pem')
        def serve():
            for _ in range(2):
                raw,_=listener.accept()
                try:
                    with context.wrap_socket(raw,server_side=True):pass
                except ssl.SSLError:raw.close()
            listener.close()
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        pem,fingerprint=certificates.leaf(self.root/'old.pem')
        case={'name':'anytls/v4','node':{'server':'127.0.0.1','port':port,'sni':'localhost'},'sha256':fingerprint,'certificate_pem':pem}
        self.assertTrue(certificates.tcp_certificate(case)['passed'])
        # Keep a trusted old leaf so the test observes the actual DER mismatch.
        case['sha256']=certificates.leaf(self.root/'new.pem')[1]
        result=certificates.tcp_certificate(case)
        self.assertFalse(result['passed']);self.assertEqual(result['status'],'served_certificate_differs')
        thread.join(5);self.assertFalse(thread.is_alive())

    def test_snapshot_detects_new_managed_certificate_and_redacts_public_pem(self):
        storage=self.root/'managed';target=storage/'ca/localhost/localhost.crt';target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes((self.root/'new.pem').read_bytes())
        state={'protocols':{'anytls':{'enabled':True,'certificate':'tls','sni':'localhost'}},
               'certificates':{'tls':{'certificate_file':str(self.root/'old.pem'),'key_file':str(self.root/'key.pem')}}}
        with patch.object(subprocess,'run',return_value=Mock(returncode=0)):
            snapshot=certificates.snapshot(state,{'tls':{'usable':True}},storage)
        row=snapshot['certificates']['tls']
        self.assertEqual(row['renewal_warning'],'newer_managed_certificate_differs')
        self.assertFalse(snapshot['forced_renewal']);self.assertFalse(snapshot['services_reloaded'])
        self.assertNotIn('certificate_pem',certificates.redact(snapshot)['certificates']['tls'])

    def test_subscription_certificate_comes_from_its_own_caddy_identity(self):
        storage=self.root/'http';target=storage/'ca/sub.example.com/sub.example.com.crt';target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes((self.root/'old.pem').read_bytes())
        with patch.object(subprocess,'run',return_value=Mock(returncode=0)):
            r=certificates.snapshot({'protocols':{},'certificates':{}},{},storage,http_hosts=['sub.example.com'])
        self.assertEqual(r['http_certificates'][0]['sha256'],certificates.leaf(target)[1])
        self.assertNotIn('certificate_pem',certificates.redact(r)['http_certificates'][0])
        with self.assertRaises(ValueError):certificates.snapshot({'protocols':{},'certificates':{}},{},storage,http_hosts=['../../key'])

    def test_failed_pinned_handshake_never_claims_a_stale_certificate(self):
        case={'name':'hy2/v4','node':{'type':'hysteria2'},'sha256':'0'*64,'expected_ips':[]}
        with patch.object(probe,'client_session',side_effect=OSError('PRIVATE')),patch.object(probe,'https'):
            r=certificates.verify([case])[0]
        self.assertFalse(r['passed']);self.assertEqual(r['status'],'expected_certificate_not_verified')
        self.assertNotIn('PRIVATE',json.dumps(r));self.assertEqual(len(r['attempts']),2)


class FakeCF:
    account='a'*32;zone='b'*32;token='c'*32;tunnel='12345678-1234-1234-1234-123456789012'
    def __init__(self,metadata=True,account_token=False):self.metadata=metadata;self.account_token=account_token;self.calls=[]
    def zones(self):return [{'id':self.zone,'name':'example.com','status':'active','account':{'id':self.account}}]
    def call(self,path,body=None,method=None):
        assert body is None and method in (None,'GET'),'audit attempted a write'
        self.calls.append(path)
        if path.endswith('/verify'):
            if path.startswith('/user') and self.account_token:raise domains.CloudflareAPIError(403,[10000])
            return {'result':{'status':'active','id':self.token}}
        if path.endswith('/tokens/'+self.token):
            if not self.metadata:raise domains.CloudflareAPIError(403)
            return {'result':{'policies':[{'effect':'allow','resources':{'com.cloudflare.api.account.zone.'+self.zone:'*'},'permission_groups':[{'name':'DNS Write'}]},
                                         {'effect':'allow','resources':{'com.cloudflare.api.account.'+self.account:'*'},'permission_groups':[{'name':'Cloudflare Tunnel Write'}]}],
                              'condition':{'request.ip':{'in':['192.0.2.1/32']}}}}
        if '/dns_records?' in path:return {'result':[{'type':'CNAME','content':self.tunnel+'.cfargotunnel.com'}]}
        if path.endswith('/configurations'):return {'result':{'config':{'ingress':[]}}}
        raise AssertionError(path)


class CloudflareAuditTests(unittest.TestCase):
    server={'id':'jp','domains':{'ipv4':'jp4.example.com','ipv6':None,'cf':'edge.example.com'},
            'protocols':{'cf':{'enabled':True,'sni':'edge.example.com'}}}
    def test_read_only_audit_distinguishes_declared_and_executed_permissions(self):
        cf=FakeCF();r=cf_audit.audit(cf,self.server)
        self.assertEqual(r['status'],'passed');self.assertTrue(r['read_access_passed'])
        self.assertEqual(r['write_policy_status'],'declared_granted');self.assertFalse(r['writes_tested'])
        self.assertEqual(r['source_ip_filter']['actual_api_source_ip'],'not_observed')
        self.assertNotIn(cf.token,json.dumps(r))

    def test_token_verify_and_dns_reads_do_not_prove_write_permissions(self):
        r=cf_audit.audit(FakeCF(metadata=False),self.server)
        self.assertTrue(r['read_access_passed']);self.assertEqual(r['token']['status'],'active')
        self.assertEqual(r['status'],'partial');self.assertEqual(r['write_policy_status'],'not_verified')
        self.assertIsNone(r['source_ip_filter']['configured'])

    def test_multiple_cf_hostnames_can_share_one_owned_tunnel(self):
        s=copy.deepcopy(self.server);s['protocols']['cf_second']={'type':'cf','enabled':True,'sni':'second.example.com'}
        r=cf_audit.audit(FakeCF(),s)
        self.assertEqual(r['status'],'passed');self.assertFalse(r['unresolved_cf_hosts'])
        self.assertEqual(r['tunnels'][0]['hosts'],['edge.example.com','second.example.com'])

    def test_account_owned_token_uses_correct_verify_and_metadata_endpoints(self):
        cf=FakeCF(account_token=True);r=cf_audit.audit(cf,self.server)
        self.assertEqual(r['status'],'passed');self.assertIn('/accounts/'+cf.account+'/tokens/verify',cf.calls)

    def test_wrong_resource_scope_and_explicit_deny_never_grant_edit(self):
        metadata={'policies':[{'effect':'allow','resources':{'com.cloudflare.api.account.zone.'+'d'*32:'*'},'permission_groups':[{'name':'DNS Write'}]}]}
        self.assertEqual(cf_audit.declared_permission(metadata,'dns_edit',FakeCF.account,FakeCF.zone),'not_granted')
        metadata['policies'][0]['resources']={'*':'*'}
        self.assertEqual(cf_audit.declared_permission(metadata,'dns_edit',FakeCF.account,FakeCF.zone),'declared_granted')
        metadata['policies'].append({**metadata['policies'][0],'effect':'deny'})
        self.assertEqual(cf_audit.declared_permission(metadata,'dns_edit',FakeCF.account,FakeCF.zone),'not_granted')

    def test_missing_domain_or_dns_permission_is_actionable(self):
        cf=FakeCF();cf.zones=lambda:[]
        r=cf_audit.audit(cf,self.server);self.assertEqual(r['status'],'needs_attention')
        self.assertIn('edge.example.com',r['unavailable_hosts'])

    def test_http_api_errors_expose_only_codes(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'token';p.write_text('PRIVATE');p.chmod(0o600);cf=domains.Cloudflare(p)
            error=urllib.error.HTTPError('https://api.cloudflare.com',403,'PRIVATE',{},io.BytesIO(b'{"errors":[{"code":10000,"message":"PRIVATE"}]}'))
            with patch('urllib.request.urlopen',side_effect=error),self.assertRaises(domains.CloudflareAPIError) as caught:
                cf.call('/zones')
        self.assertEqual(caught.exception.status,403);self.assertEqual(caught.exception.codes,(10000,))
        self.assertNotIn('PRIVATE',str(caught.exception))

    def test_audit_cli_cannot_accept_restart_permission(self):
        with patch.object(fleetctl,'read',return_value={'servers':[{'id':'jp'}]}),patch.object(sys,'argv',['fleetctl','diagnose','--server','jp','--allow-restart']),self.assertRaises(ValueError):
            fleetctl.main()


if __name__=='__main__':unittest.main()
