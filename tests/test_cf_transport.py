"""CF management must remain TLS-verified and fail closed on the selected relay."""
import copy
import http.server
import io
import json
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock,patch

ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import cf_transport,domains,fleet,onboard,fleetctl,cf_audit


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.config=json.loads((ROOT/'templates/servers.example.json').read_text())
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.token=pathlib.Path(self.tmp.name)/'token';self.token.write_text('fixture-secret');self.token.chmod(0o600)
        self.config['cloudflare']={'token_file':str(self.token),'management_server':'jp'}
        self.transport=cf_transport.SSHTransport(self.config,'jp');self.addCleanup(self.transport.close)

    def launch(self,reply):
        proc=Mock();proc.poll.return_value=None;proc.wait.return_value=0
        context=Mock();context.__enter__=Mock(return_value=context);context.__exit__=Mock(return_value=False)
        reservation=Mock();reservation.__enter__=Mock(return_value=reservation);reservation.__exit__=Mock(return_value=False);reservation.getsockname.return_value=('127.0.0.1',34567)
        return proc,context,reservation,reply

    def test_verified_source_precedes_authorization_and_forward_is_loopback_only(self):
        proc,ready,reservation,_=self.launch(None)
        self.transport.connection=Mock();self.transport.connection.sock=Mock()
        raw=Mock(side_effect=[(200,b'ip=192.0.2.10\n'),(200,b'{"success":true}')])
        with patch.object(self.transport,'resolve',return_value=['1.1.1.1']),patch.object(cf_transport.socket,'socket',return_value=reservation),patch.object(cf_transport.socket,'create_connection',return_value=ready),patch.object(cf_transport.subprocess,'Popen',return_value=proc) as popen,patch.object(self.transport,'_request',raw):
            self.transport.request('/client/v4/zones',headers={'Authorization':'Bearer fixture-secret'})
        self.assertEqual(raw.call_args_list[0].args,('/cdn-cgi/trace',));self.assertFalse(raw.call_args_list[0].kwargs)
        self.assertEqual(raw.call_args_list[1].args[0],'/client/v4/zones')
        args=popen.call_args.args[0];self.assertIn('127.0.0.1:34567:1.1.1.1:443',args)
        self.assertEqual(args[args.index('-S')+1],'none');self.assertIn('ControlMaster=no',args)
        self.assertNotIn('fixture-secret',' '.join(args));self.assertTrue(self.transport.info()['verified'])
        self.transport.close();proc.terminate.assert_called_once()

    def test_unexpected_source_is_closed_before_a_token_is_sent(self):
        proc,ready,reservation,_=self.launch(None)
        with patch.object(self.transport,'resolve',return_value=['1.1.1.1']),patch.object(cf_transport.socket,'socket',return_value=reservation),patch.object(cf_transport.socket,'create_connection',return_value=ready),patch.object(cf_transport.subprocess,'Popen',return_value=proc),patch.object(self.transport,'_request',return_value=(200,b'ip=198.51.100.20\n')) as request:
            with self.assertRaisesRegex(RuntimeError,'未发送管理令牌'):
                self.transport.request('/client/v4/zones',headers={'Authorization':'Bearer fixture-secret'})
        self.assertEqual(request.call_count,1);self.assertTrue(self.transport.closed);proc.terminate.assert_called_once()

    def test_get_retries_only_after_rechecking_the_verified_connection(self):
        self.transport.proc=Mock(poll=Mock(return_value=None));self.transport.observed_ip=self.transport.expected_ip
        with patch.object(self.transport,'ensure') as ensure, \
             patch.object(self.transport,'_request',side_effect=[socket.timeout(),(200,b'{}')]) as request:
            self.assertEqual(self.transport.request('/client/v4/zones'),(200,b'{}'))
        self.assertEqual(ensure.call_count,2);self.assertEqual(request.call_count,2)

    def test_write_timeout_is_never_replayed(self):
        with patch.object(self.transport,'ensure') as ensure, \
             patch.object(self.transport,'_request',side_effect=socket.timeout()) as request:
            with self.assertRaises(socket.timeout):
                self.transport.request('/client/v4/zones',method='POST',body=b'fixture')
        self.assertEqual(ensure.call_count,1);self.assertEqual(request.call_count,1)

    def test_preflight_is_bounded_before_any_token(self):
        self.transport.proc=Mock(poll=Mock(return_value=None));self.transport.port=1234
        connection=Mock();connection.sock=None
        response=Mock();response.status=200;response.read.return_value=b'ip=192.0.2.10\n'
        connection.getresponse.return_value=response
        with patch.object(cf_transport,'ForwardHTTPS',return_value=connection) as factory:
            self.transport._request('/cdn-cgi/trace')
        self.assertEqual(factory.call_args.kwargs['timeout'],cf_transport.PREFLIGHT_TIMEOUT)
        self.assertEqual(connection.request.call_args.args[:2],('GET','/cdn-cgi/trace'))
        self.assertFalse(connection.request.call_args.kwargs['headers'])

    def test_stale_socket_is_dropped_before_authorized_request(self):
        self.transport.proc=Mock(poll=Mock(return_value=None));self.transport.port=1234
        self.transport.observed_ip=self.transport.expected_ip
        connection=Mock();connection.sock.settimeout.side_effect=OSError('closed')
        self.transport.connection=connection
        with self.assertRaises(OSError):
            self.transport._request('/client/v4/zones',headers={'Authorization':'fixture'})
        connection.request.assert_not_called();connection.close.assert_called_once()
        self.assertIsNone(self.transport.connection)
        self.assertFalse(self.transport.info()['verified'])

    def test_ssh_dns_failure_never_uses_local_http_or_leaks_stderr(self):
        with patch.object(cf_transport.subprocess,'run',side_effect=subprocess.CalledProcessError(255,'ssh',stderr='PRIVATE')),patch('urllib.request.urlopen') as direct:
            with self.assertRaises(RuntimeError) as caught:self.transport.request('/client/v4/zones')
        self.assertNotIn('PRIVATE',str(caught.exception));direct.assert_not_called()

    def test_dead_established_channel_does_not_reopen_or_fallback(self):
        self.transport.observed_ip=self.transport.expected_ip;self.transport.proc=Mock(poll=Mock(return_value=255))
        with patch.object(self.transport,'resolve') as resolve,patch('urllib.request.urlopen') as direct:
            with self.assertRaisesRegex(RuntimeError,'未回退本机出口'):self.transport.request('/client/v4/zones')
        resolve.assert_not_called();direct.assert_not_called()

    def test_api_host_is_not_an_arbitrary_forward_proxy(self):
        with self.assertRaises(ValueError):self.transport.request('https://example.com/private')
        with self.assertRaises(ValueError):self.transport.request('/cdn-cgi/trace')

    def test_client_routes_every_method_through_selected_transport_and_preserves_codes(self):
        transport=Mock();transport.request.return_value=(200,b'{"success":true,"result":[]}')
        cf=domains.Cloudflare(self.token,transport)
        with patch('urllib.request.urlopen') as direct:
            self.assertEqual(cf.call('/zones')['result'],[])
            cf.call('/zones/example/dns_records',{'content':'fixture'},'POST')
        direct.assert_not_called();self.assertEqual(transport.request.call_args.args[:2],('/client/v4/zones/example/dns_records','POST'))
        transport.request.return_value=(403,b'{"success":false,"errors":[{"code":10000}]}')
        with self.assertRaises(domains.CloudflareAPIError) as caught:cf.call('/zones')
        self.assertEqual(caught.exception.status,403);self.assertEqual(caught.exception.codes,(10000,))

    def test_inventory_rejects_missing_pending_or_ipv6_only_relay(self):
        for change in ('unknown','pending','ipv6-only'):
            cfg=copy.deepcopy(self.config)
            if change=='unknown':cfg['cloudflare']['management_server']='missing'
            elif change=='pending':cfg['servers'][0]['status']='pending'
            else:cfg['servers'][0]['ipv4']=None;cfg['servers'][0]['domains']['ipv4']=None
            with self.subTest(change=change),self.assertRaises(ValueError):fleet.validate(cfg)

    def test_domain_discovery_uses_same_inventory_transport(self):
        relay=Mock();relay.request.return_value=(200,json.dumps({'success':True,'result':[{'name':'example.com','status':'active','account':{'name':'fixture'}}]}).encode())
        with patch.dict(os.environ),patch.object(onboard,'read',return_value=self.config),patch.object(cf_transport,'SSHTransport',return_value=relay) as transport,patch.object(sys,'argv',['onboard','zones','--config',str(self.token)]):
            self.assertEqual(onboard.main()['zones'][0]['name'],'example.com')
        self.assertEqual(transport.call_args.args[1],'jp');self.assertTrue(relay.request.called)


class TLSForwardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=pathlib.Path(cls.temp.name)
        cls.cert=cls.root/'cert';cls.key=cls.root/'key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=api.cloudflare.com','-addext','subjectAltName=DNS:api.cloudflare.com','-keyout',str(cls.key),'-out',str(cls.cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        cls.received=[]
        cls.connection_ids=[]
        cls.trace_ip=b'192.0.2.10'
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            dropped=set()
            def do_GET(self):
                cls.received.append((self.path,self.headers['Host']))
                cls.connection_ids.append((self.path,self.client_address[1],bool(self.headers.get('Authorization'))))
                if self.path.endswith('/drop-once') and self.path not in self.dropped:
                    self.dropped.add(self.path);self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();return
                body=b'ip='+cls.trace_ip+b'\n' if self.path=='/cdn-cgi/trace' else b'{"success":true}'
                self.send_response(200);self.send_header('Content-Length',str(len(body)))
                if self.path.endswith('/close'):self.send_header('Connection','close')
                self.end_headers();self.wfile.write(body)
            def do_POST(self):
                self.rfile.read(int(self.headers.get('Content-Length','0')))
                cls.connection_ids.append((self.path,self.client_address[1],bool(self.headers.get('Authorization'))))
                self.connection.shutdown(socket.SHUT_RDWR);self.connection.close()
            def log_message(self,*args):pass
        cls.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cls.cert,cls.key)
        cls.server.socket=context.wrap_socket(cls.server.socket,server_side=True)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.thread.join(5);cls.temp.cleanup()

    def test_local_forward_validates_cf_name_and_sends_cf_host_header(self):
        context=ssl.create_default_context(cafile=str(self.cert))
        conn=cf_transport.ForwardHTTPS(self.server.server_port,context=context)
        try:
            conn.request('GET','/client/v4/zones');response=conn.getresponse();self.assertEqual(response.status,200);response.read()
        finally:conn.close()
        self.assertEqual(self.received[-1],('/client/v4/zones','api.cloudflare.com'))
        self.assertTrue(context.check_hostname);self.assertEqual(context.verify_mode,ssl.CERT_REQUIRED)

    def test_untrusted_certificate_is_rejected(self):
        conn=cf_transport.ForwardHTTPS(self.server.server_port)
        try:
            with self.assertRaises(ssl.SSLCertVerificationError):conn.request('GET','/client/v4/zones')
        finally:conn.close()

    def test_verified_trace_and_api_requests_share_the_same_tls_connection(self):
        config=json.loads((ROOT/'templates/servers.example.json').read_text())
        transport=cf_transport.SSHTransport(config,'jp');transport.proc=Mock(poll=Mock(return_value=None))
        transport.port=self.server.server_port;transport.observed_ip=transport.expected_ip
        original=cf_transport.ForwardHTTPS
        def connect(port,timeout):
            return original(port,timeout=timeout,context=ssl.create_default_context(cafile=str(self.cert)))
        before=len(self.connection_ids)
        try:
            with patch.object(cf_transport,'ForwardHTTPS',side_effect=connect):
                transport.request('/client/v4/a',headers={'Authorization':'fixture'})
                transport.request('/client/v4/b',headers={'Authorization':'fixture'})
        finally:transport.close()
        rows=self.connection_ids[before:]
        self.assertEqual([r[0] for r in rows],['/cdn-cgi/trace','/client/v4/a','/client/v4/b'])
        self.assertEqual(len({r[1] for r in rows}),1)
        self.assertEqual([r[2] for r in rows],[False,True,True])

    def test_closed_connection_rechecks_egress_before_sending_another_token(self):
        config=json.loads((ROOT/'templates/servers.example.json').read_text())
        transport=cf_transport.SSHTransport(config,'jp');transport.proc=Mock(poll=Mock(return_value=None))
        transport.port=self.server.server_port;transport.observed_ip=transport.expected_ip
        original=cf_transport.ForwardHTTPS
        def connect(port,timeout):
            return original(port,timeout=timeout,context=ssl.create_default_context(cafile=str(self.cert)))
        before=len(self.connection_ids)
        try:
            with patch.object(cf_transport,'ForwardHTTPS',side_effect=connect):
                transport.request('/client/v4/close',headers={'Authorization':'fixture'})
                transport.request('/client/v4/next',headers={'Authorization':'fixture'})
        finally:transport.close()
        rows=self.connection_ids[before:]
        self.assertEqual([r[0] for r in rows],['/cdn-cgi/trace','/client/v4/close','/cdn-cgi/trace','/client/v4/next'])
        self.assertNotEqual(rows[0][1],rows[2][1])
        self.assertEqual([r[2] for r in rows],[False,True,False,True])

    def test_disconnected_get_rechecks_egress_before_safe_retry(self):
        config=json.loads((ROOT/'templates/servers.example.json').read_text())
        transport=cf_transport.SSHTransport(config,'jp');transport.proc=Mock(poll=Mock(return_value=None))
        transport.port=self.server.server_port;transport.observed_ip=transport.expected_ip
        original=cf_transport.ForwardHTTPS
        def connect(port,timeout):
            return original(port,timeout=timeout,context=ssl.create_default_context(cafile=str(self.cert)))
        before=len(self.connection_ids)
        try:
            with patch.object(cf_transport,'ForwardHTTPS',side_effect=connect):
                self.assertEqual(transport.request('/client/v4/drop-once',headers={'Authorization':'fixture'})[0],200)
        finally:transport.close()
        rows=self.connection_ids[before:]
        self.assertEqual([r[0] for r in rows],['/cdn-cgi/trace','/client/v4/drop-once','/cdn-cgi/trace','/client/v4/drop-once'])
        self.assertEqual([r[2] for r in rows],[False,True,False,True])

    def test_new_connection_with_wrong_egress_never_receives_token(self):
        config=json.loads((ROOT/'templates/servers.example.json').read_text())
        transport=cf_transport.SSHTransport(config,'jp');transport.proc=Mock(poll=Mock(return_value=None))
        transport.port=self.server.server_port;transport.observed_ip=transport.expected_ip
        original=cf_transport.ForwardHTTPS
        def connect(port,timeout):
            return original(port,timeout=timeout,context=ssl.create_default_context(cafile=str(self.cert)))
        before=len(self.connection_ids)
        try:
            with patch.object(cf_transport,'ForwardHTTPS',side_effect=connect):
                transport.request('/client/v4/close',headers={'Authorization':'fixture'})
                type(self).trace_ip=b'198.51.100.20'
                with self.assertRaisesRegex(RuntimeError,'未发送管理令牌'):
                    transport.request('/client/v4/next',headers={'Authorization':'fixture'})
        finally:
            type(self).trace_ip=b'192.0.2.10';transport.close()
        rows=self.connection_ids[before:]
        self.assertEqual([r[0] for r in rows],['/cdn-cgi/trace','/client/v4/close','/cdn-cgi/trace'])
        self.assertEqual([r[2] for r in rows],[False,True,False])

    def test_disconnected_post_is_not_replayed(self):
        config=json.loads((ROOT/'templates/servers.example.json').read_text())
        transport=cf_transport.SSHTransport(config,'jp');transport.proc=Mock(poll=Mock(return_value=None))
        transport.port=self.server.server_port;transport.observed_ip=transport.expected_ip
        original=cf_transport.ForwardHTTPS
        def connect(port,timeout):
            return original(port,timeout=timeout,context=ssl.create_default_context(cafile=str(self.cert)))
        before=len(self.connection_ids)
        try:
            with patch.object(cf_transport,'ForwardHTTPS',side_effect=connect):
                with self.assertRaises((OSError,http.client.HTTPException)):
                    transport.request('/client/v4/write',method='POST',body=b'fixture',headers={'Authorization':'fixture'})
        finally:transport.close()
        rows=self.connection_ids[before:]
        self.assertEqual([r[0] for r in rows],['/cdn-cgi/trace','/client/v4/write'])


if __name__=='__main__':unittest.main()
