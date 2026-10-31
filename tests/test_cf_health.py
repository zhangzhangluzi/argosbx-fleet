"""Real loopback HTTP and process-change regressions for connector evidence."""
import copy,http.server,json,subprocess,sys,tempfile,threading,unittest
from pathlib import Path
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import diagnostics

class ConnectorEvidenceTests(unittest.TestCase):
    state={'protocols':{'cf':{'enabled':True}}}
    def check(self,body,metrics_status=200,protocol_arg='--protocol=http2\0'):
        paths=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                paths.append(self.path);self.send_response(200 if self.path=='/ready' else metrics_status);self.end_headers()
                self.wfile.write(b'ready' if self.path=='/ready' else body)
            def log_message(self,*args):pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);(root/'42').mkdir();(root/'42/exe').symlink_to(root/'cloudflared')
                (root/'42/cmdline').write_bytes(('cloudflared\0'+protocol_arg+'--metrics\0'+'127.0.0.1:'+str(server.server_port)+'\0--token\0PRIVATE\0').encode())
                (root/'42/environ').write_bytes(b'TUNNEL_TRANSPORT_PROTOCOL=http2\0TUNNEL_TOKEN=PRIVATE\0')
                command=Mock(side_effect=['','42'])
                result=diagnostics.connector_health(self.state,command,root)
                self.assertEqual(command.call_count,2)
                self.assertTrue(all('start' not in c.args[0] and 'restart' not in c.args[0] for c in command.call_args_list))
                self.assertNotIn('PRIVATE',json.dumps(result));return result,paths
        finally:server.shutdown();server.server_close();thread.join(5)
    def test_real_ready_and_ha_four_with_cumulative_counter(self):
        value,paths=self.check(b'cloudflared_tunnel_ha_connections 4\ncloudflared_tunnel_total_requests 20\ncloudflared_tunnel_request_errors 6\nother_metric{token="PRIVATE"} 1\n')
        self.assertTrue(value['ready']);self.assertEqual(value['ha_connections'],4)
        self.assertEqual(value['redundancy'],'full');self.assertEqual(value['configured_protocol'],'http2')
        self.assertEqual(value['request_errors_total'],6);self.assertIn('cancellation',value['request_error_counter_scope'])
        self.assertEqual(paths,['/ready','/metrics'])
    def test_readiness_with_one_connection_is_reduced_not_disconnected(self):
        value,_=self.check(b'cloudflared_tunnel_ha_connections 1\n')
        self.assertTrue(value['ready']);self.assertEqual(value['redundancy'],'reduced')
    def test_environment_transport_is_reported_without_credentials(self):
        value,_=self.check(b'cloudflared_tunnel_ha_connections 4\n',protocol_arg='')
        self.assertEqual(value['configured_protocol'],'http2')
    def test_ready_without_any_ha_connection_cannot_pass(self):
        value,_=self.check(b'cloudflared_tunnel_ha_connections 0\n')
        self.assertFalse(value['ready']);self.assertEqual(value['redundancy'],'none')
    def test_missing_or_nonfinite_counter_is_unknown(self):
        for body in [b'unknown_metric 4\n',b'cloudflared_tunnel_ha_connections NaN\n',b'cloudflared_tunnel_ha_connections -1\n']:
            with self.subTest(body=body):
                value,_=self.check(body);self.assertIsNone(value['ha_connections']);self.assertEqual(value['redundancy'],'unknown')
    def test_metrics_redirect_or_oversize_never_claims_full_redundancy(self):
        for status,body in [(302,b'PRIVATE'),(200,b'x'*1048577)]:
            value,_=self.check(body,status);self.assertEqual(value['metrics_status'],'unavailable');self.assertEqual(value['redundancy'],'unknown')
    def test_label_values_are_not_returned_and_integral_scientific_notation_works(self):
        self.assertEqual(diagnostics._metric_total('counter{private="PRIVATE"} 1e2\ncounter{private="other"} 2\n','counter'),102)
        self.assertIsNone(diagnostics._metric_total('counter 1.5','counter'))

class ConnectorProcessTests(unittest.TestCase):
    def test_network_snapshot_tracks_connector_restarts_and_established_edge_sockets(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'net').mkdir()
            for pid,inode in [(10,100),(20,200),(21,200)]:
                (root/str(pid)/'fd').mkdir(parents=True);(root/str(pid)/'fd/5').symlink_to('socket:['+str(inode)+']')
            (root/'net/udp').write_text('header\n0: 00000000:20FB 00000000:0000 07 0:0 00:0 0 0 0 100 2 0 0\n')
            (root/'net/tcp').write_text('header\n0: 0100007F:9C40 0100007F:1EA4 01 0:0 00:0 0 0 0 200 2 0 0\n')
            (root/'sys/kernel/random').mkdir(parents=True);(root/'sys/kernel/random/boot_id').write_text('boot')
            state={'bindings':{'x':{'service':'sb.service'}},'protocols':{'cf':{'enabled':True}}}
            current=[20]
            def show(args,**kwargs):
                return Mock(stdout='MainPID='+str(current[0] if args[2]=='argo.service' else 10)+'\nActiveState=active\n')
            with patch.object(subprocess,'run',side_effect=show),patch.object(diagnostics,'connector_health',return_value={'required':True,'ready':True}):
                before=diagnostics.snapshot(state,root);current[0]=21;after=diagnostics.snapshot(state,root)
            self.assertEqual(before['services']['sb.service'],after['services']['sb.service'])
            self.assertIn('argo.service',before['services']);self.assertFalse(diagnostics.delta(before,after)['processes_preserved'])
            connection=next(v for v in before['sockets'] if v['service']=='argo.service')
            self.assertEqual(connection['remote_port'],7844);self.assertEqual(connection['state'],'connected')

if __name__=='__main__':unittest.main()
