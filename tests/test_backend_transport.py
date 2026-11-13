import contextlib
import copy
import json
import io
import os
import pathlib
import socketserver
import tempfile
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler
from unittest.mock import Mock,patch

import ad_rules
import backend_transport as transport
import fleet
import fleetctl
import lease
import servers
import udp_buffers

ROOT=pathlib.Path(__file__).resolve().parents[1]

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append((self.command,self.path,self.headers.get('User-Agent')))
        if self.path.endswith('/fail'):
            self.send_response(503);self.end_headers();return
        value={'console_routes':{},'snapshot':{'fixture':True}} if self.path.endswith('/api/file/fleet-ad-state') else {'status':'success','data':{'ok':True}}
        body=json.dumps(value).encode();self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def do_PATCH(self):
        size=int(self.headers.get('Content-Length','0'));data=json.loads(self.rfile.read(size))
        self.server.requests.append((self.command,self.path,data))
        body=b'{"status":"success","data":{"changed":true}}'
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass

class Server(socketserver.UnixStreamServer):
    def __init__(self,path):
        self.requests=[]
        super().__init__(str(path),Handler)

class RelayTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=pathlib.Path(self.tmp.name)/'backend.sock';self.server=Server(self.path)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        self.proc=Mock();self.proc.poll.return_value=None
        self.config={'coordinator':'us','subscription':{'backend_url':'https://example.invalid/private','backend_relay':{'port':3001}}}
        self.value={'identity':transport.identity(self.config),'process':self.proc,'socket':self.path,'prefix':'/private'}
        self.token=transport._active.set(self.value);self.addCleanup(transport._active.reset,self.token)

    def test_backend_api_uses_private_socket_and_preserves_method_and_user_agent(self):
        with patch.object(servers.urllib.request,'urlopen',side_effect=AssertionError('public route used')):
            self.assertEqual(servers.request(self.config,'/api/sub/x',{'field':1},'PATCH',user_agent='test-client'),{'changed':True})
            self.assertEqual(servers.request(self.config,'/api/subs',user_agent='test-client'),{'ok':True})
        self.assertEqual(self.server.requests,[('PATCH','/private/api/sub/x',{'field':1}),('GET','/private/api/subs','test-client')])

    def test_managed_ad_snapshot_is_read_from_same_relay(self):
        config=copy.deepcopy(self.config);config['subscription']['ad_rules_snapshot']='@sub-store'
        with patch('dns_policy.console_routes',return_value={}),patch.object(ad_rules,'validate',side_effect=lambda value:value), \
             patch.object(ad_rules,'get',side_effect=AssertionError('public route used')):
            self.assertEqual(ad_rules.load(config),{'fixture':True})
        self.assertEqual(self.server.requests[0][1],'/private/api/file/fleet-ad-state')

    def test_wrong_identity_and_dead_relay_never_fall_back(self):
        other=copy.deepcopy(self.config);other['coordinator']='jp'
        with self.assertRaises(ValueError):servers.request(other,'/api/subs')
        other=copy.deepcopy(self.config);other['subscription']['backend_relay']['port']=3002
        with self.assertRaises(ValueError):servers.request(other,'/api/subs')
        self.proc.poll.return_value=255
        with self.assertRaises(RuntimeError):servers.request(self.config,'/api/subs')
        self.assertFalse(self.server.requests)

    def test_disconnect_after_response_rejects_receipt(self):
        self.proc.poll.side_effect=[None,None,255]
        with self.assertRaises(RuntimeError):servers.request(self.config,'/api/subs')
        self.assertEqual(len(self.server.requests),1)

    def test_relay_retries_only_idempotent_transport_failures(self):
        class Broken:
            def request(self,*args,**kwargs):raise TimeoutError('fixture')
            def close(self):pass
        with patch.object(transport,'UnixHTTPConnection',side_effect=[Broken(),transport.UnixHTTPConnection(self.path)]) as make, \
             patch.object(transport.time,'sleep'):
            self.assertEqual(servers.request(self.config,'/api/subs'),{'ok':True})
            self.assertEqual(make.call_count,2)
        with patch.object(transport,'UnixHTTPConnection',return_value=Broken()) as make, \
             self.assertRaises(TimeoutError):servers.request(self.config,'/api/subs',{'field':1},'POST')
        self.assertEqual(make.call_count,1)

    def test_backend_http_error_does_not_expose_private_url(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:servers.request(self.config,'/fail')
        self.assertEqual(caught.exception.code,503)
        self.assertNotIn('private',str(caught.exception))
        caught.exception.close()

    def test_public_verification_retries_transient_read_but_not_http_error(self):
        with patch.object(servers.urllib.request,'urlopen',side_effect=[TimeoutError(),io.BytesIO(b'ok')]) as op, \
             patch.object(servers.time,'sleep'):
            self.assertEqual(servers.read_public('https://example.invalid','test'),'ok')
            self.assertEqual(op.call_count,2)
        error=urllib.error.HTTPError('https://example.invalid',403,'denied',None,None)
        with patch.object(servers.urllib.request,'urlopen',side_effect=error) as op, \
             self.assertRaises(urllib.error.HTTPError):servers.read_public('https://example.invalid','test')
        self.assertEqual(op.call_count,1);error.close()

    def test_ad_asset_verification_retries_only_transient_reads(self):
        snapshot={'mrs_sha256':ad_rules.sha(b'fixture')}
        with patch.object(ad_rules.urllib.request,'urlopen',side_effect=[TimeoutError(),io.BytesIO(b'fixture')]) as get, \
             patch.object(ad_rules.time,'sleep'):
            ad_rules.verify_asset(self.config,snapshot)
        self.assertEqual(get.call_count,2)
        error=urllib.error.HTTPError('https://example.invalid',404,'missing',None,None)
        with patch.object(ad_rules.urllib.request,'urlopen',side_effect=error) as get, \
             self.assertRaises(urllib.error.HTTPError):ad_rules.verify_asset(self.config,snapshot)
        self.assertEqual(get.call_count,1);error.close()

class RelayLifecycleTests(unittest.TestCase):
    def test_no_settings_creates_no_process(self):
        with patch.object(transport.subprocess,'Popen') as launch:
            with transport.connection({'subscription':{}}):pass
        launch.assert_not_called()

    def test_real_local_unix_socket_lifecycle(self):
        config={'coordinator':'us','subscription':{'backend_url':'https://example.invalid/private','backend_relay':{'port':3001}}}
        created={}
        class FakeSSH:
            def __init__(self,args,**kwargs):
                self.args=args;self.dead=False
                spec=args[args.index('-L')+1];path=pathlib.Path(spec.split(':127.0.0.1:',1)[0])
                created['directory']=path.parent;created['mode']=path.parent.stat().st_mode&0o777
                self.server=Server(path);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
                created['process']=self
            def poll(self):return 0 if self.dead else None
            def terminate(self):self.server.shutdown();self.server.server_close();self.dead=True
            def wait(self,timeout=None):return 0
        with patch.object(transport,'ssh_candidates',return_value=[['ssh','-S','/old-master','user@fixture']]), \
             patch.object(transport.subprocess,'Popen',side_effect=FakeSSH):
            with transport.connection(config):
                self.assertTrue(transport.active(config))
                self.assertEqual(transport.request(config,'/api/subs'),{'ok':True})
                self.assertEqual(created['mode'],0o700)
                self.assertIn('StreamLocalBindMask=0177',created['process'].args)
                self.assertIn('-C',created['process'].args)
                self.assertEqual(created['process'].args[2],'none')
            self.assertFalse(created['directory'].exists())
            self.assertTrue(created['process'].dead)
            self.assertFalse(transport.active(config))

    def test_invalid_relay_settings_are_rejected_by_inventory(self):
        original=json.loads((ROOT/'templates/servers.example.json').read_text())
        for setting in ({'port':0},{'port':True},{'port':3001,'host':'0.0.0.0'},'3001'):
            config=copy.deepcopy(original);config['subscription']['backend_relay']=setting
            with self.subTest(setting=setting),self.assertRaises(ValueError):fleet.validate(config)
        config=copy.deepcopy(original);config['subscription']['backend_relay']={'port':3001}
        config['coordinator']=config['servers'][0]['id']
        fleet.validate(config)
        config['servers'][0]['status']='pending'
        with self.assertRaises(ValueError):fleet.validate(config)

    def test_optional_jump_is_another_active_server(self):
        config=json.loads((ROOT/'templates/servers.example.json').read_text())
        config['coordinator']=config['servers'][0]['id']
        config['subscription']['backend_relay']={'port':3001,'jump_server':config['coordinator']}
        with self.assertRaises(ValueError):fleet.validate(config)
        config['subscription']['backend_relay']['jump_server']='missing'
        with self.assertRaises(ValueError):fleet.validate(config)

    def test_japan_udp443_is_managed_by_existing_udp_buffer_inspection(self):
        self.assertEqual(udp_buffers.expected_binary('argosbx-hy2-udp443'),pathlib.Path('/root/agsbx/xray'))

    def test_ssh_candidates_keep_direct_then_verified_jump(self):
        config={'coordinator':'us','subscription':{'backend_relay':{'port':3001,'jump_server':'jp'}}}
        def args(ident,_):
            return ['ssh','-S','/old-'+ident,'-o','StrictHostKeyChecking=yes',ident+'@fixture']
        with patch.object(lease,'ssh_args',side_effect=args):
            direct,jump=list(lease.ssh_candidates(config,'us'))
        self.assertEqual(direct[2],'/old-us')
        self.assertEqual(jump[2],'none')
        option=next(x for x in jump if x.startswith('ProxyCommand='))
        self.assertIn('StrictHostKeyChecking=yes',option)
        self.assertIn('%h:%p',option)
        self.assertIn('jp@fixture',option)

    def test_read_only_inspection_can_retry_transport_but_write_is_never_replayed(self):
        config={'coordinator':'us','subscription':{'backend_relay':{'port':3001,'jump_server':'jp'}}}
        failed=Mock(returncode=255,stderr='connection failed',stdout='')
        success=Mock(returncode=0,stderr='',stdout='{"ok":true}')
        with patch.object(lease,'ssh_candidates',return_value=iter([['ssh','direct'],['ssh','jump']])), \
             patch.object(fleetctl.subprocess,'run',side_effect=[failed,success]) as run:
            self.assertEqual(fleetctl.remote(config,'us','inspect'),{'ok':True})
            self.assertEqual(run.call_count,2)
        with patch.object(fleetctl,'ssh_args',return_value=['ssh','direct']), \
             patch.object(fleetctl.subprocess,'run',return_value=failed) as run:
            with self.assertRaises(RuntimeError):fleetctl.remote(config,'us','apply',{})
            self.assertEqual(run.call_count,1)

    def test_followup_selects_reachable_path_before_a_write(self):
        config={'coordinator':'us','subscription':{'backend_relay':{'port':3001,'jump_server':'jp'}}}
        with patch.object(lease,'ssh_candidates',return_value=iter([['ssh','direct'],['ssh','jump']])), \
             patch.object(lease.subprocess,'run',side_effect=[Mock(returncode=255),Mock(returncode=0)]) as run:
            self.assertEqual(lease.reachable_ssh_args(config,'us'),['ssh','jump'])
        self.assertEqual([call.args[0][-1] for call in run.call_args_list],['true','true'])

    def test_coordinator_retries_through_jump_after_connection_failure(self):
        config={'coordinator':'us','subscription':{'backend_relay':{'port':3001,'jump_server':'jp'}}}
        def args(ident,_):return ['ssh','-S','none',ident+'@fixture']
        first=Mock(stdin=io.BytesIO(),stdout=io.BytesIO(b''));first.poll.return_value=1
        second=Mock(stdin=io.BytesIO(),stdout=io.BytesIO(b'READY'));second.poll.return_value=None
        with patch.object(lease,'ssh_args',side_effect=args), \
             patch.object(lease.subprocess,'Popen',side_effect=[first,second]) as launch, \
             patch.object(lease.select,'select',side_effect=[([first.stdout],[],[]),([second.stdout],[],[])]):
            with lease.coordinator(config):lease.ensure_owned()
        self.assertEqual(launch.call_count,2)
        self.assertTrue(any('ProxyCommand=' in x for x in launch.call_args_list[1].args[0]))
        first.wait.assert_called();second.wait.assert_called()

    def test_backend_retries_ssh_jump_and_removes_its_private_socket(self):
        config={'coordinator':'us','subscription':{'backend_url':'https://example.invalid/private',
                'backend_relay':{'port':3001,'jump_server':'jp'}}}
        attempts=[]
        class DeadSSH:
            def poll(self):return 255
            def wait(self,timeout=None):return 255
        class GoodSSH:
            def __init__(self,args):
                spec=args[args.index('-L')+1];path=pathlib.Path(spec.split(':127.0.0.1:',1)[0])
                attempts.append(path.parent)
                self.server=Server(path);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
                self.dead=False
            def poll(self):return 0 if self.dead else None
            def terminate(self):self.server.shutdown();self.server.server_close();self.dead=True
            def wait(self,timeout=None):return 0
        def launch(args,**kwargs):
            if not attempts:attempts.append('direct-failed');return DeadSSH()
            return GoodSSH(args)
        with patch.object(transport,'ssh_candidates',return_value=[['ssh','-S','none','us'],['ssh','-S','none','-o','ProxyCommand=fixture','us']]), \
             patch.object(transport.subprocess,'Popen',side_effect=launch):
            with transport.connection(config):
                self.assertEqual(transport.request(config,'/api/subs'),{'ok':True})
        self.assertEqual(attempts[0],'direct-failed')
        self.assertFalse(attempts[1].exists())

if __name__=='__main__':unittest.main()
