import copy,contextlib,io,json,socket,sys,tempfile,threading,unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import probe
from protocols import XHTTP_REUSE,validate_settings,render,export
from inbounds import create
from test_core import fixtures
from test_optimization import SETTINGS

class ReuseTests(unittest.TestCase):
    def test_client_only_apply_never_requires_cloudflare_token(self):
        import fleetctl
        old={'xhttp':copy.deepcopy(SETTINGS)};new=copy.deepcopy(old);new['xhttp']['client']['reuse-settings']=dict(XHTTP_REUSE)
        server={'id':'test','protocols':new,'certificates':{}}
        planned={'protocols':new,'certificates':{},'previous_protocols':old,'restart_required':[]}
        with tempfile.TemporaryDirectory() as d,patch.object(fleetctl,'STATE',Path(d)),patch.object(fleetctl,'read',return_value={}),patch.object(fleetctl,'servers',return_value={'test':server}),patch.object(fleetctl,'remote',side_effect=[planned,{'restarted':[]}]),patch.object(fleetctl,'Cloudflare',side_effect=AssertionError('unexpected CF call')),patch.object(sys,'argv',['fleetctl','protocol-apply','--server','test']),contextlib.redirect_stdout(io.StringIO()) as output:
            fleetctl.main()
        self.assertFalse(json.loads(output.getvalue())['cf_synchronized'])
    def fixture(self):
        c,_,s=fixtures()
        with patch('inbounds.vless_encryption',return_value=('fixture-private','fixture-public')):
            native,_,node=create('xhttp',SETTINGS,{})
        path='/test/x.json';c[path]['inbounds'].append(native)
        s['bindings']['xhttp']={'path':path,'tag':native['tag'],'core':'xray','service':'test.service','inbound':copy.deepcopy(native)}
        s['templates']['xhttp']=node;s['protocols']['xhttp']=copy.deepcopy(SETTINGS)
        return c,s,node
    def test_client_only_change_preserves_native_configs_and_identity(self):
        c,s,node=self.fixture();s['templates']['xhttp']['xhttp-opts']['reuse-settings']={'max-concurrency':'8-16'}
        desired=copy.deepcopy(s['protocols']);desired['xhttp']['client']['reuse-settings']=dict(XHTTP_REUSE)
        self.assertEqual(render(c,s,desired),c)
        before=copy.deepcopy(node);s['protocols']=desired
        actual=export(c,s)['proxies'][-1]
        self.assertEqual(actual['uuid'],before['uuid']);self.assertEqual(actual['encryption'],before['encryption'])
        self.assertEqual(actual['xhttp-opts']['reuse-settings'],XHTTP_REUSE)
        self.assertNotIn('reuse-settings',actual)
        self.assertEqual(s['templates']['xhttp']['xhttp-opts']['reuse-settings'],{'max-concurrency':'8-16'})
    def test_probe_uses_exported_parameters_instead_of_hardcoded_defaults(self):
        _,_,node=self.fixture();node['xhttp-opts']['reuse-settings']={**XHTTP_REUSE,'max-concurrency':'4-8','h-max-reusable-secs':'60-90'}
        xmux=probe.xhttp_client(node,23456)['outbounds'][0]['streamSettings']['xhttpSettings']['extra']['xmux']
        self.assertEqual(xmux,{'maxConcurrency':'4-8','maxConnections':'0','cMaxReuseTimes':'0','hMaxRequestTimes':'0','hMaxReusableSecs':'60-90','hKeepAlivePeriod':0})
    def test_unknown_cross_protocol_or_conflicting_settings_rejected(self):
        invalid=[{}, {'max-concurrency':'8-4'}, {'max-concurrency':'1-129'},
                 {'max-concurrency':True},{'h-max-reusable-secs':'0-100'},
                 {'h-max-reusable-secs':'86401'}, {'max-concurrency':'1','max-connections':'1'},
                 {'h-keep-alive-period':True},{'unknown':'1'}, {'max-concurrency':'01'}]
        for reuse in invalid:
            with self.subTest(reuse=reuse),self.assertRaises(ValueError):
                validate_settings({'xhttp':{**SETTINGS,'client':{'reuse-settings':reuse}}})
        validate_settings({'xhttp':{**SETTINGS,'client':{'reuse-settings':XHTTP_REUSE}}})
        with self.assertRaises(ValueError):validate_settings({'reality':{'client':{'reuse-settings':XHTTP_REUSE}}})

class AttemptTests(unittest.TestCase):
    case={'name':'fixture','expected_ips':['192.0.2.1']}
    def test_first_failure_retained_after_retry(self):
        with patch.object(probe,'https',side_effect=[TimeoutError('PRIVATE URL'), '192.0.2.1']) as request:
            r=probe.run_attempts(1,self.case,request,lambda p:True)
        self.assertEqual(r['status'],'passed_after_retry');self.assertFalse(r['first_attempt_ok'])
        self.assertTrue(r['retry_recovered']);self.assertEqual(r['attempt_count'],2)
        self.assertEqual(r['attempts'][0]['errors']['https']['type'],'TimeoutError')
        self.assertNotIn('PRIVATE',json.dumps(r));self.assertIn('https_ms',r['attempts'][0])
    def test_successes_from_different_attempts_never_combined(self):
        https=iter(['192.0.2.1', '192.0.2.9']);udp=iter([False,True])
        r=probe.run_attempts(1,self.case,lambda p:next(https),lambda p:next(udp))
        self.assertFalse(r['passed']);self.assertFalse(r['exit_ok']);self.assertTrue(r['udp_ok'])
        self.assertEqual(r['attempts'][1]['errors']['exit']['type'],'UnexpectedExit')
    def test_udp_failure_does_not_hide_https_success(self):
        def udp(p):raise OSError(101,'PRIVATE CREDENTIAL')
        r=probe.run_attempts(1,self.case,lambda p:'192.0.2.1',udp)
        self.assertFalse(r['passed']);self.assertTrue(r['https_ok'])
        self.assertEqual(r['attempts'][0]['errors']['udp'],{'type':'OSError','errno':101})
        self.assertNotIn('PRIVATE',json.dumps(r))
    def test_first_success_not_retried(self):
        r=probe.run_attempts(1,self.case,lambda p:'192.0.2.1',lambda p:True)
        self.assertTrue(r['first_attempt_ok']);self.assertEqual(len(r['attempts']),1)
    def test_startup_failure_is_classified_and_redacted(self):
        with patch.object(probe,'client_session',side_effect=OSError('PRIVATE CONFIG')):
            r=probe.check_case(self.case)
        self.assertEqual(r['status'],'setup_failed');self.assertFalse(r['passed']);self.assertNotIn('PRIVATE',json.dumps(r))
    def test_summary_distinguishes_retries_from_first_pass(self):
        first=probe.run_attempts(1,self.case,lambda p:'192.0.2.1',lambda p:True)
        recovered={**first,'first_attempt_ok':False,'retry_recovered':True}
        with patch.object(probe,'check_case',side_effect=[first,recovered]):r=probe.verify([self.case,self.case])
        self.assertTrue(r['passed']);self.assertFalse(r['first_attempt_passed'])
        self.assertEqual(r['first_attempt_successes'],1);self.assertEqual(r['retry_recovered'],1)

class PortTests(unittest.TestCase):
    def test_tcp_and_udp_are_reserved_until_launch(self):
        with probe.reserved_port() as (port,release):
            for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
                with socket.socket(socket.AF_INET,kind) as sock,self.assertRaises(OSError):sock.bind(('127.0.0.1',port))
            release()
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:sock.bind(('127.0.0.1',port))
            self.assertIn(port,probe._PORTS)
        self.assertNotIn(port,probe._PORTS)
    def test_parallel_reservations_have_unique_ports_and_cleanup(self):
        barrier=threading.Barrier(6)
        def worker(_):
            with probe.reserved_port() as (port,release):barrier.wait(timeout=5);return port
        with ThreadPoolExecutor(max_workers=6) as pool:ports=list(pool.map(worker,range(6)))
        self.assertEqual(len(set(ports)),6);self.assertFalse(probe._PORTS)
    def test_udp_conflict_retries_and_closes_both_sockets(self):
        from unittest.mock import MagicMock
        def sock(port,blocked=False):
            s=MagicMock();s.getsockname.return_value=('127.0.0.1',port)
            if blocked:s.bind.side_effect=OSError(48,'in use')
            return s
        first,blocked,second,udp=sock(21000),sock(21000,True),sock(21001),sock(21001)
        with patch.object(probe.socket,'socket',side_effect=[first,blocked,second,udp]):
            with probe.reserved_port() as (port,release):self.assertEqual(port,21001)
        for s in (first,blocked,second,udp):s.close.assert_called()
