import contextlib,errno,hashlib,io,json,os,runpy,sys,tempfile,unittest,urllib.error
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import bootstrap,host_preflight,install,onboard,release

class BootstrapSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.server=onboard.defaults('test','JP','日本','192.0.2.1',None,'example.com','/fixture/key','/fixture/known')
        self.paths={k:self.root/k for k in ('journal','native','state','caddy','current')}

    def check(self):return host_preflight.check(self.server,'v1.2.35',**self.paths)

    def system(self):
        return (patch.object(host_preflight.os,'geteuid',return_value=0),
                patch.object(host_preflight.platform,'system',return_value='Linux'),
                patch.object(host_preflight.shutil,'which',return_value='/bin/systemctl'))

    def test_ipv4_only_defaults_and_loopback_xhttp(self):
        self.assertEqual(self.server['protocols']['hy2']['listen'],'0.0.0.0')
        self.assertEqual(self.server['protocols']['xhttp']['listen'],'127.0.0.1')
        self.assertNotIn(('tcp',18083),host_preflight.ports(self.server))
        with self.system()[0],self.system()[1],self.system()[2],patch.object(host_preflight,'bind') as bind:
            self.assertTrue(self.check()['blank_or_resumable'])
        self.assertTrue(all(call.args[3]==host_preflight.socket.AF_INET for call in bind.call_args_list))
        dual=onboard.defaults('test','JP','日本','192.0.2.1','2001:db8::1','example.com','/fixture/key','/fixture/known')
        self.assertEqual(dual['protocols']['hy2']['listen'],'::')

    def test_existing_host_and_mismatched_journal_stop_before_bind(self):
        self.paths['caddy'].write_text('existing')
        with self.system()[0],self.system()[1],self.system()[2],patch.object(host_preflight,'bind') as bind:
            with self.assertRaises(ValueError):self.check()
            bind.assert_not_called()
        self.paths['caddy'].unlink()
        self.paths['journal'].write_text(json.dumps({'server':{'id':'different'},'phase':2}))
        with self.system()[0],self.system()[1],self.system()[2],patch.object(host_preflight,'bind') as bind:
            with self.assertRaises(ValueError):self.check()
            bind.assert_not_called()

    def test_existing_newer_maintenance_version_cannot_be_downgraded(self):
        target=self.root/'v9.0.0';target.mkdir();self.paths['current'].symlink_to(target)
        with self.system()[0],self.system()[1],self.system()[2],patch.object(host_preflight,'bind') as bind:
            with self.assertRaises(ValueError):self.check()
            bind.assert_not_called()

    def test_offline_retry_is_bounded_and_partial_file_removed(self):
        output=self.root/'download';calls=[]
        def open_url(url,timeout):
            calls.append(timeout)
            if len(calls)<3:raise urllib.error.URLError('temporary')
            return io.BytesIO(b'validated by caller')
        with patch.object(bootstrap.urllib.request,'urlopen',side_effect=open_url),patch.object(bootstrap.time,'sleep') as sleep:
            bootstrap.download('https://example.invalid/file',output)
        self.assertEqual(calls,[30,30,30]);self.assertEqual(sleep.call_count,2)
        self.assertEqual(output.read_bytes(),b'validated by caller')

    def test_nonretryable_http_failure_stops_immediately(self):
        output=self.root/'download'
        error=urllib.error.HTTPError('https://example.invalid',404,'missing',{},None)
        with patch.object(bootstrap.urllib.request,'urlopen',side_effect=error) as urlopen,patch.object(bootstrap.time,'sleep') as sleep:
            with self.assertRaises(urllib.error.HTTPError):bootstrap.download('https://example.invalid',output)
        self.assertEqual(urlopen.call_count,1);sleep.assert_not_called();self.assertFalse(output.exists())

    def test_release_is_byte_reproducible(self):
        first=Path(release.package(self.root/'first')).read_bytes()
        second=Path(release.package(self.root/'second')).read_bytes()
        self.assertEqual(first,second);self.assertEqual(first[4:8],b'\0'*4)

    def test_missing_interval_defaults_to_thirty_minutes_in_all_clients(self):
        root=Path(__file__).resolve().parents[1]
        inventory=json.loads((root/'templates/servers.example.json').read_text());inventory.pop('health',None)
        captured={}
        with patch('storage.save',side_effect=lambda path,value:captured.update(value=value)),contextlib.redirect_stdout(io.StringIO()):
            runpy.run_path(str(root/'generate.py'),init_globals={'inventory_override':inventory})
        files={v['name']:v for v in captured['value']['files']}
        for client in ('clash','stash'):
            self.assertIn('"interval": 1800',files[client]['process'][0]['args']['content'])
        self.assertIn('interval=1800',files['shadowrocket-config']['content'])

    def test_interrupted_install_keeps_current_and_retry_succeeds(self):
        archive=Path(release.package(self.root/'packages'));digest=hashlib.sha256(archive.read_bytes()).hexdigest()
        version=json.loads((Path(__file__).resolve().parents[1]/'versions.json').read_text())['version']
        dest=self.root/'installed';dest.mkdir();(dest/'v1.0.0').mkdir();(dest/'current').symlink_to('v1.0.0')
        with patch.object(install.os,'rename',side_effect=OSError(errno.ENOSPC,'simulated interrupted rename')):
            with self.assertRaises(OSError):install.install(archive,digest,dest)
        self.assertEqual(os.readlink(dest/'current'),'v1.0.0');self.assertFalse((dest/version).exists())
        self.assertEqual(install.install(archive,digest,dest)['installed'],version)
        self.assertEqual(os.readlink(dest/'current'),version)
