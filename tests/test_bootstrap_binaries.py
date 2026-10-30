import hashlib,io,json,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import bootstrap

class BinaryPinTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.native=self.root/'native'
        self.archive=self.zip(b'old core');self.url='https://example.invalid/v1.zip'
        self.patchers=[patch.object(bootstrap,'ROOT',self.root),patch.object(bootstrap,'NATIVE',self.native),patch.object(bootstrap.platform,'machine',return_value='x86_64')]
        for p in self.patchers:p.start();self.addCleanup(p.stop)
        downloader=patch.object(bootstrap.urllib.request,'urlretrieve',side_effect=self.fetch)
        self.download=downloader.start();self.addCleanup(downloader.stop)
        self.pin()
    @staticmethod
    def zip(data):
        result=io.BytesIO()
        with zipfile.ZipFile(result,'w') as archive:archive.writestr('xray',data)
        return result.getvalue()
    def fetch(self,url,destination):
        self.assertEqual(url,self.url);Path(destination).write_bytes(self.archive)
    def pin(self):
        item={'url':self.url,'sha256':hashlib.sha256(self.archive).hexdigest()}
        (self.root/'binaries.json').write_text(json.dumps({'xray':{'amd64':item,'arm64':item}}))
    def test_identical_verified_pin_resumes_without_download(self):
        bootstrap.binaries();bootstrap.binaries()
        self.assertEqual(self.download.call_count,1)
        self.assertEqual((self.native/'xray').read_bytes(),b'old core')
    def test_changed_manifest_never_reuses_self_consistent_old_core(self):
        bootstrap.binaries()
        self.url='https://example.invalid/v2.zip';self.archive=self.zip(b'new core');self.pin()
        bootstrap.binaries()
        self.assertEqual(self.download.call_count,2)
        self.assertEqual((self.native/'xray').read_bytes(),b'new core')
    def test_source_url_and_architecture_are_bound_even_for_same_bytes(self):
        bootstrap.binaries();self.url='https://example.invalid/other.zip';self.pin();bootstrap.binaries()
        with patch.object(bootstrap.platform,'machine',return_value='aarch64'):bootstrap.binaries()
        self.assertEqual(self.download.call_count,3)
    def test_tampered_binary_is_not_accepted_by_valid_marker(self):
        bootstrap.binaries();(self.native/'xray').write_bytes(b'tampered');bootstrap.binaries()
        self.assertEqual(self.download.call_count,2)
        self.assertEqual((self.native/'xray').read_bytes(),b'old core')
    def test_legacy_or_corrupt_marker_cannot_assert_manifest_provenance(self):
        bootstrap.binaries()
        for marker in (hashlib.sha256(b'old core').hexdigest(),'malformed'):
            with self.subTest(marker=marker):
                (self.native/'xray.sha256').write_text(marker);bootstrap.binaries()
        self.assertEqual(self.download.call_count,3)
    def test_bad_download_keeps_existing_core_and_marker(self):
        bootstrap.binaries();before=(self.native/'xray.sha256').read_bytes()
        self.url='https://example.invalid/v2.zip';self.pin();self.archive=b'corrupt archive'
        with self.assertRaises(ValueError):bootstrap.binaries()
        self.assertEqual((self.native/'xray').read_bytes(),b'old core')
        self.assertEqual((self.native/'xray.sha256').read_bytes(),before)
