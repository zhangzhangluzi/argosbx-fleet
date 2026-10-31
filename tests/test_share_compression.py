"""Scope-preserving Caddy compression plans and explicit readback recovery."""
import json,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import country_routes as routes

SHARE='''unrelated PRIVATE\n# BEGIN EXTERNAL SEVEN SHARES
@external_seven_share path /share/col/external-seven /share/file/external-seven-shadowrocket-config /share/file/external-seven-shadowrocket-ads
handle @external_seven_share {
 header Cache-Control "private, no-store"
 header Vary "User-Agent"
 reverse_proxy 127.0.0.1:3001
}
# END EXTERNAL SEVEN SHARES
suffix PRIVATE
'''

class CompressionTests(unittest.TestCase):
    def test_only_owned_three_share_paths_gain_one_encoding_handler(self):
        result=routes.compression_render(SHARE)
        self.assertEqual(result.replace(' encode gzip\n',''),SHARE)
        self.assertEqual(routes.compression_render(result),result)
    def test_existing_optional_ingress_share_keeps_its_path_and_auth_scope(self):
        text=SHARE.replace('/share/file/external-seven-shadowrocket-ads\n','/share/file/external-seven-shadowrocket-ads /share/file/external-seven-de-mia-ingress\n')
        result=routes.compression_render(text)
        self.assertEqual(result.replace(' encode gzip\n',''),text)
        self.assertEqual(routes.compression_render(result),result)
    def test_duplicate_missing_or_unknown_optional_paths_are_rejected(self):
        for suffix in ['/share/col/external-seven','/api/private','/share/file/external-seven-unknown']:
            text=SHARE.replace('/share/file/external-seven-shadowrocket-ads\n','/share/file/external-seven-shadowrocket-ads '+suffix+'\n')
            with self.subTest(suffix=suffix),self.assertRaises(ValueError):routes.compression_render(text)
        with self.assertRaises(ValueError):routes.compression_render(SHARE.replace(' /share/col/external-seven',''))
    def test_unknown_scope_backend_or_existing_encoding_fails_closed(self):
        for value in [SHARE.replace('/share/col/external-seven','/api/private'),SHARE.replace('127.0.0.1:3001','127.0.0.1:9000'),SHARE.replace('handle @external_seven_share {','handle @external_seven_share {\n encode zstd'),SHARE+SHARE]:
            with self.subTest(value=value),self.assertRaises(ValueError):routes.compression_render(value)
    def prepare(self,root):
        main=root/'Caddyfile';path=root/'shares.caddy';journal=root/'journal.json'
        path.write_text(SHARE);main.write_text('import '+str(path)+'\n')
        return path,main,journal
    def test_validate_then_reload_keeps_pid_and_recovery_restores_bytes(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(subprocess,'run') as validate,patch.object(subprocess,'check_output',return_value=b'42'),patch.object(routes.os,'kill') as signal:
            path,main,journal=self.prepare(Path(directory));original=main.read_bytes()
            result=routes.compression_upgrade(path,main,journal)
            self.assertTrue(result['pending_readback']);self.assertFalse(result['existing_services_restarted'])
            self.assertEqual(main.read_bytes(),original);self.assertEqual(journal.stat().st_mode&0o777,0o600)
            self.assertEqual(validate.call_args.args[0][1],'validate');signal.assert_called_once()
            routes.compression_finish(True,journal);self.assertEqual(path.read_text(),SHARE);self.assertFalse(journal.exists())
    def test_validation_failure_never_writes_or_reloads(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(subprocess,'run',side_effect=subprocess.CalledProcessError(1,['caddy'])),patch.object(routes.os,'kill') as signal:
            path,main,journal=self.prepare(Path(directory))
            with self.assertRaises(subprocess.CalledProcessError):routes.compression_upgrade(path,main,journal)
            self.assertEqual(path.read_text(),SHARE);self.assertFalse(journal.exists());signal.assert_not_called()
    def test_concurrent_config_or_pid_changes_retain_recovery_and_do_not_overwrite(self):
        for kind in ['path','main','pid']:
            with tempfile.TemporaryDirectory() as directory,patch.object(subprocess,'run'),patch.object(subprocess,'check_output',return_value=b'42') as pid,patch.object(routes.os,'kill') as signal:
                path,main,journal=self.prepare(Path(directory));routes.compression_upgrade(path,main,journal);signal.reset_mock()
                if kind=='path':path.write_text('third party')
                elif kind=='main':main.write_text('third party')
                else:pid.return_value=b'43'
                with self.subTest(kind=kind),self.assertRaises(ValueError):routes.compression_finish(True,journal)
                self.assertTrue(journal.exists());signal.assert_not_called()

if __name__=='__main__':unittest.main()
