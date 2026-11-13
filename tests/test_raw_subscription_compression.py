import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import country_routes as routes

TOKEN='a'*36
ADMIN='''unrelated route
@substore_admin path /{token}/* /assets/* / /settings/*
 handle @substore_admin {{
  header Cache-Control "no-store"
  header Referrer-Policy "no-referrer"
  reverse_proxy 127.0.0.1:3001
 }}
other route
'''.format(token=TOKEN)

class RawCompressionTest(unittest.TestCase):
    def test_only_original_download_gets_negotiated_gzip(self):
        result=routes.raw_compression_render(ADMIN)
        definition='  @substore_raw_download path /'+TOKEN+'/download/collection/all\n'
        encoding='  encode @substore_raw_download gzip\n'
        self.assertEqual(result.replace(definition,'').replace(encoding,''),ADMIN)
        self.assertEqual(routes.raw_compression_render(result),result)
        self.assertIn('header Cache-Control "no-store"',result)
        self.assertEqual(result.count('reverse_proxy 127.0.0.1:3001'),1)

    def test_ambiguous_paths_other_encoding_or_scope_conflict_fail_closed(self):
        cases=[ADMIN.replace('/assets/*','/'+('b'*36)+'/* /assets/*'),
               ADMIN.replace('handle @substore_admin','handle @other'),
               ADMIN.replace('  header Cache-Control','  encode zstd\n  header Cache-Control'),
               ADMIN.replace('  header Cache-Control','  @substore_raw_download path /other\n  header Cache-Control'),
               ADMIN.replace('127.0.0.1:3001','127.0.0.1:9000')]
        for text in cases:
            with self.subTest(text=text),self.assertRaises(ValueError):routes.raw_compression_render(text)

    def test_stage_validates_full_caddy_config_and_preserves_recovery(self):
        with tempfile.TemporaryDirectory() as d,patch.object(subprocess,'run') as validate, \
             patch.object(subprocess,'check_output',return_value=b'42'),patch.object(routes.os,'kill') as signal:
            root=Path(d);path=root/'routes.caddy';main=root/'Caddyfile';journal=root/'journal'
            path.write_text(ADMIN);main.write_text('import '+str(path)+'\n');original=main.read_bytes()
            result=routes.stage_import(routes.raw_compression_render,path,main,journal)
            self.assertTrue(result['pending_readback']);self.assertFalse(result['existing_services_restarted'])
            self.assertEqual(main.read_bytes(),original);self.assertEqual(journal.stat().st_mode&0o777,0o600)
            self.assertEqual(validate.call_args.args[0][1],'validate');signal.assert_called_once()
            routes.compression_finish(True,journal);self.assertEqual(path.read_text(),ADMIN);self.assertFalse(journal.exists())

    def test_rollback_timer_precedes_any_write_and_is_stopped_for_noop(self):
        with tempfile.TemporaryDirectory() as d:
            journal=Path(d)/'journal';events=[]
            def run(args,**kwargs):events.append(args);return subprocess.CompletedProcess(args,0,'','')
            def stage(*args):
                self.assertEqual(events[0][0],'systemd-run');return {'changed':False,'existing_services_restarted':False}
            with patch.object(routes.subprocess,'run',side_effect=run),patch.object(routes,'stage_import',side_effect=stage):
                result=routes.raw_compression_upgrade(Path(d)/'routes',Path(d)/'main',journal)
            self.assertEqual(result['rollback_seconds'],0)
            self.assertTrue(any(x[:2]==['systemctl','stop'] for x in events))

    def test_error_after_journal_creation_keeps_automatic_recovery_scheduled(self):
        with tempfile.TemporaryDirectory() as d:
            journal=Path(d)/'journal';events=[]
            def run(args,**kwargs):events.append(args);return subprocess.CompletedProcess(args,0,'','')
            def stage(*args):journal.write_text('{}');raise ValueError('simulated interruption')
            with patch.object(routes.subprocess,'run',side_effect=run),patch.object(routes,'stage_import',side_effect=stage):
                with self.assertRaises(ValueError):routes.raw_compression_upgrade(Path(d)/'routes',Path(d)/'main',journal)
            self.assertTrue(journal.exists());self.assertFalse(any(x[:2]==['systemctl','stop'] for x in events))

    def test_existing_other_transaction_blocks_before_timer_or_writes(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);other=root/'ad-route-journal.json';other.write_text('{}')
            with patch.object(routes.subprocess,'run',side_effect=AssertionError('must not touch system')):
                with self.assertRaises(ValueError):
                    routes.raw_compression_upgrade(root/'routes',root/'main',root/'raw-journal.json')
            self.assertTrue(other.exists())

if __name__=='__main__':unittest.main()
