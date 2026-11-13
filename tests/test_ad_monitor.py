import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import urllib.error

import ad_delivery
import ad_monitor
import ad_rules


class Response:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        return b'upstream rules'


class AdMonitorTests(unittest.TestCase):
    def test_retry_only_transient_fetch_failures_without_logging_url(self):
        url = 'https://example.test/private-token'
        unavailable = urllib.error.HTTPError(url, 503, 'unavailable', {}, None)
        with patch.object(ad_rules.urllib.request, 'urlopen', side_effect=[unavailable, Response()]) as fetch, \
                patch.object(ad_rules.time, 'sleep') as sleep, contextlib.redirect_stderr(io.StringIO()) as log:
            self.assertEqual(ad_rules.get(url, 'text/plain'), b'upstream rules')
            self.assertEqual(fetch.call_count, 2)
            sleep.assert_called_once_with(1)
            self.assertNotIn('private-token', log.getvalue())
        forbidden = urllib.error.HTTPError(url, 403, 'forbidden', {}, None)
        with patch.object(ad_rules.urllib.request, 'urlopen', side_effect=forbidden) as fetch, \
                patch.object(ad_rules.time, 'sleep') as sleep, self.assertRaises(urllib.error.HTTPError):
            ad_rules.get(url, 'text/plain')
        self.assertEqual(fetch.call_count, 1)
        sleep.assert_not_called()

    def test_new_upstream_console_block_stops_release_without_broad_exception(self):
        marker = ad_rules.AD_RULE
        rules = [marker, 'MATCH,日常线路']
        with self.assertRaisesRegex(ValueError, 'ads.google.com'):
            ad_rules.check_console_samples(rules, marker, 'ads.google.com\n')
        ad_rules.check_console_samples(['DOMAIN,ads.google.com,日常线路', *rules], marker, 'ads.google.com\n')
        with self.assertRaisesRegex(ValueError, 'ads.google.com'):
            ad_rules.check_console_samples(['DOMAIN-SUFFIX,google.com,REJECT', *rules], marker, '')

    def test_failed_stage_retains_last_success_without_secret_error_text(self):
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory)/'status.json'
            status.write_text(json.dumps({'last_success': 'old-success'}))
            err = io.StringIO()
            with patch.object(ad_delivery, 'check_onboarding'), \
                    patch.object(ad_delivery, 'read_config', return_value={}), \
                    patch.object(ad_delivery, 'refresh', side_effect=RuntimeError('secret-url')), \
                    contextlib.redirect_stderr(err), self.assertRaises(RuntimeError):
                ad_monitor.run(status_path=status, lock_path=Path(directory)/'lock')
            saved = json.loads(status.read_text())
            self.assertEqual(saved['last_success'], 'old-success')
            self.assertEqual(saved['phase'], 'ad-rules')
            self.assertEqual(saved['result'], 'failed')
            self.assertNotIn('secret-url', status.read_text() + err.getvalue())

    def test_success_records_both_checks_and_verify_keeps_status(self):
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory)/'status.json'
            with patch.object(ad_delivery, 'check_onboarding'), \
                    patch.object(ad_delivery, 'read_config', return_value={}), \
                    patch.object(ad_delivery, 'refresh', return_value={'domains': 911, 'changed': False}), \
                    patch('standard_rule_source.refresh_if_configured', return_value={'configured': True}), \
                    contextlib.redirect_stdout(io.StringIO()):
                result = ad_monitor.run(status_path=status, lock_path=Path(directory)/'lock')
                self.assertEqual(result['result'], 'success')
                self.assertTrue(result['standard_configured'])
                before = status.read_bytes()
                ad_monitor.run(verify_only=True, status_path=status, lock_path=Path(directory)/'lock')
                self.assertEqual(status.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
