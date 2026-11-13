import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import ad_delivery
import ad_setup
import country_routes


class AdSetupTests(unittest.TestCase):
    def test_compiler_download_checks_hash_and_resumes(self):
        archive = gzip.compress(b'fixture-compiler')
        build = ('fixture.gz', 1, len(archive), hashlib.sha256(archive).hexdigest())
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'tools/mihomo'
            with patch.object(ad_setup, 'DEFAULT_COMPILER', target), \
                    patch.object(ad_setup, 'BUILDS', {'x86_64': build}), \
                    patch.object(ad_setup.platform, 'machine', return_value='x86_64'), \
                    patch.object(ad_setup, 'check_compiler'), \
                    patch.object(ad_setup.urllib.request, 'urlopen',
                                 side_effect=[io.BytesIO(b'bad'), io.BytesIO(archive)]) as fetch:
                ad_setup.install_compiler(target)
                self.assertEqual(target.read_bytes(), b'fixture-compiler')
                self.assertEqual(fetch.call_count, 2)
                ad_setup.install_compiler(target)
                self.assertEqual(fetch.call_count, 2)

    def test_native_and_multiple_aggregate_configuration(self):
        base = {'backend_url': 'https://sub.example:8443/private', 'mihomo': '/usr/bin/mihomo'}
        self.assertEqual(ad_delivery.aggregates(ad_delivery.validate_config(base)), [{'prefix': ''}])
        legacy = {**base, 'external_ads_url': 'https://sub.example:8443/share/file/external-seven-shadowrocket-ads?token=fixture'}
        self.assertEqual([a['prefix'] for a in ad_delivery.aggregates(ad_delivery.validate_config(legacy))], ['', 'external-seven-'])
        multi = {**base, 'aggregates': [{'prefix': ''}, {'prefix': 'second-',
                 'ads_url': 'https://sub.example:8443/share/file/second-shadowrocket-ads?token=fixture'}]}
        self.assertEqual(ad_delivery.ads_url(ad_delivery.validate_config(multi), 'second-'), multi['aggregates'][1]['ads_url'])
        for url in ('https://evil.example/share/file/second-shadowrocket-ads?token=fixture',
                    'https://sub.example:8443/share/file/second-shadowrocket-ads',
                    'https://sub.example:8443/share/file/other-shadowrocket-ads?token=fixture'):
            invalid = {**multi, 'aggregates': [{'prefix': ''}, {'prefix': 'second-', 'ads_url': url}]}
            with self.subTest(url=url), self.assertRaises(ValueError):
                ad_delivery.validate_config(invalid)

    def test_scope_discovery_requires_every_managed_file_and_share(self):
        native = set(ad_delivery.FORMATS)
        seven = {'external-seven-' + f for f in ad_delivery.FORMATS}
        with patch('publication.temporary_names', return_value=native):
            self.assertEqual(ad_setup.discover({'backend_url': 'fixture'}, {}), [''])
        with patch('publication.temporary_names', return_value=native | seven):
            with self.assertRaises(ValueError):
                ad_setup.discover({'backend_url': 'fixture'}, {})
            self.assertEqual(ad_setup.discover({'external_ads_url': 'fixture'}, {}), ['', 'external-seven-'])
        with patch('publication.temporary_names', return_value=native | (seven - {'external-seven-stash'})):
            with self.assertRaises(ValueError):
                ad_setup.discover({'external_ads_url': 'fixture'}, {})

    def test_first_setup_discovers_unique_existing_share_identity(self):
        spec = {'backend_url': 'https://sub.example:8443/private', 'mihomo': '/usr/bin/mihomo'}
        with patch.object(ad_setup, 'available_prefixes', return_value={'', 'seven-'}), \
                patch.object(ad_setup, 'request', return_value=[{'token': 'fixture-token'}]):
            config = ad_setup.initial_settings(spec)
            self.assertEqual(config['aggregates'][1]['ads_url'],
                             'https://sub.example:8443/share/file/seven-shadowrocket-ads?token=fixture-token')
        with patch.object(ad_setup, 'available_prefixes', return_value={'', 'seven-'}), \
                patch.object(ad_setup, 'request', return_value=[{'token': 'one'}, {'token': 'two'}]), \
                self.assertRaises(ValueError):
            ad_setup.initial_settings(spec)

    def test_native_only_first_setup_and_repeat(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            main = root/'Caddyfile'
            main.write_text(country_routes.AD_ROUTES)
            spec = {'backend_url': 'https://sub.example:8443/private', 'mihomo': '/usr/bin/mihomo'}
            with patch.object(ad_setup, 'CONFIG', root/'config.json'), \
                    patch.object(ad_setup, 'LOCK', root/'lock'), \
                    patch.object(ad_setup, 'CADDY_MAIN', main), \
                    patch.object(ad_setup, 'CADDY_INCLUDE', root/'absent'), \
                    patch.object(country_routes, 'AD_JOURNAL', root/'route-journal'), \
                    patch.object(ad_delivery, 'JOURNAL', root/'publish-journal'), \
                    patch.object(ad_delivery, 'check_onboarding'), \
                    patch.object(ad_setup, 'available_prefixes', return_value={''}), \
                    patch.object(ad_setup, 'discover', return_value=['']), \
                    patch.object(ad_setup, 'install_compiler', return_value=Path('/usr/bin/mihomo')), \
                    patch.object(ad_setup, 'candidate_snapshot', return_value={'fixture': True}), \
                    patch.object(country_routes, 'store_ad_asset'), \
                    patch.object(ad_setup, 'wait_asset'), \
                    patch.object(ad_delivery, 'publish', return_value={'native': {}}) as publish, \
                    patch.object(country_routes, 'ad_finish'), \
                    patch.object(ad_setup, 'install_units', return_value={'unit_files_changed': 3}), \
                    patch.object(ad_setup, 'enable_timer') as timer, \
                    patch.object(ad_setup, 'get', return_value=None):
                result = ad_setup.setup(spec)
                self.assertTrue(result['initialized'])
                self.assertTrue(result['timer_enabled'])
                self.assertEqual(os.stat(root/'config.json').st_mode & 0o777, 0o600)
                self.assertEqual(json.loads((root/'config.json').read_text())['aggregates'], [{'prefix': ''}])
                publish.assert_called_once()
                timer.assert_called_once()
                with self.assertRaises(ValueError):
                    ad_setup.setup(spec)

    def test_native_route_is_scoped_and_idempotent(self):
        original = 'example.test {\n# BEGIN TI UNIFIED SUBSCRIPTION\nrespond 200\n# END TI UNIFIED SUBSCRIPTION\n}\n'
        result = country_routes.ad_render_main(original)
        self.assertEqual(result.count(country_routes.AD_ROUTES), 1)
        self.assertEqual(country_routes.ad_render_main(result), result)
        with self.assertRaises(ValueError):
            country_routes.ad_render_main('example.test {\nrespond 200\n}\n')

    def test_incomplete_setup_restores_only_its_own_route(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            route = root/'route-journal'
            route.write_text(json.dumps({'owner': 'ad-setup', 'asset_sha256': 'fixture'}))
            with patch.object(country_routes, 'AD_JOURNAL', route), \
                    patch.object(ad_delivery, 'JOURNAL', root/'publish-journal'), \
                    patch.object(ad_setup, 'get', return_value=None), \
                    patch.object(country_routes, 'ad_finish') as finish:
                ad_setup.recover_setup({}, {})
                finish.assert_called_once_with(restore=True)
            route.write_text(json.dumps({'owner': 'other'}))
            with patch.object(country_routes, 'AD_JOURNAL', route), \
                    patch.object(country_routes, 'ad_finish') as finish, self.assertRaises(ValueError):
                ad_setup.recover_setup({}, {})
            finish.assert_not_called()

    def test_route_rollback_does_not_break_a_committed_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            route = root/'route-journal'
            route.write_text('{}')
            with patch.object(country_routes, 'AD_JOURNAL', route), \
                    patch.object(ad_delivery, 'JOURNAL', root/'publish-journal'), \
                    patch.object(ad_setup, 'get', return_value={'content': 'committed'}) as get, \
                    patch.object(country_routes, 'ad_finish') as finish:
                ad_setup.rollback_unpublished_route({})
                finish.assert_not_called()
                get.return_value = None
                ad_setup.rollback_unpublished_route({})
                finish.assert_called_once_with(restore=True)

    def test_unit_upgrade_and_failed_effective_readback_roll_back(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            units = root/'units'
            previous = root/'v1.2.35/systemd'
            units.mkdir()
            previous.mkdir(parents=True)
            old = b'[Unit]\nDescription=previous release\n'
            (units/'argosbx-ad-refresh.service').write_bytes(old)
            (previous/'argosbx-ad-refresh.service').write_bytes(old)
            timer = (ad_setup.ROOT/'systemd/argosbx-ad-refresh.timer').read_bytes()
            (units/'argosbx-ad-refresh.timer').write_bytes(timer)

            def run(args, **kwargs):
                if args[:2] == ['systemctl', 'show']:
                    return Mock(returncode=1 if '@.service' in args[2] else 0, stdout='')
                return Mock(returncode=0, stdout='')

            with patch.object(ad_setup, 'UNIT_DIR', units), patch.object(ad_setup, 'INSTALL_ROOT', root), \
                    patch.object(ad_setup.subprocess, 'run', side_effect=run), \
                    patch.object(ad_setup.subprocess, 'check_output', return_value='ExecStart=unexpected\n'):
                with self.assertRaises(ValueError):
                    ad_setup.install_units()
            self.assertEqual((units/'argosbx-ad-refresh.service').read_bytes(), old)
            self.assertEqual((units/'argosbx-ad-refresh.timer').read_bytes(), timer)
            self.assertFalse((units/'argosbx-ad-alert@.service').exists())

            with patch.object(ad_setup, 'UNIT_DIR', units), patch.object(ad_setup, 'INSTALL_ROOT', root), \
                    patch.object(ad_setup.subprocess, 'run', side_effect=run), \
                    patch.object(ad_setup.subprocess, 'check_output',
                                 return_value='ExecStart=ad_monitor.py run\nOnFailure=argosbx-ad-alert@fixture.service\n'):
                self.assertEqual(ad_setup.install_units()['unit_files_changed'], 2)
            self.assertTrue((units/'argosbx-ad-alert@.service').exists())


if __name__ == '__main__':
    unittest.main()
