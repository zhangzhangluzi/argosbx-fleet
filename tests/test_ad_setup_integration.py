"""Exercise native-only first publication through real template processors."""
import base64
import contextlib
import copy
import io
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import ad_delivery
import ad_monitor
import ad_rules
import ad_setup
import country_routes

ROOT = Path(__file__).resolve().parents[1]


class AdSetupIntegrationTest(unittest.TestCase):
    def test_native_only_publish_and_repeated_verification(self):
        config = json.loads((ROOT/'templates/servers.example.json').read_text())
        captured = {}
        with patch('storage.save', side_effect=lambda path, value: captured.update(payload=value)), \
                contextlib.redirect_stdout(io.StringIO()):
            runpy.run_path(str(ROOT/'generate.py'), init_globals={'inventory_override': config})
        files = {item['name']: copy.deepcopy(item) for item in captured['payload']['files']}
        nodes = [{'name': 'JP-U-v4-Hysteria2', 'type': 'hysteria2', 'server': '192.0.2.1',
                  'port': 443, 'password': 'fixture-password', 'sni': 'tls.example.com'}]
        domains = ('.applovin.com\n.doubleclick.net\n.google-analytics.com\n'
                   'pixel.facebook.com\nanalytics.tiktok.com\napi.appsflyersdk.com\n' + '\n'.join(ad_rules.EXTRA_ADS) + '\n')
        mrs = ad_rules.MRS_MAGIC + b'fixture'
        snapshot = ad_rules.validate({'revision': '1'*40, 'domains': domains,
                   'domain_count': len(domains.splitlines()), 'domains_sha256': ad_rules.sha(domains.encode()),
                   'mrs_sha256': ad_rules.sha(mrs), 'mrs': base64.b64encode(mrs).decode()})

        def render(item, user_agent):
            if item.get('source') == 'local' and 'content' in item:
                return item['content']
            script = item['process'][0]['args']['content']
            javascript = '''
const spec=JSON.parse(require('fs').readFileSync(0,'utf8'));
const ProxyUtils={yaml:{safeLoad:JSON.parse,safeDump:JSON.stringify},
 parse:body=>JSON.parse(body).proxies,
 produce:nodes=>nodes.map(n=>{n=structuredClone(n);if(n.type==='hysteria2'){n.auth=n.password;delete n.password;}return n;})};
const operator=new Function('ProxyUtils',spec.script+';return operator;')(ProxyUtils);
const out=operator({$content:JSON.stringify({proxies:spec.nodes}),$options:{_req:{headers:{'user-agent':spec.ua}},_res:{headers:{}}}});
process.stdout.write(out.$content);
'''
            return subprocess.check_output(['node', '-e', javascript], text=True,
                                           input=json.dumps({'script': script, 'nodes': nodes, 'ua': user_agent}))

        def api(_config, path, value=None, method=None, raw=False, user_agent='FlClash/0.8.99'):
            name = path.rsplit('/', 1)[-1]
            if path == '/api/files' and method is None:
                return list(files.values())
            if method == 'POST':
                files[value['name']] = copy.deepcopy(value)
                return value
            if method == 'PATCH':
                files[name] = copy.deepcopy(value)
                return value
            if method == 'DELETE':
                del files[name]
                return {}
            if raw:
                return render(files[name], user_agent)
            raise AssertionError(path)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            main = root/'Caddyfile'
            main.write_text(country_routes.AD_ROUTES)
            config_path = root/'ad-publisher.json'
            spec = {'backend_url': config['subscription']['backend_url'], 'mihomo': '/usr/bin/mihomo'}
            patches = [patch.object(ad_setup, 'CONFIG', config_path), patch.object(ad_delivery, 'CONFIG', config_path),
                patch.object(ad_setup, 'LOCK', root/'setup.lock'),
                patch.object(ad_setup, 'CADDY_MAIN', main), patch.object(ad_setup, 'CADDY_INCLUDE', root/'missing'),
                patch.object(country_routes, 'AD_JOURNAL', root/'route-journal'),
                patch.object(ad_delivery, 'JOURNAL', root/'publish-journal'),
                patch.object(ad_delivery, 'AD_JOURNAL', root/'route-journal'),
                patch.object(ad_delivery, 'check_onboarding'),
                patch.object(ad_setup, 'request', side_effect=api), patch.object(ad_delivery, 'request', side_effect=api),
                patch.object(ad_setup, 'get', side_effect=lambda _, kind, name: copy.deepcopy(files.get(name))),
                patch.object(ad_delivery, 'get', side_effect=lambda _, kind, name: copy.deepcopy(files.get(name))),
                patch.object(ad_setup, 'install_compiler', return_value=Path('/usr/bin/mihomo')),
                patch.object(ad_setup, 'candidate_snapshot', return_value=snapshot),
                patch.object(country_routes, 'store_ad_asset'), patch.object(ad_delivery, 'store_ad_asset'),
                patch.object(ad_delivery, 'check_asset'), patch.object(country_routes, 'ad_finish'),
                patch.object(ad_setup, 'install_units', return_value={'unit_files_changed': 3}),
                patch.object(ad_setup, 'enable_timer'),
                patch('standard_rule_source.refresh_if_configured', return_value={'configured': False})]
            with contextlib.ExitStack() as stack:
                for item in patches:
                    stack.enter_context(item)
                first = ad_setup.setup(spec)
                self.assertTrue(first['initialized'])
                self.assertEqual(first['scopes'], [''])
                self.assertIn(ad_rules.STATE_FILE, files)
                self.assertFalse(any(name.startswith('server-check-') for name in files))
                self.assertEqual(json.loads(files[ad_rules.STATE_FILE]['content'])['snapshot'], snapshot)
                second = ad_setup.setup()
                self.assertFalse(second['initialized'])
                result = ad_monitor.run(verify_only=True, status_path=root/'status', lock_path=root/'verify.lock')
                self.assertTrue(result['verified'])
                self.assertEqual(result['ad']['profiles']['native']['Stash/3.6.0'], 1)
                before = copy.deepcopy(files)
                blocked = domains + 'ads.google.com\n'
                candidate = {**snapshot, 'domains': blocked, 'domain_count': len(blocked.splitlines()),
                             'domains_sha256': ad_rules.sha(blocked.encode())}
                with patch.object(ad_rules, 'refresh', return_value=candidate), \
                        self.assertRaisesRegex(ValueError, 'ads.google.com'):
                    ad_delivery.refresh(ad_delivery.read_config(config_path))
                self.assertEqual(files, before)


if __name__ == '__main__':
    unittest.main()
