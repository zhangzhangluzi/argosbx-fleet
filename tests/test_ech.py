"""ECH identity, fail-closed export, and client routing regressions."""
import base64
import copy
import json
import unittest
from unittest.mock import Mock
from test_core import fixtures
import ech
from protocols import export, render
from probe import outbound
from dns_policy import harden_config

CONFIG = base64.b64encode(b'\x00\x04\xfe\x0d\x00\x00').decode()
KEY = '-----BEGIN ECH KEYS-----\nfixture-private\n-----END ECH KEYS-----\n'

class ECHTests(unittest.TestCase):
    def setup(self):
        configs, _, state = fixtures()
        keygen = Mock(return_value=(KEY, CONFIG))
        ech.configure(configs, state, keygen)
        return configs, state, keygen

    def test_repeat_does_not_rotate_and_public_export_has_no_private_key(self):
        configs, state, keygen = self.setup()
        original = copy.deepcopy((configs, state))
        ech.configure(configs, state, keygen)
        self.assertEqual(keygen.call_count, 1)
        self.assertEqual((configs, state), original)
        nodes = export(configs, state)['proxies']
        self.assertEqual(nodes[0]['ech-opts']['config'], CONFIG)
        self.assertNotIn('fixture-private', json.dumps(nodes))
        self.assertEqual(nodes[1]['ech-opts']['query-server-name'], ech.PUBLIC_NAME)
        self.assertEqual(nodes[1]['ech-opts']['_dns'], ech.DNS)
        self.assertNotIn('ech-opts', nodes[2])

    def test_disabled_inbound_keeps_key_when_reenabled(self):
        configs, state, keygen = self.setup()
        wanted = copy.deepcopy(state['protocols'])
        wanted['anytls']['enabled'] = False
        disabled = render(configs, state, wanted)
        old = state['protocols'];state['protocols'] = wanted
        ech.configure(disabled, state, keygen)
        restored = render(disabled, state, old);state['protocols'] = old
        ech.configure(restored, state, keygen)
        self.assertEqual(keygen.call_count, 1)
        self.assertEqual(export(restored, state)['proxies'][0]['ech-opts']['config'], CONFIG)

    def test_missing_native_key_cannot_silently_regenerate_or_export(self):
        configs, state, keygen = self.setup()
        del configs['/test/s.json']['inbounds'][0]['tls']['ech']
        with self.assertRaises(ValueError):ech.configure(configs, state, keygen)
        with self.assertRaises(ValueError):export(configs, state)
        self.assertEqual(keygen.call_count, 1)

    def test_changed_key_stops_export(self):
        configs, state, _ = self.setup()
        configs['/test/s.json']['inbounds'][0]['tls']['ech']['key'] = ['different']
        with self.assertRaises(ValueError):export(configs, state)

    def test_unmanaged_key_is_not_overwritten(self):
        configs, _, state = fixtures()
        configs['/test/s.json']['inbounds'][0]['tls']['ech'] = {'enabled':True, 'key':[KEY]}
        keygen = Mock()
        with self.assertRaises(ValueError):ech.configure(configs, state, keygen)
        keygen.assert_not_called()

    def test_probe_preserves_ech_and_native_chrome_fingerprint(self):
        configs, state, _ = self.setup()
        n = export(configs, state)['proxies'][0];n['server']='192.0.2.1'
        tls = outbound(n)[0]['tls']
        self.assertEqual(tls['ech'], {'enabled':True, 'config':[ech.pem_config(CONFIG)]})
        self.assertEqual(tls['utls']['fingerprint'], 'chrome')

    def test_malformed_config_is_rejected(self):
        for value in ('', 'bad!', 'AAAA'):
            with self.assertRaises(ValueError):ech.pem_config(value)

    def test_dns_bootstrap_and_application_dns_are_separate(self):
        profile = harden_config({'dns':{}, 'rules':['MATCH,DIRECT']}, 'clash', hosts={})
        dns = profile['dns']
        self.assertEqual(dns['proxy-server-nameserver-policy'], {ech.PUBLIC_NAME:[ech.DNS+'#DIRECT']})
        self.assertTrue(all('dns.alidns.com' not in u for u in dns['default-nameserver']))
        self.assertTrue(all('#DIRECT' in u for u in dns['proxy-server-nameserver']))

if __name__ == '__main__':unittest.main()
