import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import fleet
import acceptance
import servers
import udp6_redirect as redirect

ROOT = Path(__file__).resolve().parents[1]
CONFIG = {'address': '2606:4700:4700::1111', 'port': 443, 'target_port': 2446}

def table():
    return {'nftables': [
        {'table': {'family': 'ip6', 'name': redirect.TABLE}},
        {'chain': {'hook': 'prerouting', 'type': 'nat', 'policy': 'accept', 'prio': -100}},
        {'rule': {'family': 'ip6', 'table': redirect.TABLE, 'chain': 'preroute', 'expr': [
            {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip6', 'field': 'daddr'}}, 'right': CONFIG['address']}},
            {'match': {'op': '==', 'left': {'payload': {'protocol': 'udp', 'field': 'dport'}}, 'right': CONFIG['port']}},
            {'counter': {'packets': 0, 'bytes': 0}}, {'redirect': {'port': CONFIG['target_port']}}
        ]}}
    ]}

class RedirectTests(unittest.TestCase):
    def test_only_exact_ipv6_udp_rule_is_accepted(self):
        self.assertTrue(redirect.valid_table(table(), CONFIG))
        cases = []
        for item, value in [(0, '2606:4700:4700::1001'), (1, 8443)]:
            bad = copy.deepcopy(table()); bad['nftables'][2]['rule']['expr'][item]['match']['right'] = value; cases.append(bad)
        bad = copy.deepcopy(table()); bad['nftables'][2]['rule']['expr'][3]['redirect']['port'] = 2447; cases.append(bad)
        bad = copy.deepcopy(table()); bad['nftables'][2]['rule']['expr'].append({'drop': None}); cases.append(bad)
        bad = copy.deepcopy(table()); bad['nftables'][1]['chain']['prio'] = 0; cases.append(bad)
        for bad in cases:
            self.assertFalse(redirect.valid_table(bad, CONFIG))
        text = redirect.render(CONFIG).decode()
        self.assertIn('table ip6 '+redirect.TABLE, text)
        self.assertIn('udp dport 443 counter redirect to :2446', text)
        self.assertNotIn('drop', text)

    def test_invalid_private_address_and_ports_are_rejected(self):
        for change in ({'address': '::1'}, {'port': True}, {'port': 0}, {'port': 2446}, {'target_port': 65536}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                redirect.validate({**CONFIG, **change})

    def transaction(self, fail=False):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        paths = {'CONFIG': root/'config', 'RULE': root/'rule', 'UNIT': root/'unit', 'JOURNAL': root/'journal'}
        state = {'timer': False, 'service': False, 'table': False, 'commands': []}
        def run(args, body=None, check=True):
            state['commands'].append(args)
            code = 0; output = ''
            if args[:3] == ['nft', '-j', 'list']:
                code = 0 if state['table'] else 1
                output = json.dumps(table()) if state['table'] else ''
            elif args[0] == 'systemd-run': state['timer'] = True
            elif args[:2] == ['systemctl', 'is-active']:
                code = 0 if state['timer' if args[-1] == redirect.TIMER else 'service'] else 3
            elif args[:2] == ['systemctl', 'is-enabled']: code = 0 if state['service'] else 1
            elif args[:3] == ['systemctl', 'enable', '--now']:
                state['service'] = True; state['table'] = True
                if fail: raise RuntimeError('simulated startup error')
            elif args[:2] == ['systemctl', 'show']: output = 'loaded\n' if state['service'] else 'not-found\n'
            elif args[:3] == ['systemctl', 'disable', '--now']: state['service'] = False; state['table'] = False
            elif args[:2] == ['systemctl', 'stop']: state['timer'] = False
            elif args[:3] == ['nft', 'delete', 'table']: state['table'] = False
            if check and code: raise RuntimeError('simulated command failure')
            return subprocess.CompletedProcess(args, code, output, '')
        return paths, state, run

    def test_stage_commit_keeps_only_redirect_and_no_proxy_restart(self):
        paths, state, run = self.transaction()
        with patch.multiple(redirect, **paths), patch.object(redirect.os, 'geteuid', return_value=0), \
             patch.object(redirect, 'target_ready', return_value=True), patch.object(redirect, 'ingress_ready', return_value=True), \
             patch.object(redirect, 'protected', return_value={'xray': {'MainPID': '42'}}), patch.object(redirect, 'run', side_effect=run):
            self.assertTrue(redirect.stage(CONFIG)['staged'])
            self.assertTrue(state['timer'])
            self.assertTrue(redirect.commit()['committed'])
        self.assertTrue(state['table']); self.assertTrue(state['service']); self.assertFalse(state['timer'])
        self.assertFalse(paths['JOURNAL'].exists())
        self.assertFalse(any(args[:2] == ['systemctl', 'restart'] for args in state['commands']))

    def test_failed_stage_recovers_owned_files(self):
        paths, state, run = self.transaction(fail=True)
        with patch.multiple(redirect, **paths), patch.object(redirect.os, 'geteuid', return_value=0), \
             patch.object(redirect, 'target_ready', return_value=True), patch.object(redirect, 'ingress_ready', return_value=True), \
             patch.object(redirect, 'protected', return_value={}), patch.object(redirect, 'run', side_effect=run):
            with self.assertRaises(RuntimeError): redirect.stage(CONFIG)
        self.assertFalse(state['table']); self.assertFalse(state['timer'])
        self.assertTrue(all(not p.exists() for p in paths.values()))

    def test_recover_refuses_drift_without_touching_rules(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); journal = root/'journal'; journal.write_text(json.dumps({'config': CONFIG}))
            rule = root/'rule'; rule.write_text('external change')
            with patch.multiple(redirect, JOURNAL=journal, RULE=rule, CONFIG=root/'config', UNIT=root/'unit'), \
                 patch.object(redirect, 'run', side_effect=AssertionError('must not touch network')):
                with self.assertRaises(ValueError): redirect.recover()
            self.assertTrue(journal.exists()); self.assertEqual(rule.read_text(), 'external change')

class InventoryTests(unittest.TestCase):
    def config(self):
        config = json.loads((ROOT/'templates/servers.example.json').read_text())
        s = config['servers'][0]
        s['protocols'] = {'hy2': {'enabled': True, 'port': 2446, 'listen': '::'}}
        s['ipv6_hy2_ingress'] = {'port': 443, 'target_port': 2446}
        return config

    def test_inventory_checks_target_and_udp_conflicts(self):
        config = self.config(); fleet.validate(config)
        for mutate in (
            lambda s: s['ipv6_hy2_ingress'].update(target_port=2447),
            lambda s: s['ipv6_hy2_ingress'].update(port=True),
            lambda s: s['protocols']['hy2'].update(enabled=False),
            lambda s: s['protocols'].update(other={'type':'hy2','enabled':True,'port':443,'listen':'::'}),
        ):
            bad = copy.deepcopy(config); mutate(bad['servers'][0])
            with self.assertRaises(ValueError): fleet.validate(bad)
        # An IPv4-only listener on the same port does not conflict.
        config['servers'][0]['protocols']['other'] = {'type':'hy2','enabled':True,'port':443,'listen':'198.51.100.1'}
        fleet.validate(config)

    def test_generated_nodes_change_only_hy2_ipv6_port(self):
        server = self.config()['servers'][0]
        source = [{'name':'fleet.hy2','type':'hysteria2','port':2446,'password':'test'},
                  {'name':'fleet.other','type':'hysteria2','port':443,'password':'other'}]
        server['protocols']['other'] = {'type':'hy2','enabled':True,'port':443,'listen':'198.51.100.1'}
        def render(s, nodes=source):
            script = (ROOT/'region-processor.js').read_text().replace('SPEC', json.dumps(fleet.region_spec(s)))
            result = subprocess.run(['node','-e',script+';process.stdout.write(JSON.stringify(operator('+json.dumps(nodes)+')));'],
                                    capture_output=True, text=True, check=True)
            return json.loads(result.stdout)
        previous = copy.deepcopy(server); previous.pop('ipv6_hy2_ingress')
        old = {n['name']: n for n in render(previous)}; new = {n['name']: n for n in render(server)}
        self.assertEqual(set(old), set(new))
        changed = [n for n in old if old[n] != new[n]]
        self.assertEqual(len(changed), 1)
        name = changed[0]; self.assertIn('-v6-Hysteria2', name)
        self.assertEqual(old[name]['port'], 2446); self.assertEqual(new[name]['port'], 443)
        old[name]['port'] = 443; self.assertEqual(old[name], new[name])

    def test_publication_refuses_missing_or_mismatched_live_redirect(self):
        config = self.config(); server = config['servers'][0]
        server['certificates'] = {}
        live = {'protocols': server['protocols'], 'certificates': {},
                'native_configuration_matches': True, 'services_active': True,
                'source_matches': True, 'certificate_health': {}}
        with patch('fleetctl.remote', return_value=live):
            with self.assertRaisesRegex(ValueError, 'IPv6 HY2'): servers.native_preflight(config)
        live['ipv6_hy2_redirect'] = {'verified': True, 'address': server['ipv6'], 'port':443, 'target_port':2446}
        with patch('fleetctl.remote', return_value=live): servers.native_preflight(config)
        live['ipv6_hy2_redirect']['target_port'] = 2447
        with patch('fleetctl.remote', return_value=live):
            with self.assertRaisesRegex(ValueError, 'IPv6 HY2'): servers.native_preflight(config)

    def test_native_diagnostics_use_the_published_ipv6_ingress(self):
        server=self.config()['servers'][0]
        nodes=[{'name':'fleet.hy2','type':'hysteria2','port':2446,'password':'test'}]
        checks={x['name']:x['node'] for x in acceptance.cases(server,nodes)}
        self.assertEqual(checks['hy2/ipv4']['port'],2446)
        self.assertEqual(checks['hy2/ipv6']['port'],443)
        self.assertEqual(nodes[0]['port'],2446)
        nodes[0]['port']=2447
        with self.assertRaises(ValueError):acceptance.cases(server,nodes)
if __name__ == '__main__': unittest.main()
