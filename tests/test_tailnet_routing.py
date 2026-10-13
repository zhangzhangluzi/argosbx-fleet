"""Scope DNS fallback and private Tailnet exceptions without weakening DNS guards."""
import copy
import json
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import dns_policy as policy
import fleet

TAILNET = {'magic_dns_suffix': 'tail-example.ts.net'}


class RoutingTests(unittest.TestCase):
    def test_only_domestic_ip_fallback_resolves(self):
        for client in ('clash', 'stash'):
            base = yaml.safe_load((ROOT/'templates'/('base-'+client+'.yaml')).read_text())
            # Also accept an old generated profile on the upgrade path.
            base['rules'] = [r.replace('RULE-SET,国内IP,DIRECT', 'RULE-SET,国内IP,DIRECT,no-resolve') for r in base['rules']]
            old_no_resolve = {r for r in base['rules'] if r.endswith(',no-resolve')}
            result = policy.harden_config(base, client, hosts={})
            self.assertIn('RULE-SET,国内IP,DIRECT', result['rules'])
            self.assertNotIn('RULE-SET,国内IP,DIRECT,no-resolve', result['rules'])
            # Existing explicit DNS overrides may replace an action, but must
            # retain no-resolve on the same destination.
            for rule in old_no_resolve - {'RULE-SET,国内IP,DIRECT,no-resolve'}:
                prefix = ','.join(rule.split(',')[:2]) + ','
                self.assertTrue(any(r.startswith(prefix) and r.endswith(',no-resolve') for r in result['rules']))
            self.assertLess(result['rules'].index('DOMAIN-SUFFIX,googleapis.cn,日常线路'), result['rules'].index('RULE-SET,国内IP,DIRECT'))
            self.assertLess(result['rules'].index('RULE-SET,广告域名,去广告'), result['rules'].index('RULE-SET,国内IP,DIRECT'))
            self.assertLess(result['rules'].index('RULE-SET,国内IP,DIRECT'), result['rules'].index('NETWORK,UDP,UDP线路'))

    def test_tailnet_scope_dns_guard_and_idempotence(self):
        for client in ('clash', 'stash'):
            base = yaml.safe_load((ROOT/'templates'/('base-'+client+'.yaml')).read_text())
            before = copy.deepcopy(base)
            result = policy.harden_config(base, client, hosts={}, tailscale=TAILNET)
            self.assertEqual(base, before)
            rules, dns = result['rules'], result['dns']
            self.assertEqual(rules[:2], [policy.MAGIC_DNS_RULE, 'DST-PORT,53,REJECT'])
            for r in ('DOMAIN-SUFFIX,tail-example.ts.net,DIRECT',
                      'IP-CIDR,100.64.0.0/10,DIRECT,no-resolve',
                      'IP-CIDR6,fd7a:115c:a1e0::/48,DIRECT,no-resolve'):
                self.assertLess(rules.index('DST-PORT,53,REJECT'), rules.index(r))
                self.assertLess(rules.index(r), rules.index('RULE-SET,广告域名,去广告'))
            self.assertFalse(any('DOMAIN-SUFFIX,ts.net,' in r for r in rules))
            self.assertEqual(dns['nameserver-policy']['+.tail-example.ts.net'],
                             ['100.100.100.100' + ('#DIRECT' if client == 'clash' else '')])
            self.assertIn('+.tail-example.ts.net', dns['fake-ip-filter'])
            self.assertEqual(policy.harden_config(result, client, hosts={}, tailscale=TAILNET), result)
            if client == 'clash':
                self.assertEqual(result['tun']['route-exclude-address'], policy.TAILSCALE_CIDRS)
            else:
                self.assertNotIn('tun', result)  # Never emit Mihomo-only fields.
            plain = policy.harden_config(base, client, hosts={})
            self.assertNotIn(policy.MAGIC_DNS_RULE, plain['rules'])
            self.assertNotIn('+.tail-example.ts.net', plain['dns']['nameserver-policy'])

    def test_shadowrocket_domestic_fallback_preserves_other_guards(self):
        base = (ROOT/'templates/base-shadowrocket.conf').read_text()
        for text in (base, base.replace('GEOIP,CN,DIRECT', 'GEOIP,CN,DIRECT,no-resolve')):
            result = policy.harden_shadowrocket(text, hosts={})
            self.assertIn('\nGEOIP,CN,DIRECT\n', result)
            self.assertNotIn('GEOIP,CN,DIRECT,no-resolve', result)
            self.assertEqual(result, policy.harden_shadowrocket(result, hosts={}))
            self.assertIn('IP-CIDR,91.108.4.0/22,Telegram,no-resolve', result)

    def test_inventory_rejects_broad_or_malformed_suffix(self):
        base = json.loads((ROOT/'templates/servers.example.json').read_text())
        fleet.validate(base)
        for value in ({}, 'tail-example.ts.net', {'magic_dns_suffix': 'ts.net'},
                      {'magic_dns_suffix': '+.ts.net'}, {'magic_dns_suffix': 'foo.com'},
                      {'magic_dns_suffix': 'tail-example.ts.net\n'},
                      {**TAILNET, 'resolver': '8.8.8.8'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                fleet.validate({**base, 'tailscale': value})
        fleet.validate({**base, 'tailscale': TAILNET})

