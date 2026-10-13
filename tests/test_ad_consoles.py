"""Precise console exceptions must not disable the surrounding ad block list."""
import importlib
import sys
import unittest
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class AdConsoleTests(unittest.TestCase):
    def setUp(self):
        sys.modules.pop('dns_policy', None)
        self.dns = importlib.import_module('dns_policy')

    def test_domestic_exceptions_precede_ad_list_and_are_idempotent(self):
        rules = self.dns.guarded_rules(['RULE-SET,广告域名,去广告', 'MATCH,日常线路'])
        for host in self.dns.DOMESTIC_BUSINESS_HOSTS:
            self.assertLess(rules.index('DOMAIN,' + host + ',DIRECT'), rules.index('RULE-SET,广告域名,去广告'))
        self.assertEqual(self.dns.guarded_rules(rules), rules)

    def test_no_platform_or_tracking_exemption(self):
        rules = self.dns.guarded_rules([])
        for host in ['ms.applovin.com', 'www.googleadservices.com', 'frontend-perf-service.e.kuaishou.com',
                     'log-sdk.ksapisrv.com', 'e.kuaishou.com', 'adkwai.com', 'byteadverts.com']:
            self.assertFalse(any(r.startswith(('DOMAIN,' + host + ',', 'DOMAIN-SUFFIX,' + host + ',')) for r in rules))
        for host in self.dns.DOMESTIC_BUSINESS_HOSTS + self.dns.BUSINESS_CONSOLES:
            self.assertFalse(any(r.startswith('DOMAIN-SUFFIX,' + host + ',') for r in rules))

    def test_dns_route_and_existing_ad_switch_agree(self):
        for client in ['clash', 'stash']:
            base = yaml.safe_load((ROOT / 'templates' / ('base-' + client + '.yaml')).read_text())
            base['proxy-groups'] = [{'name': '去广告', 'type': 'select', 'proxies': ['开启去广告', '关闭去广告']}]
            value = self.dns.harden_config(base, client, hosts={})
            for host in self.dns.DOMESTIC_BUSINESS_HOSTS:
                self.assertEqual(value['dns']['nameserver-policy'][host],
                                 [self.dns.LOCAL_DOH + ('#DIRECT' if client == 'clash' else '')])
            for host in self.dns.BUSINESS_CONSOLES:
                self.assertIn('1.1.1.1', value['dns']['nameserver-policy'][host][0])
            self.assertEqual(value['proxy-groups'], base['proxy-groups'])
            self.assertEqual(value['rule-providers'], base['rule-providers'])

    def test_shadowrocket_gets_same_exact_routes(self):
        base = (ROOT / 'templates' / 'base-shadowrocket.conf').read_text()
        value = self.dns.harden_shadowrocket(base, hosts={})
        for host in self.dns.DOMESTIC_BUSINESS_HOSTS:
            self.assertIn('\nDOMAIN,' + host + ',DIRECT\n', value)
        self.assertEqual(self.dns.harden_shadowrocket(value, hosts={}), value)
