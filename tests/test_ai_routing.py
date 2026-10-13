"""Keep AI routing coverage consistent and scoped across native client formats."""
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import dns_policy

ADDED = ('notebooklm.google', 'notebook.google', 'copilot.microsoft.com',
         'copilot.com', 'copilot.cloud.microsoft', 'grok.com', 'grok.x.ai',
         'accounts.x.ai')


class AiRoutingTests(unittest.TestCase):
    def profiles(self):
        for client in ('clash', 'stash'):
            base = yaml.safe_load((ROOT/'templates'/('base-'+client+'.yaml')).read_text())
            yield client, dns_policy.harden_config(base, client, hosts={})['rules']
        raw = dns_policy.harden_shadowrocket((ROOT/'templates/base-shadowrocket.conf').read_text(), hosts={})
        yield 'shadowrocket', raw.split('[Rule]', 1)[1].split('\n[', 1)[0].strip().splitlines()

    def test_client_coverage_is_identical_before_domestic_ip_fallback(self):
        profiles = list(self.profiles())
        common = {r for r in profiles[0][1] if r.endswith(',AI线路')}
        for client, rules in profiles:
            ai = [r for r in rules if r.endswith(',AI线路')]
            self.assertEqual(set(ai), common, client)
            self.assertEqual(len(ai), len(set(ai)), client)
            fallback = 'GEOIP,CN,DIRECT' if client == 'shadowrocket' else 'RULE-SET,国内IP,DIRECT'
            for host in ADDED:
                self.assertLess(rules.index('DOMAIN-SUFFIX,'+host+',AI线路'), rules.index(fallback), client)
            # Preserve pre-existing AI entries and Google Play's independent path.
            self.assertIn('DOMAIN-SUFFIX,notebooklm.google.com,AI线路', rules)
            self.assertIn('DOMAIN-SUFFIX,chatgpt.com,AI线路', rules)
            self.assertIn('DOMAIN-SUFFIX,googleapis.cn,日常线路', rules)
            if client != 'shadowrocket':
                self.assertLess(rules.index('RULE-SET,广告域名,去广告'), rules.index('DOMAIN-SUFFIX,grok.com,AI线路'))

    def test_no_platform_wide_or_substring_matching(self):
        for client, rules in self.profiles():
            suffixes = [r.split(',')[1] for r in rules if r.startswith('DOMAIN-SUFFIX,') and r.endswith(',AI线路')]
            def matches(host):
                return any(host == suffix or host.endswith('.'+suffix) for suffix in suffixes)
            for host in ADDED:
                self.assertTrue(matches(host), (client, host))
                self.assertTrue(matches('api.'+host), (client, host))
                self.assertFalse(matches(host+'.unrelated.example'), (client, host))
            for host in ('www.google.com','accounts.google.com','www.microsoft.com',
                         'login.live.com','www.bing.com','x.com','example.com'):
                self.assertFalse(matches(host), (client, host))
