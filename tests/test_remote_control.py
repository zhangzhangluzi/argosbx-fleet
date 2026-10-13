"""Remote applications must not fall through to foreign relays or remote DNS."""
import re
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import dns_policy as policy


class RemoteControlTests(unittest.TestCase):
    def test_helpers_match_but_unrelated_apps_do_not(self):
        for name in ('UURemote', 'UURemoteDaemon', 'UURemoteServer', 'uuyc-cli',
                     'ToDesk.exe', 'ToDesk_Service', 'ToDesk_Session',
                     'SunloginClient', 'SunloginClient_Desktop', 'sunloginclient',
                     'oray-sunloginservice'):
            self.assertRegex(name, policy.REMOTE_CONTROL_PROCESS)
        for name in ('curl', 'Safari', 'FlClashCore', 'not-ToDesk', 'remoteagent'):
            self.assertIsNone(re.fullmatch(policy.REMOTE_CONTROL_PROCESS, name))

    def test_priority_and_dns_remain_consistent_and_idempotent(self):
        for client in ('clash', 'stash'):
            base = yaml.safe_load((ROOT / 'templates' / ('base-'+client+'.yaml')).read_text())
            result = policy.harden_config(base, client, hosts={})
            rules = result['rules']
            self.assertEqual(rules[0], 'DST-PORT,53,REJECT')
            for domain in policy.REMOTE_CONTROL_DOMAINS:
                self.assertLess(rules.index('DOMAIN-SUFFIX,'+domain+',DIRECT'),
                                rules.index('RULE-SET,广告域名,去广告'))
                self.assertEqual(result['dns']['nameserver-policy']['+.'+domain],
                                 [policy.LOCAL_DOH+('#DIRECT' if client == 'clash' else '')])
                if client == 'clash':
                    self.assertIn('+.'+domain, result['dns']['fake-ip-filter'])
            self.assertEqual(policy.harden_config(result, client, hosts={}), result)
            self.assertEqual(policy.REMOTE_CONTROL_RULE in rules, client == 'clash')
            if client == 'clash':
                self.assertEqual(rules[1], policy.REMOTE_CONTROL_RULE)
                self.assertEqual(result['find-process-mode'], 'strict')
            self.assertEqual(result['dns']['nameserver'],
                             [u+('#日常线路' if client == 'clash' else '') for u in policy.REMOTE])
            self.assertIn('DOMAIN-SUFFIX,chatgpt.com,AI线路', rules)

    def test_shadowrocket_gets_only_compatible_domain_rules(self):
        original = (ROOT / 'templates/base-shadowrocket.conf').read_text()
        result = policy.harden_shadowrocket(original, hosts={})
        for domain in policy.REMOTE_CONTROL_DOMAINS:
            self.assertIn('\nDOMAIN-SUFFIX,'+domain+',DIRECT\n', result)
        self.assertNotIn('PROCESS-NAME-REGEX', result)
        self.assertEqual(policy.harden_shadowrocket(result, hosts={}), result)
