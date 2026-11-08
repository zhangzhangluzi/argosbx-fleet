"""Regression tests for managed ad exceptions and failed rule releases."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ad_delivery
import ad_rules
from dns_policy import console_dns


class AdRefreshTests(unittest.TestCase):
    def test_route_and_dns_add_remove_and_retarget_in_both_yaml_formats(self):
        old = {'old.example': 'DIRECT', 'move.example': '日常线路'}
        new = {'analytics.google.com': '日常线路', 'move.example': 'DIRECT'}
        before = ['DST-PORT,53,REJECT', 'DOMAIN,old.example,DIRECT',
                  'DOMAIN,move.example,日常线路', 'DOMAIN,unrelated.example,DIRECT',
                  ad_rules.AD_RULE, 'MATCH,日常线路']
        expected = ['DST-PORT,53,REJECT', 'DOMAIN,analytics.google.com,日常线路',
                    'DOMAIN,move.example,DIRECT', 'DOMAIN,unrelated.example,DIRECT',
                    ad_rules.AD_RULE, 'MATCH,日常线路']
        self.assertEqual(ad_delivery.replace_exceptions(before, old, new, ad_rules.AD_RULE), expected)
        for client in ('clash', 'stash'):
            unrelated = {'unrelated.example': ['https://example.test/dns-query']}
            policy = {**unrelated, **console_dns(client, old)}
            ad_delivery.replace_dns(policy, client, old, new)
            self.assertEqual(policy, {**unrelated, **console_dns(client, new)})
        with self.assertRaises(ValueError):
            ad_delivery.replace_exceptions(['DOMAIN,old.example,REJECT', ad_rules.AD_RULE],
                                           old, new, ad_rules.AD_RULE)

    def test_earlier_suffix_cannot_hide_exact_business_exception(self):
        rows = ['DOMAIN-SUFFIX,google.com,REJECT', 'DOMAIN,analytics.google.com,日常线路']
        self.assertEqual(ad_rules.first_domain_target(rows, 'analytics.google.com'), 'REJECT')
        self.assertFalse(ad_rules.matches('other.adsdk.vivo.com.cn', {'adsdk.vivo.com.cn'}))
        self.assertTrue(ad_rules.matches('ms.applovin.com', {'.applovin.com'}))

    def test_refresh_skips_same_domains_and_refuses_broken_upstream(self):
        domains = '.applovin.com\n.doubleclick.net\n.google-analytics.com\n'
        before = {'domains': domains + '\n'.join(ad_rules.EXTRA_ADS) + '\n'}
        with patch.object(ad_rules, 'upstream_domains', return_value=('1'*40, domains)), \
                patch.object(ad_rules, 'compile_snapshot') as compile_rules:
            self.assertIs(ad_rules.refresh(before, 'mihomo'), before)
            compile_rules.assert_not_called()
        with patch.object(ad_rules, 'upstream_domains', return_value=('1'*40, '.applovin.com\n')), \
                patch.object(ad_rules, 'compile_snapshot') as compile_rules, self.assertRaises(ValueError):
            ad_rules.refresh(before, 'mihomo')
            compile_rules.assert_not_called()

    def test_failed_readback_restores_both_scopes_and_active_state(self):
        api = {'subscription': {'backend_url': 'http://127.0.0.1:3001/fixture'}}
        names = [prefix + fmt for prefix in ad_delivery.PREFIXES for fmt in ad_delivery.FORMATS]
        original = {name: {'name': name, 'content': 'old'} for name in names}
        original[ad_rules.STATE_FILE] = {'name': ad_rules.STATE_FILE, 'content': 'previous'}
        live = dict(original)

        def rpc(config, path, value=None, method=None):
            if method == 'POST':
                live[value['name']] = value
            elif method == 'PATCH':
                live[path.rsplit('/', 1)[1]] = value
            elif method == 'DELETE':
                del live[path.rsplit('/', 1)[1]]
            elif path == '/api/files':
                return list(live.values())
            else:
                raise AssertionError(path)

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(ad_delivery, 'JOURNAL', Path(directory)/'journal.json'), \
                patch.object(ad_delivery, 'get', side_effect=lambda _, kind, name: live.get(name)), \
                patch.object(ad_delivery, 'request', side_effect=rpc), \
                patch.object(ad_delivery, 'candidate', side_effect=lambda before, *_: {**before, 'content': 'new'}), \
                patch.object(ad_delivery, 'store_ad_asset'), \
                patch.object(ad_delivery, 'verify', side_effect=[{}, ValueError('readback failed')]):
            with self.assertRaisesRegex(ValueError, 'readback failed'):
                ad_delivery.publish({}, api, {}, {}, {}, original[ad_rules.STATE_FILE])
            self.assertEqual(live, original)
            self.assertFalse(ad_delivery.JOURNAL.exists())
