"""The accepted snapshot is a single version across the three clients."""
import base64
import json
from pathlib import Path
import tempfile
import unittest

import ad_rules
import country_routes


class AdDeliveryTests(unittest.TestCase):
    def test_snapshot_checksum_and_versioned_provider(self):
        domains = ad_rules.convert('# header\n+.Doubleclick.net\n+.applovin.com\n+.applovin.com\n')
        self.assertEqual(domains, '.doubleclick.net\n.applovin.com\n')
        mrs = ad_rules.MRS_MAGIC + b'fixture'
        snapshot = {'revision': '1'*40, 'domains': domains, 'domain_count': 2,
                    'domains_sha256': ad_rules.sha(domains.encode()),
                    'mrs_sha256': ad_rules.sha(mrs), 'mrs': base64.b64encode(mrs).decode()}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'snapshot.json'
            path.write_text(json.dumps(snapshot))
            config = {'subscription': {'backend_url': 'https://sub.example:8443/private',
                                       'ad_rules_snapshot': str(path)}}
            result = ad_rules.load(config)
            value = {'rule-providers': {'广告域名': {'behavior': 'domain', 'format': 'mrs'}}}
            ad_rules.use_provider(value, config, result)
            self.assertEqual(value['rule-providers']['广告域名']['url'],
                             'https://sub.example:8443/rules/ad/ads-'+ad_rules.sha(mrs)+'.mrs')
            self.assertEqual(ad_rules.file_object('ads', 'ads', result)['content'], domains)
            with self.assertRaises(ValueError):
                ad_rules.validate({**snapshot, 'domains': '.bad.example\n'})
            with self.assertRaises(ValueError):
                ad_rules.validate({**snapshot, 'mrs_sha256': '0'*64})

    def test_malformed_upstream_is_refused(self):
        for value in ('', '<html>error</html>', 'DOMAIN-SUFFIX,example.com', '+.com'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ad_rules.convert(value)

    def test_asset_route_keeps_original_import_and_is_idempotent(self):
        original = '# BEGIN EXTERNAL SEVEN SHARES\n# END EXTERNAL SEVEN SHARES\n'
        after = country_routes.ad_render(original)
        self.assertTrue(after.startswith(original))
        self.assertEqual(country_routes.ad_render(after), after)
        with self.assertRaises(ValueError):
            country_routes.ad_render(original+'handle /rules/ad/* { respond 200 }\n')
