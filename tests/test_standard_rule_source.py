import copy,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from standard_rule_source import sanitize,validate_candidates,refresh_if_configured
from test_standard_rule_provider import fixture,ORIGIN

class StandardRuleSourceTest(unittest.TestCase):
    def test_snapshot_is_a_strict_rule_only_whitelist(self):
        raw=fixture();raw['proxy-providers']={'secret':'not-public'}
        raw['dns']={'nameserver':['private-resolver']}
        raw['rule-providers']['广告域名']['extra-token']='should-not-leak'
        clean=sanitize(raw,ORIGIN)
        self.assertEqual(set(clean),{'rules','rule-providers'})
        serialized=json.dumps(clean,ensure_ascii=False)
        for secret in ('not-public','private-resolver','should-not-leak','do-not-export'):
            self.assertNotIn(secret,serialized)

    def test_bad_provider_url_and_unsupported_rule_are_rejected(self):
        for mutate in (lambda x:x['rule-providers']['广告域名'].update(url='https://evil.test/ad.mrs'),
                       lambda x:x['rules'].append('CUSTOM-NEW-TYPE,foo,DIRECT'),
                       lambda x:x['rules'].append('DOMAIN,https://bad.test,DIRECT')):
            profile=fixture();mutate(profile)
            with self.assertRaises(ValueError):sanitize(profile,ORIGIN)

    def test_refresh_refuses_snapshots_that_break_published_rules(self):
        root=Path(__file__).resolve().parents[1]/'templates'
        scripts={'standard':(root/'standard-rule-provider.js').read_text().replace('STANDARD_AD_ORIGIN',ORIGIN),
                 'process':(root/'standard-process-provider.js').read_text(),
                 'stash':(root/'standalone-rules.js').read_text().replace('STANDALONE_FORMAT','stash'),
                 'clash':(root/'standalone-rules.js').read_text().replace('STANDALONE_FORMAT','clash')}
        stash=fixture();clash=copy.deepcopy(stash)
        clash['rules'].insert(2,'PROCESS-NAME-REGEX,(?i)^example$,DIRECT')
        candidate={'stash':sanitize(stash,ORIGIN),'clash':sanitize(clash,ORIGIN)}
        validate_candidates(candidate,scripts,node='node')
        for profile in candidate.values():
            rule='DOMAIN,r.applovin.com,日常线路'
            profile['rules'].remove(rule)
            profile['rules'].insert(profile['rules'].index('DOMAIN,developers.applovin.com,日常线路'),rule)
        validate_candidates(candidate,scripts,node='node')
        candidate['stash']['rules'].insert(5,'DOMAIN,new.example,DIRECT')
        with self.assertRaises(ValueError):validate_candidates(candidate,scripts,node='node')

    def test_optional_sync_skips_only_when_source_is_absent(self):
        with patch.object(Path,'is_file',return_value=False):
            self.assertEqual(refresh_if_configured(),{'configured':False})
        with patch.object(Path,'is_file',return_value=True), \
             patch('standard_rule_source.read_config',return_value={'backend_url':'https://example.test/private'}), \
             patch('standard_rule_source.api',return_value=[]):
            self.assertEqual(refresh_if_configured(),{'configured':False})
        with patch.object(Path,'is_file',return_value=True), \
             patch('standard_rule_source.read_config',return_value={'backend_url':'https://example.test/private'}), \
             patch('standard_rule_source.api',return_value=[{'name':'standard-rule-source'}]), \
             patch('standard_rule_source.refresh',return_value={'verified':True,'updated':1}):
            self.assertEqual(refresh_if_configured(),{'configured':True,'verified':True,'updated':1})

if __name__=='__main__':unittest.main()
