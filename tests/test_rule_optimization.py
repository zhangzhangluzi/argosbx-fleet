import sys,unittest
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import dns_policy as policy
from routing_policy import AI_DOMAINS,DIAGNOSTIC_DOMAINS,OVERSEAS_DOMAINS

class RuleOptimizationTests(unittest.TestCase):
    def profile(self,client):
        base=yaml.safe_load((ROOT/'templates'/('base-'+client+'.yaml')).read_text())
        return policy.harden_config(base,client,hosts={})

    def test_explicit_remote_dns_beats_broad_cn_set(self):
        for client in ('clash','stash'):
            v=self.profile(client)
            for domain in DIAGNOSTIC_DOMAINS+OVERSEAS_DOMAINS:
                self.assertLess(v['rules'].index('DOMAIN-SUFFIX,'+domain+',日常线路'),v['rules'].index('RULE-SET,国内域名,DIRECT'))
                self.assertIn('1.1.1.1',v['dns']['nameserver-policy']['+.'+domain][0])
            self.assertLess(v['rules'].index('RULE-SET,广告域名,去广告'),v['rules'].index('DOMAIN-SUFFIX,github.com,日常线路'))
            self.assertIn('RULE-SET,国内IP,DIRECT',v['rules'])
            self.assertEqual(v,policy.harden_config(v,client,hosts={}))

    def test_ai_dns_matches_selected_egress_without_bootstrap_recursion(self):
        for client in ('clash','stash'):
            v=self.profile(client)
            for domain in AI_DOMAINS:
                dns=v['dns']['nameserver-policy']['+.'+domain]
                self.assertEqual(dns,[u+'#AI线路' for u in policy.REMOTE] if client=='clash' else policy.STASH_AI_DNS)
            if client=='stash':
                for ip in ('8.8.8.8','8.8.4.4'):
                    self.assertIn('IP-CIDR,'+ip+'/32,AI线路,no-resolve',v['rules'])
                self.assertIn('IP-CIDR,1.1.1.1/32,日常线路,no-resolve',v['rules'])
                self.assertEqual(v['dns']['proxy-server-nameserver'],policy.BOOTSTRAP)

    def test_shadowrocket_tailnet_and_ads_are_native_and_scoped(self):
        src=(ROOT/'templates/base-shadowrocket.conf').read_text()
        args={'hosts':{},'tailscale':{'magic_dns_suffix':'tail-example.ts.net'},'ads_url':'https://sub.example/ads'}
        text=policy.harden_shadowrocket(src,**args)
        self.assertEqual(text,policy.harden_shadowrocket(text,**args))
        self.assertIn('*.tail-example.ts.net = server:100.100.100.100',text)
        self.assertNotIn('*.ts.net =',text)
        self.assertIn('fd7a:115c:a1e0::/48',text)
        self.assertIn(policy.MAGIC_DNS_RULE,text)
        ads='DOMAIN-SET,https://sub.example/ads,REJECT'
        self.assertIn(ads,text)
        self.assertLess(text.index('DOMAIN,ads.applovin.com,日常线路'),text.index(ads))
        self.assertLess(text.index(ads),text.index('GEOIP,CN,DIRECT'))
        self.assertNotIn('PASS',text)
