import json
from pathlib import Path
import subprocess
import sys
import unittest

TEMPLATE=(Path(__file__).resolve().parents[1]/'templates'/'standard-rule-provider.js').read_text()
ORIGIN='https://example.test:8443'
CN='https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/'
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dns_policy import BUSINESS_CONSOLES, DOMESTIC_BUSINESS_HOSTS


def fixture():
    return {'proxies':[{'name':'must-not-appear','password':'do-not-export'}],
      'rule-providers':{
        '广告域名':{'behavior':'domain','format':'mrs','url':ORIGIN+'/rules/ad/ads-'+'a'*64+'.mrs'},
        '国内域名':{'behavior':'domain','format':'mrs','url':CN+'geosite/cn.mrs'},
        '国内IP':{'behavior':'ipcidr','format':'mrs','url':CN+'geoip/cn.mrs'}},
      'rules':[
        'IP-CIDR,100.100.100.100/32,DIRECT,no-resolve', 'DST-PORT,53,REJECT',
        'DST-PORT,853,日常线路', 'DOMAIN-SUFFIX,tailnet.test,DIRECT',
        'DOMAIN-SUFFIX,browserleaks.com,日常线路', 'DOMAIN,ads.applovin.com,日常线路',
        'DOMAIN,ads.tiktok.com,日常线路', 'DOMAIN,max.applovin.com,日常线路', 'DOMAIN,dash.applovin.com,日常线路',
        'DOMAIN,developers.applovin.com,日常线路', 'DOMAIN,support.applovin.com,日常线路',
        'DOMAIN,analytics.google.com,日常线路',
        *['DOMAIN,'+domain+',DIRECT' for domain in DOMESTIC_BUSINESS_HOSTS],
        'DOMAIN,r.applovin.com,日常线路',
        'IP-CIDR,223.6.6.6/32,DIRECT,no-resolve', 'DOMAIN,dns.alidns.com,日常线路',
        'IP-CIDR,1.1.1.1/32,日常线路,no-resolve', 'IP-CIDR,8.8.8.8/32,AI线路,no-resolve',
        'IP-CIDR,223.5.5.5/32,日常线路,no-resolve', 'DOMAIN-SUFFIX,telegram.org,Telegram',
        'RULE-SET,广告域名,去广告', 'IP-CIDR,127.0.0.0/8,DIRECT,no-resolve',
        'DOMAIN-SUFFIX,chatgpt.com,AI线路', 'DOMAIN-SUFFIX,cn,DIRECT',
        'DOMAIN-SUFFIX,google.com,日常线路', 'RULE-SET,国内域名,DIRECT',
        'RULE-SET,国内IP,DIRECT', 'NETWORK,UDP,日常线路', 'MATCH,日常线路']}


def render(part, source):
    code=TEMPLATE.replace('STANDARD_AD_ORIGIN',ORIGIN)
    js=r'''
      const vm=require('vm'),fs=require('fs'),v=JSON.parse(fs.readFileSync(0,'utf8'));
      const input={$content:JSON.stringify(v.profile),$options:{_req:{query:{part:v.part}}}};
      const ctx={input,ProxyUtils:{yaml:{safeLoad:JSON.parse}}};vm.createContext(ctx);
      vm.runInContext(v.script+'\noperator(input);',ctx);
      process.stdout.write(JSON.stringify(input));
    '''
    p=subprocess.run(['node','-e',js],input=json.dumps({'part':part,'profile':source,'script':code},ensure_ascii=False),
                     text=True,capture_output=True)
    if p.returncode: raise ValueError('rule generation rejected')
    return json.loads(p.stdout)


class StandardRuleProviderTest(unittest.TestCase):
    def test_combined_business_rules_are_exact_and_fail_closed(self):
        profile=fixture()
        output=render('business-all',profile)['$content'].splitlines()
        expected={'DOMAIN,'+domain for domain in BUSINESS_CONSOLES+DOMESTIC_BUSINESS_HOSTS}
        self.assertEqual(set(output),expected)
        self.assertEqual(len(output),len(expected))
        for host in ('ms.applovin.com','www.googleadservices.com','log-sdk.ksapisrv.com'):
            self.assertNotIn('DOMAIN,'+host,output)
        for host in (BUSINESS_CONSOLES[0],DOMESTIC_BUSINESS_HOSTS[0]):
            changed=fixture()
            changed['rules']=[rule for rule in changed['rules'] if not rule.startswith('DOMAIN,'+host+',')]
            failed=render('business-all',changed)
            self.assertEqual(failed['$options']['_res']['status'],503)
            self.assertEqual(failed['$content'],'')

    def test_business_providers_follow_existing_route_and_block_scope(self):
        for part,domains in (('business-overseas',BUSINESS_CONSOLES),
                             ('business-cn',DOMESTIC_BUSINESS_HOSTS)):
            profile=fixture()
            output=render(part,profile)['$content'].splitlines()
            self.assertEqual(set(output),{'DOMAIN,'+domain for domain in domains})
            self.assertEqual(len(output),len(domains))
            for not_allowed in ('ms.applovin.com','a.applovin.com','www.googleadservices.com',
                                'frontend-perf-service.e.kuaishou.com','log-sdk.ksapisrv.com'):
                self.assertNotIn('DOMAIN,'+not_allowed,output)
            domain=domains[0]
            index=next(i for i,r in enumerate(profile['rules']) if r.startswith('DOMAIN,'+domain+','))
            profile['rules'][index]='DOMAIN,'+domain+',REJECT'
            failed=render(part,profile)
            self.assertEqual(failed['$options']['_res']['status'],503)
            self.assertEqual(failed['$content'],'')

    def test_applovin_console_provider_is_exact_and_fail_closed(self):
        profile=fixture()
        result=render('applovin-console',profile)
        self.assertEqual(set(result['$content'].splitlines()), {
            'DOMAIN,ads.applovin.com', 'DOMAIN,max.applovin.com',
            'DOMAIN,dash.applovin.com', 'DOMAIN,r.applovin.com',
            'DOMAIN,developers.applovin.com', 'DOMAIN,support.applovin.com',
        })
        self.assertNotIn('ms.applovin.com',result['$content'])
        profile['rules'].remove('DOMAIN,r.applovin.com,日常线路')
        failed=render('applovin-console',profile)
        self.assertEqual(failed['$options']['_res']['status'],503)
        self.assertEqual(failed['$content'],'')

    def test_all_rules_are_exported_in_order_without_targets(self):
        profile=fixture()
        names=['magic-dns','dns-block','dns-dot','priority-direct','priority-proxy',
               'china-console','foreign-console','dns-direct','dns-proxy-1','google-dns',
               'dns-proxy-2','telegram','ads','lan','ai','china-sites','overseas',
               'china-domains','china-ip','udp']
        actual=[]
        for name in names:
            out=render(name,profile)
            if name in ('ads','china-domains','china-ip'):
                self.assertEqual(out['$options']['_res']['status'],302)
                actual.append('RULE-SET,'+{'ads':'广告域名','china-domains':'国内域名','china-ip':'国内IP'}[name])
            else:
                self.assertNotIn('do-not-export',out['$content'])
                actual.extend(out['$content'].strip().splitlines())
        expected=[]
        for rule in profile['rules']:
            pieces=rule.split(',')
            if pieces[0]=='MATCH':continue
            expected.append(','.join(pieces[:2]+pieces[3:]))
        self.assertEqual(actual,expected)
        self.assertIn('IP-CIDR,100.100.100.100/32,no-resolve',actual)
        self.assertLess(actual.index('DOMAIN,ads.applovin.com'),actual.index('RULE-SET,广告域名'))

    def test_redirects_are_restricted(self):
        for name in ('ads','china-domains','china-ip'):
            self.assertEqual(render(name,fixture())['$options']['_res']['status'],302)
        p=fixture();p['rule-providers']['广告域名']['url']='https://bad.test/ads.mrs'
        out=render('ads',p)
        self.assertEqual(out['$options']['_res']['status'],503)
        self.assertEqual(out['$content'],'')

    def test_unrecognized_or_reordered_rules_fail_closed(self):
        p=fixture();p['rules'].insert(5,'DOMAIN,new.test,DIRECT')
        for part,profile in (('ai',p),('unknown',fixture())):
            out=render(part,profile)
            self.assertEqual(out['$options']['_res']['status'],503)
            self.assertEqual(out['$content'],'')

    def test_current_rule_additions_with_same_policy_propagate(self):
        p=fixture();i=p['rules'].index('DOMAIN-SUFFIX,chatgpt.com,AI线路')
        p['rules'].insert(i+1,'DOMAIN-SUFFIX,new-ai.example,AI线路')
        result=render('ai',p)['$content']
        self.assertIn('DOMAIN-SUFFIX,new-ai.example',result)

    def test_reordered_exact_console_host_keeps_every_part_usable(self):
        original=fixture()
        changed=fixture()
        rule='DOMAIN,r.applovin.com,日常线路'
        changed['rules'].remove(rule)
        changed['rules'].insert(changed['rules'].index('DOMAIN,developers.applovin.com,日常线路'),rule)
        for part in ('magic-dns','priority-proxy','china-console','foreign-console',
                     'business-all','ads','ai','china-domains','udp'):
            before=render(part,original)
            after=render(part,changed)
            self.assertEqual(after.get('$content'),before.get('$content'),part)
            self.assertEqual(after.get('$options',{}).get('_res'),before.get('$options',{}).get('_res'),part)

    def test_console_normalization_rejects_crossing_a_broad_rule(self):
        profile=fixture()
        rule='DOMAIN,r.applovin.com,日常线路'
        profile['rules'].remove(rule)
        index=profile['rules'].index('DOMAIN,developers.applovin.com,日常线路')
        profile['rules'][index:index]=[rule,'DOMAIN-SUFFIX,applovin.com,DIRECT']
        result=render('business-all',profile)
        self.assertEqual(result['$options']['_res']['status'],503)
        self.assertEqual(result['$content'],'')

    def test_shared_sanitized_source_and_error_response(self):
        source={'stash':fixture(),'clash':{'proxies':[{'password':'do-not-export'}]}}
        self.assertIn('chatgpt.com',render('ai',source)['$content'])
        result=render('unknown',source)
        self.assertEqual(result['$options']['_res']['status'],503)
        self.assertEqual(result['$content'],'')


if __name__=='__main__':unittest.main()
