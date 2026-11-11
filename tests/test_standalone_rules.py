import json
from pathlib import Path
import subprocess
import unittest


SCRIPT = (Path(__file__).parents[1] / 'templates' / 'standalone-rules.js').read_text()


def render(client, profile):
    script = SCRIPT.replace('STANDALONE_FORMAT', client)
    node = r'''
      const fs = require('fs'), vm = require('vm');
      const x = JSON.parse(fs.readFileSync(0, 'utf8'));
      const input = {$content:JSON.stringify(x.profile)};
      const ctx = {input,ProxyUtils:{yaml:{safeLoad:JSON.parse,safeDump:JSON.stringify}}};
      vm.createContext(ctx);
      vm.runInContext(x.script + '\noperator(input);', ctx);
      process.stdout.write(input.$content);
    '''
    return subprocess.check_output(['node', '-e', node], input=json.dumps(
        {'script':script, 'profile':profile}, ensure_ascii=False), text=True)


def apply(script, profile):
    node = r'''
      const fs = require('fs'),vm = require('vm');
      const x = JSON.parse(fs.readFileSync(0,'utf8'));
      const ctx = {config:x.profile}; vm.createContext(ctx);
      vm.runInContext(x.script + '\nconfig = main(config);', ctx);
      process.stdout.write(JSON.stringify(ctx.config));
    '''
    return json.loads(subprocess.check_output(['node', '-e', node], input=json.dumps(
        {'script':script, 'profile':profile}, ensure_ascii=False), text=True, stderr=subprocess.PIPE))


def fixture(client):
    providers = {}
    for name, behavior in [('国内域名','domain'),('国内IP','ipcidr'),('广告域名','domain')]:
        providers[name] = {'type':'http','behavior':behavior,'format':'mrs',
                           'url':'https://rules.example/'+behavior+'.mrs', 'interval':86400,
                           'path':'./ruleset/'+behavior+'.mrs'}
        if client == 'clash': providers[name]['proxy'] = '日常线路'
    return {'proxies':[{'name':'PRIVATE-CREDENTIALS','password':'never-export'}],
            'rule-providers':providers,
            'rules':['DST-PORT,53,REJECT','DST-PORT,853,日常线路',
                     'DOMAIN,ads.applovin.com,日常线路',
                     'RULE-SET,广告域名,去广告','DOMAIN-SUFFIX,grok.com,AI线路',
                     'DOMAIN-SUFFIX,telegram.org,Telegram',
                     'RULE-SET,国内域名,DIRECT','RULE-SET,国内IP,DIRECT',
                     'NETWORK,UDP,日常线路','MATCH,日常线路']}


class StandaloneRulesTest(unittest.TestCase):
    def test_stash_overlay_retains_order_and_excludes_credentials(self):
        result = json.loads(render('stash', fixture('stash')))
        self.assertNotIn('proxies', result)
        self.assertNotIn('never-export', json.dumps(result))
        self.assertEqual(result['rules'][0], 'DOMAIN,ads.applovin.com,独立规则·日常线路')
        self.assertEqual(result['rules'][1], 'RULE-SET,独立规则·广告域名,独立规则·去广告')
        self.assertFalse(any(r.startswith(('MATCH,','DST-PORT,53,','DST-PORT,853,')) for r in result['rules']))
        groups = {x['name']:x for x in result['proxy-groups']}
        self.assertEqual(groups['独立规则·自动节点']['interval'], 1800)
        self.assertTrue(groups['独立规则·自动节点']['include-all'])
        self.assertEqual(groups['独立规则·自动节点']['proxies'], ['REJECT'])
        self.assertEqual(groups['独立规则·关闭去广告']['proxies'], ['独立规则·日常线路'])
        self.assertEqual(len(result['rule-providers']),3)

    def test_clash_script_preserves_base_and_fallback(self):
        script = render('clash', fixture('clash'))
        self.assertNotIn('never-export', script)
        base={'proxies':[{'name':'Existing','type':'direct'}],
              'proxy-groups':[{'name':'Existing group','type':'select','proxies':['Existing']}],
              'rules':['DOMAIN,base.example,DIRECT','MATCH,Existing group'],
              'dns':{'enable':True,'nameserver':['system']},'mode':'rule'}
        result=apply(script,base)
        self.assertEqual(result['proxies'],base['proxies'])
        self.assertEqual(result['dns'],base['dns'])
        self.assertEqual(result['rules'][-2:],base['rules'])
        self.assertEqual(result['rules'][0],'DOMAIN,ads.applovin.com,独立规则·日常线路')
        groups={g['name']:g for g in result['proxy-groups']}
        self.assertEqual(groups['独立规则·关闭去广告']['proxies'],['PASS'])
        self.assertEqual(result['rule-providers']['独立规则·国内IP']['proxy'],'独立规则·日常线路')
        self.assertTrue(result['rule-providers']['独立规则·国内IP']['path'].endswith('standalone-cn-ip.mrs'))

    def test_current_profile_changes_flow_to_both_clients(self):
        for client in ('stash','clash'):
            p=fixture(client)
            p['rules'].insert(3, 'DOMAIN,new.example,AI线路')
            p['rule-providers']['广告域名']['url']='https://rules.example/new-ads.mrs'
            output=render(client,p)
            self.assertIn('DOMAIN,new.example,独立规则·AI线路',output)
            self.assertIn('https://rules.example/new-ads.mrs',output)

    def test_conflicting_existing_names_are_rejected_in_clash(self):
        script=render('clash',fixture('clash'))
        with self.assertRaises(subprocess.CalledProcessError):
            apply(script,{'proxy-groups':[{'name':'独立规则·日常线路'}]})

    def test_source_error_never_returns_raw_profile(self):
        self.assertEqual(render('stash',{'proxies':[{'password':'do-not-export'}]}),'')

    def test_shared_sanitized_source_selects_the_right_client(self):
        stash=fixture('stash');clash=fixture('clash')
        stash['rules'].insert(3,'DOMAIN,stash-only.example,DIRECT')
        clash['rules'].insert(3,'DOMAIN,clash-only.example,DIRECT')
        source={'stash':stash,'clash':clash}
        self.assertIn('stash-only.example',render('stash',source))
        self.assertNotIn('clash-only.example',render('stash',source))
        self.assertIn('clash-only.example',render('clash',source))


if __name__ == '__main__':
    unittest.main()
