import json
from pathlib import Path
import subprocess
import sys
import unittest
from urllib.parse import quote

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import unified_external as u


SPEC={'sources':['external-hk','external-jp-cf'],
      'countries':{'香港':['HK'],'日本':['JP'],'日本自建':['JP']},
      'chain_source':'external-jp-cf'}
PROFILE='''function operator(input) {
 const source=ProxyUtils.yaml.safeLoad(input.$content);
 const proxies=source.proxies;
 const config={rules:['MATCH,日常线路']};
 config.proxies=proxies;
 const names=proxies.map(p=>p.name);
 const countryCodes={"日本":["JP"],"美国":["US"]};
 const inCountry=(n,c)=>countryCodes[c].some(prefix=>n.startsWith(prefix+'-T-')||n.startsWith(prefix+'-U-'));
 const countries=Object.keys(countryCodes).filter(c=>names.some(n=>inCountry(n,c)));
 const regions=countries.map(c=>'地区-'+c);
 config['proxy-groups']=[
  {name:'日常线路',type:'select',proxies:regions},
  {name:'AI线路',type:'select',proxies:['日常线路',...["地区-美国", "地区-日本"].filter(n=>regions.includes(n))]},
  {name:'Telegram',type:'select',proxies:['日常线路',...["地区-美国", "地区-日本"]].filter(n=>n==='日常线路'||regions.includes(n))},
  ...countries.map(c=>({name:'地区-'+c,type:'url-test',proxies:names.filter(n=>inCountry(n,c)),interval:1800}))
 ];
 input.$content=ProxyUtils.yaml.safeDump(config);
 return input;
}'''


def item(name,code):
    return {'name':name,'process':[{'type':'Script Operator','args':{'mode':'script','content':code}}]}


class UnifiedExternalTests(unittest.TestCase):
    def test_profile_adds_regions_without_mixing_japan_self(self):
        obj,countries,order=u.patch_profile(item('clash',PROFILE),SPEC['countries'])
        code=obj['process'][0]['args']['content']
        nodes=[{'name':x} for x in ('JP-T-v4-native','US-T-v4-native','HK-T-edge',
                                     'JP-T-v4-CF-自建-Mia-8.8.8.8-443','CF入口-Mia-8.8.8.8-443')]
        js=('const ProxyUtils={yaml:{safeLoad:x=>JSON.parse(x),safeDump:x=>JSON.stringify(x)}};\n'+code+
            '\nconsole.log(operator({$content:'+json.dumps(json.dumps({'proxies':nodes},ensure_ascii=False))+'}).$content);')
        groups={x['name']:x for x in json.loads(subprocess.check_output(['node','-e',js],text=True))['proxy-groups']}
        self.assertEqual(groups['地区-日本']['proxies'],['JP-T-v4-native'])
        self.assertEqual(groups['地区-日本自建']['proxies'],['JP-T-v4-CF-自建-Mia-8.8.8.8-443'])
        self.assertEqual(groups['地区-香港']['proxies'],['HK-T-edge'])
        self.assertEqual(groups['日常线路']['proxies'][0],'地区-日本')
        self.assertIn('地区-日本自建',groups['Telegram']['proxies'])
        self.assertEqual(countries['日本'],['JP'])

    def test_uri_chains_use_matching_entry_and_fail_closed(self):
        helper=(ROOT/'unified-shadowrocket.js').read_text()
        names=['CF入口-Mia-8.8.8.8-443','JP-T-v4-CF-自建-Mia-8.8.8.8-443','US-T-v4-native']
        lines=['vless://fixture@8.8.8.8:443#'+quote(name) for name in names]
        js=helper+'\nconsole.log(JSON.stringify(attachJapanChains('+json.dumps('\n'.join(lines))+')));'
        result=json.loads(subprocess.check_output(['node','-e',js],text=True))
        self.assertEqual(result.count('chain='),1)
        self.assertIn('chain=CF%E5%85%A5%E5%8F%A3-Mia-8.8.8.8-443',result)
        bad=helper+'\nattachJapanChains('+json.dumps(lines[1])+');'
        self.assertNotEqual(subprocess.run(['node','-e',bad],capture_output=True).returncode,0)

    def test_empty_external_chain_does_not_block_native_uri(self):
        helper=(ROOT/'unified-shadowrocket.js').read_text()
        js=helper+'\nconsole.log(attachJapanChains("vless://fixture@8.8.8.8:443#JP-T-native"));'
        self.assertIn('JP-T-native',subprocess.check_output(['node','-e',js],text=True))

    def test_shadowrocket_preserves_rules_and_closes_missing_chain(self):
        original={'name':'shadowrocket-config','source':'local',
                  'content':'[General]\nfoo = bar\n[Rule]\nFINAL,日常线路\n[Proxy Group]\nold = select, DIRECT\n'}
        obj=u.patch_shadowrocket(original,{'日本':['JP'],'日本自建':['JP']},['地区-日本','地区-日本自建'],1800)
        code=obj['process'][0]['args']['content']
        nodes=[{'name':'JP-T-v4-native'},{'name':'JP-T-v4-CF-自建-Mia-8.8.8.8-443'}]
        js=('const ProxyUtils={yaml:{safeLoad:x=>JSON.parse(x)}};\n'+code+
            '\nconsole.log(operator({$content:'+json.dumps(json.dumps({'proxies':nodes},ensure_ascii=False))+'}).$content);')
        text=subprocess.check_output(['node','-e',js],text=True)
        self.assertIn('FINAL,日常线路',text)
        self.assertIn('close-if-proxy-chain-missing = true',text)
        self.assertIn('地区-日本自建 = url-test, JP-T-v4-CF-自建-',text)
        self.assertIn('interval=1800',text)

    def test_unexpected_or_duplicate_sources_rejected(self):
        with self.assertRaises(ValueError):u.validate({**SPEC,'sources':['same','same']})
        with self.assertRaises(ValueError):u.patch_profile(item('clash','invalid'),SPEC['countries'])

    def test_apply_preserves_other_country_collections(self):
        response=(ROOT/'flclash-response-transformer.js').read_text()
        payload={'subscriptions':[],'collections':[{'name':'all','subscriptions':['native-jp'],
                    'process':[{'type':'Response Transformer','args':{'content':response,'arguments':{}}}]},
                    {'name':'shadowrocket-jp','subscriptions':['native-jp'],'process':[]}],
                 'files':[item('clash',PROFILE),item('stash',PROFILE),
                          {'name':'shadowrocket-config','source':'local','content':'[General]\n[Rule]\nFINAL,日常线路\n[Proxy Group]\n'}]}
        result=u.apply(payload,SPEC)
        self.assertEqual(result['collections'][0]['subscriptions'],['native-jp','external-hk','external-jp-cf'])
        self.assertEqual(result['collections'][0]['ignoreFailedRemoteSub'],'fallbackQuiet')
        self.assertEqual(result['collections'][1],payload['collections'][1])
        self.assertIn('attachJapanChains',result['collections'][0]['process'][0]['args']['content'])

    def test_dynamic_verification_allows_external_churn_but_not_policy_or_native_changes(self):
        import copy
        groups=[{'name':n,'type':'select','proxies':['JP-T-native']}
                for n in ('日常线路','AI线路','Telegram','去广告','开启去广告','关闭去广告')]
        groups.append({'name':'地区-日本','type':'url-test','proxies':['JP-T-native']})
        expected={'proxies':[{'name':'JP-T-native','port':443},{'name':'HK-T-old','port':443}],
                  'proxy-groups':groups,'rules':['MATCH,日常线路'],'dns':{'enable':True}}
        changed=copy.deepcopy(expected);changed['proxies'][1]={'name':'HK-T-new','port':443}
        u.check_dynamic_profile(changed,expected,['JP-T-native'])
        changed['dns']['enable']=False
        with self.assertRaises(ValueError):u.check_dynamic_profile(changed,expected,['JP-T-native'])
        changed=copy.deepcopy(expected);changed['proxies'][0]['port']=444
        with self.assertRaises(ValueError):u.check_dynamic_profile(changed,expected,['JP-T-native'])

    def test_shadowrocket_reference_verification(self):
        entry='CF入口-Mia-8.8.8.8-443';exit='JP-T-v4-CF-自建-Mia-8.8.8.8-443'
        valid='vless://fixture@8.8.8.8:443#'+quote(entry)+'\n'+'vless://fixture@8.8.8.8:443?chain='+quote(entry)+'#'+quote(exit)
        u.check_shadowrocket_chains(valid)
        with self.assertRaises(ValueError):u.check_shadowrocket_chains(valid.replace('?chain=','?ignored='))


if __name__=='__main__':unittest.main()
