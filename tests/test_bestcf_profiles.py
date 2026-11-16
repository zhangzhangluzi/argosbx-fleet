import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import bestcf_profiles as b


def file_object(code):
    return {'process':[{'type':'Script Operator','args':{'content':code}}]}


class BestCFProfilesTests(unittest.TestCase):
    def test_template_discards_old_ip_country_and_proxyip(self):
        uri=('vless://00000000-0000-4000-8000-000000000000@8.8.8.8:443?'
             'security=tls&type=ws&sni=edge.example&path=%2Fproxyip%3Dgermany.example#DE-T-old')
        new=b.source_template(uri)
        self.assertNotIn('8.8.8.8',new)
        self.assertNotIn('germany.example',new)
        self.assertNotIn('DE-T',new)
        self.assertIn('sni=edge.example',new)

    def test_country_mapping_keeps_japan_and_separates_self_hosted_nodes(self):
        old = (' const countryCodes={"日本":["JP"],"德国":["DE"]};\n'
               " const inCountry=(n,c)=>countryCodes[c].some(prefix=>n.startsWith(prefix+'-T-')||n.startsWith(prefix+'-U-'));\n"
               " const purpose='地区-德国';")
        result = b.mihomo_file(file_object(old))['process'][0]['args']['content']
        js = result + '\nconsole.log(JSON.stringify([inCountry("JP-T-v4-CF-自建-Mia-1","日本自建"),inCountry("JP-T-v4-CF-自建-Mia-1","日本"),inCountry("JP-T-v4-普通","日本")]));'
        self.assertEqual(json.loads(subprocess.check_output(['node','-e',js],text=True)), [True,False,True])
        self.assertIn('地区-日本自建', result)
        self.assertNotIn('地区-德国', result)

    def test_shadowrocket_profile_sets_fail_closed_and_disjoint_groups(self):
        old = (' const countries=[{"code":"JP","label":"日本"},{"code":"DE","label":"德国"}];\n'
               " const available=countries.filter(c=>nodes.some(p=>p.name.startsWith(c.code+'-')));\n"
               " const names=nodes.filter(p=>p.name.startsWith(c.code+'-'));\n"
               " const purpose='地区-德国';\n input.$options??={};")
        result = b.shadowrocket_file(file_object(old))['process'][0]['args']['content']
        self.assertIn('close-if-proxy-chain-missing = true', result)
        self.assertIn('地区-日本自建', result)
        self.assertIn('!isSelf(p)', result)

    def test_unexpected_template_is_rejected(self):
        with self.assertRaises(ValueError):
            b.mihomo_file(file_object('const unexpected=1;'))
        with self.assertRaises(ValueError):
            b.shadowrocket_file(file_object('const unexpected=1;'))

    def test_uri_adds_chain_only_when_upstream_exists(self):
        helper = (ROOT/'bestcf-shadowrocket.js').read_text()
        selfname = 'JP-T-v4-CF-自建-Mia-1'
        upname = 'CF入口-Mia-1'
        nodes = [{'name':upname}, {'name':selfname,'dialer-proxy':upname}]
        lines = ['vless://fixture@8.8.8.8:443?security=reality#' +
                 __import__('urllib.parse',fromlist=['quote']).quote(selfname),
                 'vless://fixture@1.1.1.1:443?security=tls#' +
                 __import__('urllib.parse',fromlist=['quote']).quote(upname)]
        js = ('const produceArtifact=async()=>'+json.dumps(nodes,ensure_ascii=False)+';\n'+helper+
              '\naddJapanChains('+json.dumps('\n'.join(lines))+',"fixture").then(x=>console.log(JSON.stringify(x)));')
        result = json.loads(subprocess.check_output(['node','-e',js],text=True))
        self.assertEqual(result.count('chain='), 1)
        self.assertIn('chain=CF%E5%85%A5%E5%8F%A3-Mia-1', result)

    def test_single_country_uri_does_not_leak_unrelated_nodes(self):
        helper = (ROOT/'bestcf-shadowrocket.js').read_text()
        nodes = [{'name':'CF入口-Mia-1'}, {'name':'JP-T-v4-CF-自建-Mia-1','dialer-proxy':'CF入口-Mia-1'}]
        from urllib.parse import quote
        names = ['CF入口-Mia-1','JP-T-v4-CF-自建-Mia-1','US-T-v4-other']
        body = '\n'.join('vless://fixture@1.1.1.1:443?security=tls#'+quote(x) for x in names)
        js = ('const produceArtifact=async()=>'+json.dumps(nodes,ensure_ascii=False)+';\n'+helper+
              '\naddJapanChains('+json.dumps(body)+',"fixture",true).then(x=>console.log(JSON.stringify(x)));')
        result = json.loads(subprocess.check_output(['node','-e',js],text=True))
        self.assertEqual(len(result.splitlines()),2)
        self.assertNotIn('US-T-v4-other',result)
        self.assertEqual(result.count('chain='),1)


if __name__ == '__main__':
    unittest.main()
