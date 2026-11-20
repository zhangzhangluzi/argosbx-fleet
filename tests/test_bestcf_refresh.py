import sys
import unittest
from pathlib import Path
import yaml

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import bestcf_refresh as b


class RefreshTests(unittest.TestCase):
    def test_token_must_be_unique(self):
        good={'name':'external-seven','type':'col','token':'fixture'}
        self.assertEqual(b.token_for_collection({'tokens':[good]}),'fixture')
        with self.assertRaises(ValueError):b.token_for_collection({'tokens':[good,good]})
        with self.assertRaises(ValueError):b.token_for_collection({'tokens':[]})

    def test_nodes_and_references_are_checked(self):
        entries=[{'name':'CF入口-Mia-1'},{'name':'CF入口-Qilin-1'}]
        exits=[{'name':label,'dialer-proxy':'CF入口-'+source+'-1','reality-opts':{'public-key':'fixture'}}
               for source,label in [('Mia','Mia优选 | TW'),('Qilin','麒麟优选 | 电信')]]
        data={'proxies':entries+exits,'proxy-groups':[{'name':'地区-日本自建','interval':1800,
                                                     'proxies':[p['name'] for p in exits]}]}
        self.assertEqual(b.check(yaml.safe_dump(data,allow_unicode=True)),(2,2))
        data['proxies']=entries[:1]+exits[:1]
        data['proxy-groups'][0]['proxies']=[exits[0]['name']]
        self.assertEqual(b.check(yaml.safe_dump(data,allow_unicode=True)),(1,1))
        del exits[0]['dialer-proxy']
        with self.assertRaises(ValueError):b.check(yaml.safe_dump(data,allow_unicode=True))

    def test_accepts_single_t26_route_but_rejects_legacy_path_and_reality(self):
        host='alllllcccd.pages.dev'
        node={'name':'原名','type':'vless','network':'ws','tls':True,'servername':host,
              'ws-opts':{'path':'/','headers':{'Host':host}}}
        doc={'proxies':[node],'proxy-groups':[{'name':'地区-日本自建','interval':1800,'proxies':['原名']}]}
        self.assertEqual(b.check(yaml.safe_dump(doc)),(1,1))
        node['ws-opts']['path']='/proxyip=old.example'
        with self.assertRaises(ValueError):b.check(yaml.safe_dump(doc))
        node['ws-opts']['path']='/'
        node['reality-opts']={}
        with self.assertRaises(ValueError):b.check(yaml.safe_dump(doc))


if __name__=='__main__': unittest.main()
