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
        exits=[{'name':'JP-T-v4-CF-自建-'+source+'-1','dialer-proxy':'CF入口-'+source+'-1',
                'reality-opts':{'public-key':'fixture'}} for source in ('Mia','Qilin')]
        data={'proxies':entries+exits,'proxy-groups':[{'name':'地区-日本自建','interval':1800}]}
        self.assertEqual(b.check(yaml.safe_dump(data,allow_unicode=True)),(2,2))
        del exits[0]['dialer-proxy']
        with self.assertRaises(ValueError):b.check(yaml.safe_dump(data,allow_unicode=True))


if __name__=='__main__': unittest.main()
