import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import publication
from storage import save


class PublicationNullRollbackTests(unittest.TestCase):
    def test_restores_legacy_shadowrocket_and_collection_with_merged_patch(self):
        cfg={'subscription':{'backend_url':'https://example.invalid'}}
        digest=lambda x:hashlib.sha256(json.dumps(x,sort_keys=True).encode()).hexdigest()
        items=[{'kind':'file','name':'shadowrocket-config',
                'before':{'name':'shadowrocket-config','source':'local','content':'old','process':[]},
                'after':{'name':'shadowrocket-config','source':'local','content':'old','type':'mihomoConfig',
                         'sourceType':'collection','sourceName':'all','process':[{'type':'Script Operator'}]}},
               {'kind':'collection','name':'all',
                'before':{'name':'all','subscriptions':['native'],'process':[]},
                'after':{'name':'all','subscriptions':['native','external'],'process':[],
                         'ignoreFailedRemoteSub':'fallbackQuiet'}}]
        live={(x['kind'],x['name']):dict(x['after']) for x in items}
        def get(_cfg,kind,name):return live.get((kind,name))
        def request(_cfg,path,value=None,method=None,**_):
            kind,name=path.split('/')[-2:]
            live[(kind,name)].update(value)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'journal.json';save(path,{'backend_sha256':digest(cfg['subscription']['backend_url']),
                                                          'attempted':items,'temporary':[]})
            result=publication.recover(path,cfg,get,request,digest)
            self.assertTrue(result['recovered']);self.assertFalse(path.exists())
        for item in items:self.assertTrue(publication.restored_equivalent(live[(item['kind'],item['name'])],item))

    def test_unrelated_extra_fields_are_not_silently_accepted(self):
        item={'kind':'collection','name':'all','before':{'name':'all'},
              'after':{'name':'all','ignoreFailedRemoteSub':'fallbackQuiet'}}
        self.assertTrue(publication.restored_equivalent({'name':'all','ignoreFailedRemoteSub':None},item))
        self.assertFalse(publication.restored_equivalent({'name':'all','ignoreFailedRemoteSub':None,'other':None},item))


if __name__=='__main__':unittest.main()
