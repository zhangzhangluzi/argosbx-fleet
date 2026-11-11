import copy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import standard_provider_update as update


class RecoveryTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.journal=Path(self.temp.name)/'journal.json'
        self.journal.write_text('{}')
        self.files={update.source.SOURCE:{'content':'new'},update.PROVIDER:{'process':['new']},
                    'server-check-rule-update-temp':{},'unrelated':{}}
        self.calls=[]
        self.saved={'source_before':'old','source_after':'new','process_before':['old'],
                    'process_after':['new'],'temporary':['server-check-rule-update-temp']}

    def api(self,base,path,body=None,method=None):
        self.calls.append((path,method))
        if path=='/api/files':return [{'name':name} for name in self.files]
        if path.startswith('/api/wholeFile/'):
            return copy.deepcopy(self.files[path.rsplit('/',1)[-1]])
        if path.startswith('/api/file/'):
            name=path.rsplit('/',1)[-1]
            if method=='PATCH':self.files[name].update(body);return {}
            if method=='DELETE':del self.files[name];return {}
        raise AssertionError(path)

    def test_recovery_restores_source_then_operator_and_leaves_other_files(self):
        with patch.object(update,'JOURNAL',self.journal),patch.object(update.source,'api',side_effect=self.api):
            self.assertEqual(update.rollback('http://example.test',self.saved),{'rolled_back':True})
        self.assertEqual(self.files[update.source.SOURCE]['content'],'old')
        self.assertEqual(self.files[update.PROVIDER]['process'],['old'])
        self.assertIn('unrelated',self.files)
        self.assertNotIn('server-check-rule-update-temp',self.files)
        self.assertFalse(self.journal.exists())
        patches=[path for path,method in self.calls if method=='PATCH']
        self.assertEqual(patches,['/api/file/'+update.source.SOURCE,'/api/file/'+update.PROVIDER])

    def test_recovery_refuses_unrelated_concurrent_change(self):
        self.files[update.source.SOURCE]['content']='someone-else'
        with patch.object(update,'JOURNAL',self.journal),patch.object(update.source,'api',side_effect=self.api):
            with self.assertRaisesRegex(ValueError,'外部修改'):update.rollback('http://example.test',self.saved)
        self.assertTrue(self.journal.exists())
        self.assertEqual(self.files[update.PROVIDER]['process'],['new'])


if __name__=='__main__':unittest.main()
