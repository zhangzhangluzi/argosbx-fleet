import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from standard_provider_routes import ROUTES,render

class StandardProviderRoutesTest(unittest.TestCase):
    def test_scope_and_idempotence(self):
        before='# END EXTERNAL SEVEN SHARES\n'
        after=render(before)
        self.assertTrue(after.startswith(before))
        self.assertEqual(render(after),after)
        self.assertEqual(ROUTES.count('not method GET'),2)
        self.assertNotIn('/api/',ROUTES)

    def test_reject_conflicts(self):
        for text in ('','# END EXTERNAL SEVEN SHARES\n/rules/providers/process.txt',
                     '# END EXTERNAL SEVEN SHARES\n# BEGIN STANDARD RULE PROVIDERS'):
            with self.assertRaises(ValueError):render(text)

if __name__=='__main__':unittest.main()
