import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from standalone_alias_routes import render, ROUTES


class StandaloneAliasTest(unittest.TestCase):
    def test_aliases_are_read_only_and_idempotent(self):
        original='# END STANDALONE RULE SHARES\n'
        result=render(original)
        self.assertTrue(result.startswith(original))
        self.assertEqual(render(result),result)
        self.assertEqual(ROUTES.count('not method GET'),2)
        self.assertNotIn('/api/',ROUTES)

    def test_unknown_alias_refused(self):
        with self.assertRaises(ValueError):
            render('# END STANDALONE RULE SHARES\n/rules/independent.stoverride')


if __name__ == '__main__':
    unittest.main()
