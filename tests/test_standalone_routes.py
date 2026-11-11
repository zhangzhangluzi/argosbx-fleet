import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from standalone_routes import render, ROUTES


class StandaloneRoutesTest(unittest.TestCase):
    def test_idempotent_and_existing_routes_unchanged(self):
        before = '# BEGIN EXTERNAL SEVEN SHARES\n# END EXTERNAL SEVEN SHARES\n'
        after = render(before)
        self.assertTrue(after.startswith(before))
        self.assertIn(ROUTES, after)
        self.assertEqual(render(after), after)
        self.assertNotIn('/api/', ROUTES)
        self.assertIn('not method GET', ROUTES)

    def test_unknown_conflicts_refused(self):
        for value in ('', '# END EXTERNAL SEVEN SHARES\n/share/file/standalone-stash',
                      '# END EXTERNAL SEVEN SHARES\n# BEGIN STANDALONE RULE SHARES'):
            with self.assertRaises(ValueError): render(value)


if __name__ == '__main__':
    unittest.main()
