import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import bestcf_pages


class WorkerPatchTests(unittest.TestCase):
    def test_only_authorized_subscriptions_are_intercepted(self):
        source = 'export default {\n\t\t\t\t\t\tconfig_JSON = await 读取config_JSON(env, host, userID, UA);\n}'
        result = bestcf_pages.patch(source)
        self.assertIn('if (用户客户端请求订阅)', result)
        self.assertIn('if (jpResult) return jpResult;', result)
        self.assertIn('config_JSON = await 读取config_JSON', result)

    def test_unexpected_worker_is_not_modified(self):
        with self.assertRaises(ValueError):
            bestcf_pages.patch('export default {}')


if __name__ == '__main__':
    unittest.main()
