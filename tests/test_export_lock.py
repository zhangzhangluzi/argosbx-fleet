import contextlib
import io
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import agent
from storage import lock


class ExportLockTests(unittest.TestCase):
    def test_waiting_export_can_acquire_after_competing_transaction(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'agent.lock'
            entered = threading.Event()
            errors = []
            def attempt():
                try:
                    with lock(path, timeout=1):
                        entered.set()
                except Exception as error:
                    errors.append(error)
            with lock(path):
                thread = threading.Thread(target=attempt)
                thread.start()
                self.assertFalse(entered.wait(.08))
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertFalse(errors)
            self.assertTrue(entered.is_set())

    def test_wait_is_bounded_and_unrelated_calls_remain_immediate(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'agent.lock'
            with lock(path):
                start = time.monotonic()
                with self.assertRaisesRegex(RuntimeError, '另一个维护事务正在运行'):
                    with lock(path, timeout=.05):
                        self.fail('must not obtain an owned lock')
                self.assertGreaterEqual(time.monotonic() - start, .04)
                start = time.monotonic()
                with self.assertRaisesRegex(RuntimeError, '另一个维护事务正在运行'):
                    with lock(path):
                        self.fail('must not obtain an owned lock')
                self.assertLess(time.monotonic() - start, .5)

    def test_only_export_requests_wait(self):
        for command, expected in [('export', 30), ('plan', 0)]:
            with self.subTest(command=command), \
                 patch('sys.argv', ['agent.py', command]), \
                 patch('sys.stdin', io.StringIO('{}')), \
                 patch('sys.stdout', io.StringIO()), \
                 patch('agent.lock', return_value=contextlib.nullcontext()) as mocked_lock, \
                 patch('agent.export_source', return_value={}), \
                 patch('agent.plan', return_value={}):
                agent.main()
                mocked_lock.assert_called_once_with(agent.HOME / 'agent.lock', timeout=expected)

    def test_invalid_timeout_fails_without_waiting(self):
        with tempfile.TemporaryDirectory() as folder:
            for value in (-1, float('nan'), float('inf'), True, '30'):
                with self.subTest(timeout=value), self.assertRaises(ValueError):
                    with lock(Path(folder) / 'agent.lock', timeout=value):
                        self.fail('invalid timeout must not acquire a lock')


if __name__ == '__main__':
    unittest.main()
