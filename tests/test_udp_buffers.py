import contextlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import udp_buffers as buffers


class Datagram:
    def __init__(self, receive):
        self.receive, self.send = receive, 212992

    def setsockopt(self, level, option, value):
        assert option == buffers.socket.SO_RCVBUF
        self.receive = value * 2

    def getsockopt(self, level, option):
        return self.receive if option == buffers.socket.SO_RCVBUF else self.send


class BufferTransaction(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        for name in ('SYSCTL', 'LIMIT', 'PERSIST', 'JOURNAL', 'RECEIPT'):
            patcher = patch.object(buffers, name, root / name)
            patcher.start()
            self.addCleanup(patcher.stop)
        buffers.SYSCTL.write_text('212992')
        buffers.LIMIT.write_text('16777216')
        self.owner = {'pid': 42, 'start': '123', 'boot': 'test'}
        self.sockets = [Datagram(212992), Datagram(16777216)]
        self.patch('service', return_value=self.owner)
        self.patch('fresh_default', side_effect=lambda: int(buffers.SYSCTL.read_text()))
        self.patch('udp_sockets', side_effect=self.scan)

    def patch(self, name, **kwargs):
        patcher = patch.object(buffers, name, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    @contextlib.contextmanager
    def scan(self, pid):
        yield [(s, {'fd': i + 3, 'inode': i + 100, 'family': 2, 'port': 8443 + i,
                    'receive': s.receive, 'send': s.send}) for i, s in enumerate(self.sockets)]

    def test_apply_preserves_larger_buffer_and_send_then_idempotent(self):
        result = buffers.apply()
        self.assertEqual([s.receive for s in self.sockets], [2097152, 16777216])
        self.assertEqual([s.send for s in self.sockets], [212992, 212992])
        self.assertEqual(len(result['adjusted']), 1)
        self.assertEqual(buffers.PERSIST.stat().st_mode & 0o777, 0o644)
        receipt = buffers.RECEIPT.read_bytes()
        self.assertFalse(buffers.apply()['changed'])
        self.assertEqual(buffers.RECEIPT.read_bytes(), receipt)
        self.assertFalse(buffers.JOURNAL.exists())

    def test_failed_readback_restores_values_and_owned_file(self):
        buffers.PERSIST.write_text('# existing\n')
        buffers.PERSIST.chmod(0o640)
        before, real = buffers.snapshot_file(), buffers.set_receive
        calls = 0
        def fail_once(sock, value):
            nonlocal calls
            calls += 1
            real(sock, value)
            if calls == 1:
                raise RuntimeError('injected readback failure')
        self.patch('set_receive', side_effect=fail_once)
        with self.assertRaisesRegex(RuntimeError, 'injected'):
            buffers.apply()
        self.assertEqual(self.sockets[0].receive, 212992)
        self.assertEqual(int(buffers.SYSCTL.read_text()), 212992)
        self.assertEqual(buffers.snapshot_file(), before)
        self.assertFalse(buffers.JOURNAL.exists())

    def test_missing_pidfd_permission_aborts_before_any_write(self):
        self.patch('udp_sockets', side_effect=PermissionError('pidfd denied'))
        with self.assertRaises(PermissionError):
            buffers.apply()
        self.assertEqual(buffers.SYSCTL.read_text(), '212992')
        self.assertFalse(buffers.JOURNAL.exists())
        self.assertFalse(buffers.PERSIST.exists())

    def test_process_change_before_apply_aborts(self):
        self.patch('service', side_effect=[self.owner, {**self.owner, 'start': '456'}])
        with self.assertRaisesRegex(RuntimeError, 'before apply'):
            buffers.apply()
        self.assertEqual(self.sockets[0].receive, 212992)
        self.assertFalse(buffers.JOURNAL.exists())

    def test_process_change_during_apply_rolls_back(self):
        self.patch('service', side_effect=[self.owner, self.owner, {**self.owner, 'start': '456'}])
        with self.assertRaisesRegex(RuntimeError, 'during apply'):
            buffers.apply()
        self.assertEqual(self.sockets[0].receive, 212992)
        self.assertEqual(int(buffers.SYSCTL.read_text()), 212992)
        self.assertFalse(buffers.PERSIST.exists())

    def test_recovery_matches_inode_not_reused_fd(self):
        buffers.apply()
        @contextlib.contextmanager
        def reused(pid):
            with self.scan(pid) as entries:
                entries[0][1]['inode'] = 999
                yield entries
        self.patch('udp_sockets', side_effect=reused)
        result = buffers.recover()
        self.assertEqual(result['restored_original_sockets'], 0)
        self.assertEqual(self.sockets[0].receive, 2097152)
        self.assertEqual(int(buffers.SYSCTL.read_text()), 212992)
        self.assertFalse(buffers.PERSIST.exists())

    def test_recovery_will_not_overwrite_external_edit(self):
        buffers.apply()
        buffers.PERSIST.write_text('net.core.rmem_default = 4194304\n')
        with self.assertRaisesRegex(RuntimeError, 'changed externally'):
            buffers.recover()
        self.assertEqual(self.sockets[0].receive, 2097152)
        self.assertTrue(buffers.RECEIPT.exists())

    def test_recovery_with_stopped_process_restores_only_default(self):
        buffers.apply()
        self.patch('service', side_effect=RuntimeError('stopped'))
        self.assertEqual(buffers.recover()['restored_original_sockets'], 0)
        self.assertEqual(int(buffers.SYSCTL.read_text()), 212992)
        self.assertEqual(self.sockets[0].receive, 2097152)

    def test_recovery_rejects_reused_pid_identity(self):
        buffers.apply()
        self.patch('service', return_value={**self.owner, 'start': '456'})
        self.assertEqual(buffers.recover()['restored_original_sockets'], 0)
        self.assertEqual(self.sockets[0].receive, 2097152)

    def test_failed_rollback_retains_recovery_record(self):
        self.patch('set_receive', side_effect=OSError('cannot set buffer'))
        with self.assertRaisesRegex(RuntimeError, 'rollback incomplete'):
            buffers.apply()
        self.assertTrue(buffers.JOURNAL.exists())
        self.assertEqual(int(buffers.SYSCTL.read_text()), 212992)

    def test_recover_restores_original_socket_and_default(self):
        buffers.apply()
        self.assertEqual(buffers.recover()['restored_original_sockets'], 1)
        self.assertEqual(self.sockets[0].receive, 212992)
        self.assertEqual(int(buffers.SYSCTL.read_text()), 212992)
        self.assertFalse(buffers.RECEIPT.exists())

    def test_reject_shrinking_default_and_invalid_sizes(self):
        for value in (True, 4096, 65537, 33554432):
            with self.assertRaises(ValueError):
                buffers.apply(value)
        buffers.SYSCTL.write_text('4194304')
        with self.assertRaisesRegex(RuntimeError, 'lower'):
            buffers.apply()
        self.assertFalse(buffers.JOURNAL.exists())

    def test_pending_transaction_prevents_overwriting_recovery(self):
        buffers.JOURNAL.write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'unfinished'):
            buffers.apply()
        self.assertEqual(buffers.JOURNAL.read_text(), '{}')


if __name__ == '__main__':
    unittest.main()
