import contextlib
import json
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

    def test_xray_apply_and_recovery_use_recorded_service_only(self):
        check = self.patch('service', return_value=self.owner)
        buffers.apply(unit='argosbx-reality443')
        self.assertEqual(json.loads(buffers.RECEIPT.read_text())['unit'], 'argosbx-reality443')
        self.assertEqual(buffers.recover()['restored_original_sockets'], 1)
        self.assertTrue(all(c.args == ('argosbx-reality443',) for c in check.call_args_list))
        self.assertEqual([s.receive for s in self.sockets], [212992, 16777216])

    def test_legacy_receipt_recovers_sb(self):
        buffers.apply()
        record = json.loads(buffers.RECEIPT.read_text())
        record.pop('unit')
        buffers.RECEIPT.write_text(json.dumps(record))
        check = self.patch('service', return_value=self.owner)
        self.assertEqual(buffers.recover()['restored_original_sockets'], 1)
        check.assert_called_once_with('sb')

    def test_unsupported_service_never_changes_default(self):
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            buffers.apply(unit='ssh')
        self.assertEqual(buffers.SYSCTL.read_text(), '212992')
        self.assertFalse(buffers.JOURNAL.exists())

    def test_new_host_initializes_without_a_running_service(self):
        buffers.LIMIT.write_text('212992')
        service = self.patch('service', side_effect=AssertionError('no service yet'))
        result = buffers.initialize_defaults()
        self.assertTrue(result['verified'])
        self.assertEqual(result['effective_receive'], 2097152)
        self.assertEqual(result['maximum'], 2097152)
        self.assertIn('net.core.rmem_max = 2097152', buffers.PERSIST.read_text())
        service.assert_not_called()
        receipt = buffers.RECEIPT.read_bytes()
        self.assertFalse(buffers.initialize_defaults()['changed'])
        self.assertEqual(receipt, buffers.RECEIPT.read_bytes())

    def test_new_host_preserves_larger_defaults_and_limits(self):
        buffers.SYSCTL.write_text('4194304')
        result = buffers.initialize_defaults()
        self.assertEqual(result['effective_receive'], 4194304)
        self.assertEqual(result['maximum'], 16777216)
        self.assertEqual(buffers.verify_defaults()['effective_receive'], 4194304)

    def test_new_host_failed_validation_restores_default_limit_and_file(self):
        buffers.LIMIT.write_text('212992')
        buffers.PERSIST.write_text('# previous\n')
        buffers.PERSIST.chmod(0o640)
        before = buffers.snapshot_file()
        self.patch('verify_defaults', side_effect=RuntimeError('injected validation failure'))
        with self.assertRaisesRegex(RuntimeError, 'injected'):
            buffers.initialize_defaults()
        self.assertEqual(int(buffers.SYSCTL.read_text()), 212992)
        self.assertEqual(int(buffers.LIMIT.read_text()), 212992)
        self.assertEqual(buffers.snapshot_file(), before)
        self.assertFalse(buffers.JOURNAL.exists())

    def test_new_host_recovery_restores_maximum_without_service_access(self):
        buffers.LIMIT.write_text('212992')
        buffers.initialize_defaults()
        service = self.patch('service', side_effect=AssertionError('no service'))
        result = buffers.recover()
        service.assert_not_called()
        self.assertEqual(result['default'], 212992)
        self.assertEqual(result['maximum'], 212992)
        self.assertFalse(buffers.PERSIST.exists())

    def test_new_host_recovery_does_not_clobber_external_limit_change(self):
        buffers.initialize_defaults()
        buffers.LIMIT.write_text('33554432')
        with self.assertRaisesRegex(RuntimeError, 'maximum changed externally'):
            buffers.recover()
        self.assertEqual(int(buffers.SYSCTL.read_text()), 2097152)
        self.assertTrue(buffers.RECEIPT.exists())

    def test_live_tuning_preserves_initialized_limit_persistence(self):
        buffers.initialize_defaults()
        buffers.apply()
        self.assertIn('net.core.rmem_max = 16777216', buffers.PERSIST.read_text())
        self.assertTrue(buffers.verify_defaults()['verified'])

    def test_missing_or_insufficient_persistence_is_not_accepted(self):
        buffers.initialize_defaults()
        buffers.PERSIST.write_text('net.core.rmem_default = 212992\n')
        with self.assertRaisesRegex(RuntimeError, 'did not verify'):
            buffers.verify_defaults()


class ServiceIdentity(unittest.TestCase):
    def test_xray_unit_requires_expected_executable(self):
        owner = {'pid': 42, 'start': '123', 'boot': 'test'}
        with patch.object(buffers.subprocess, 'check_output', return_value='42\n') as query, \
             patch.object(buffers, 'identity', return_value=owner), \
             patch.object(Path, 'resolve', autospec=True,
                          side_effect=lambda p: Path('/root/agsbx/xray') if str(p)=='/proc/42/exe' else p):
            self.assertEqual(buffers.service('argosbx-reality443'), owner)
            query.assert_called_once_with(
                ['systemctl', 'show', 'argosbx-reality443', '-p', 'MainPID', '--value'], text=True)
            with self.assertRaisesRegex(RuntimeError, 'expected running sing-box'):
                buffers.service('sb')

    def test_arbitrary_units_are_rejected_before_systemctl(self):
        with patch.object(buffers.subprocess, 'check_output') as query:
            with self.assertRaisesRegex(ValueError, 'unsupported'):
                buffers.service('ssh')
            query.assert_not_called()


class BootstrapBufferPolicy(unittest.TestCase):
    def test_initialization_failure_prevents_service_install_and_export(self):
        import bootstrap
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(bootstrap, 'JOURNAL', Path(temp)/'bootstrap.json'), \
             patch.object(buffers, 'HOME', Path(temp)), \
             patch.object(bootstrap, 'preflight'), \
             patch.object(buffers, 'initialize_defaults', side_effect=RuntimeError('buffer validation failed')), \
             patch.object(bootstrap, 'run') as run, \
             patch.object(bootstrap.agent, 'export_source') as export:
            with self.assertRaisesRegex(RuntimeError, 'buffer validation failed'):
                bootstrap.install({}, 'test-only')
            run.assert_not_called()
            export.assert_not_called()

    def test_completed_legacy_install_is_not_automatically_retuned(self):
        import bootstrap
        import json
        server = {'protocols': {}, 'onboarding': {'certificate_host': 'test.example.com'},
                  'subscription': {'url': 'https://test.example.com:8443/'+'a'*32},
                  'certificates': {'domain': {'certificate_file': '/test/cert', 'key_file': '/test/key'}}}
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(bootstrap, 'JOURNAL', Path(temp)/'bootstrap.json'), \
             patch.object(bootstrap, 'preflight'), \
             patch.object(bootstrap, 'run'), \
             patch.object(buffers, 'initialize_defaults') as initialize, \
             patch.object(buffers, 'apply') as apply, \
             patch.object(buffers, 'verify_defaults') as verify, \
             patch.object(bootstrap.agent, 'load', return_value={}), \
             patch.object(bootstrap.agent, 'certificate_health', return_value={}), \
             patch.object(bootstrap.agent, 'export_source', return_value={}):
            bootstrap.JOURNAL.write_text(json.dumps({'server': server, 'phase': 4}))
            result = bootstrap.install(server, 'test-only')
            self.assertEqual(result['udp_buffers']['status'], 'legacy-install-unchanged')
            initialize.assert_not_called()
            apply.assert_not_called()
            verify.assert_not_called()


if __name__ == '__main__':
    unittest.main()
