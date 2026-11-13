import copy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import fleet
import onboard


class OneClickOnboardingTests(unittest.TestCase):
    def args(self, address='192.0.2.42'):
        return ['onboard.py', 'add-install', '--config', '/tmp/fixture-servers.json',
                '--server', 'jp2', '--country', 'JP', '--country-name', '日本',
                '--ipv4', address, '--zone', 'example.com', '--ssh-key', '/tmp/key',
                '--known-hosts', '/tmp/known-hosts']

    def test_add_and_install_in_one_command(self):
        config = {'servers': [], 'purpose_order': []}
        with patch.object(sys, 'argv', self.args()), patch.dict('os.environ', {}, clear=False), \
                patch.object(onboard, 'read', return_value=config), \
                patch.object(onboard.Cloudflare, 'from_config', return_value=object()), \
                patch.object(onboard.tunnels, 'discover'), patch.object(fleet, 'validate'), \
                patch.object(onboard, 'save') as save, \
                patch.object(onboard, 'install', return_value={'publication': 'ok'}) as install:
            result = onboard.main()
        self.assertFalse(result['resumed'])
        self.assertEqual(config['servers'][0]['status'], 'pending')
        save.assert_called_once()
        install.assert_called_once_with(config, 'jp2')

    def test_retry_resumes_matching_pending_server_and_rejects_conflict(self):
        server = onboard.defaults('jp2', 'JP', '日本', '192.0.2.42', None,
                                  'example.com', '/tmp/key', '/tmp/known-hosts')
        config = {'servers': [server], 'purpose_order': ['JP']}
        with patch.object(sys, 'argv', self.args()), patch.dict('os.environ', {}, clear=False), \
                patch.object(onboard, 'read', return_value=config), \
                patch.object(onboard, 'install', return_value={'publication': 'ok'}) as install:
            self.assertTrue(onboard.main()['resumed'])
            install.assert_called_once_with(config, 'jp2')
        with patch.object(sys, 'argv', self.args('192.0.2.43')), patch.dict('os.environ', {}, clear=False), \
                patch.object(onboard, 'read', return_value=copy.deepcopy(config)), \
                patch.object(onboard, 'install') as install, self.assertRaises(ValueError):
            onboard.main()
        install.assert_not_called()

    def test_retry_of_active_server_does_not_run_install(self):
        server = onboard.defaults('jp2', 'JP', '日本', '192.0.2.42', None,
                                  'example.com', '/tmp/key', '/tmp/known-hosts')
        server['status'] = 'active'
        with patch.object(sys, 'argv', self.args()), patch.dict('os.environ', {}, clear=False), \
                patch.object(onboard, 'read', return_value={'servers': [server]}), \
                patch.object(onboard, 'install') as install:
            self.assertTrue(onboard.main()['already_active'])
        install.assert_not_called()

    def test_active_server_with_pending_publication_resumes_transaction(self):
        server = onboard.defaults('jp2', 'JP', '日本', '192.0.2.42', None,
                                  'example.com', '/tmp/key', '/tmp/known-hosts')
        server['status'] = 'active'
        with tempfile.TemporaryDirectory() as directory:
            pending = Path(directory)/'onboarding.json'
            pending.write_text('{}')
            with patch.object(sys, 'argv', self.args()), patch.dict('os.environ', {}, clear=False), \
                    patch.object(onboard, 'PUBLICATION', pending), \
                    patch.object(onboard, 'read', return_value={'servers': [server]}), \
                    patch.object(onboard, 'install', return_value={'published': True}) as install:
                self.assertTrue(onboard.main()['resumed'])
            install.assert_called_once()


if __name__ == '__main__':
    unittest.main()
