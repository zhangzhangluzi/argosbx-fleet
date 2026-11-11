import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import probe


class ProbeDnsTest(unittest.TestCase):
    def test_hostname_probe_uses_observer_dns_without_changing_proxy_identity(self):
        node={'type':'anytls','server':'jp4.example.test','port':443,
              'password':'fixture-only','sni':'jp.example.test'}
        config=probe.singbox_client(node,23456)
        self.assertEqual(config['dns']['servers'][0],{'type':'local','tag':'local'})
        self.assertEqual(config['route']['default_domain_resolver'],'local')
        self.assertEqual(config['outbounds'][0]['server'],node['server'])
        self.assertEqual(config['outbounds'][0]['tls']['server_name'],node['sni'])
        self.assertEqual(config['inbounds'][0]['listen'],'127.0.0.1')
        self.assertNotIn('tun',str(config).lower())


if __name__=='__main__':unittest.main()
