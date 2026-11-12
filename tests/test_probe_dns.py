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

    def test_observer_ech_bootstrap_does_not_depend_on_mainland_doh(self):
        node={'type':'vless','network':'xhttp','server':'edge.example.test','port':443,
              'uuid':'fixture-only','encryption':'fixture-only','tls':True,'servername':'edge.example.test',
              'xhttp-opts':{'path':'/fixture','mode':'packet-up','host':'edge.example.test'},
              'ech-opts':{'enable':True,'query-server-name':'cloudflare-ech.com'}}
        tls=probe.xhttp_client(node,23456)['outbounds'][0]['streamSettings']['tlsSettings']
        self.assertEqual(tls['echConfigList'],'cloudflare-ech.com+https://1.1.1.1/dns-query')
        node['ech-opts']['config']='fixture-static-ech'
        self.assertEqual(probe.xhttp_client(node,23456)['outbounds'][0]['streamSettings']['tlsSettings']['echConfigList'],'fixture-static-ech')
        vmess={'type':'vmess','server':'edge.example.test','port':443,'uuid':'fixture-only',
               'tls':True,'servername':'edge.example.test','ws-opts':{'path':'/fixture'},
               'ech-opts':{'enable':True,'query-server-name':'cloudflare-ech.com'}}
        self.assertEqual(probe.singbox_client(vmess,23456)['dns']['servers'][1]['server'],'1.1.1.1')


if __name__=='__main__':unittest.main()
