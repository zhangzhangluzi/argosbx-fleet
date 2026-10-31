"""Catch partial exports and connector outages before changing subscriptions."""
import copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import agent,fleetctl,servers
import test_stash_download

class CompleteProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_stash_download.StashDownloadTests.setUpClass()
        renderer=test_stash_download.StashDownloadTests()
        cls.full=json.loads(renderer.render_file({'headers':{'User-Agent':'Stash/3.6.2'}})['$content'])

    def test_equal_native_profile_is_accepted(self):
        servers.check_equivalent_profile(copy.deepcopy(self.full),self.full,'test')

    def test_lost_health_or_default_selection_is_rejected(self):
        for mutate in (
            lambda g:g.update(interval=600),lambda g:g.update(lazy=False),
            lambda g:g.update(proxies=list(reversed(g['proxies'])))):
            value=copy.deepcopy(self.full);group=next(g for g in value['proxy-groups'] if g['type']=='url-test')
            mutate(group)
            with self.assertRaisesRegex(ValueError,'proxy-groups'):servers.check_equivalent_profile(value,self.full,'test')

    def test_country_subset_removes_other_countries_and_references(self):
        full=copy.deepcopy(self.full)
        node={**full['proxies'][0],'name':'TW-U-v4-Hysteria2'};full['proxies'].append(node)
        full['proxy-groups'].append({'name':'地区-台湾','type':'url-test','interval':1800,'proxies':[node['name']]})
        for g in full['proxy-groups']:
            if g['name'] in ('日常线路','AI线路','Telegram'):g['proxies'].append('地区-台湾')
        selected=servers.subset_profile(full,self.full['proxies'])
        self.assertEqual(selected,self.full)
        self.assertEqual(len(full['proxies']),3)
        with self.assertRaises(ValueError):servers.check_equivalent_profile(full,selected,'country')

    def test_legacy_filter_preserves_parameters_and_removes_empty_country(self):
        full=copy.deepcopy(self.full)
        xhttp=full['proxies'].pop();xhttp['name']='TW-T-CF-VLESS-XHTTP-TLS';full['proxies'].append(xhttp)
        jp=next(g for g in full['proxy-groups'] if g['type']=='url-test');jp['proxies']=[full['proxies'][0]['name']]
        full['proxy-groups'].append({**jp,'name':'地区-台湾','proxies':[xhttp['name']]})
        full['proxy-groups'][0]['proxies'].append('地区-台湾')
        legacy=servers.stash_expected_profile(full,False)
        self.assertEqual(len(legacy['proxies']),1)
        self.assertNotIn('地区-台湾',[g['name'] for g in legacy['proxy-groups']])
        self.assertEqual(legacy['proxy-groups'][0]['proxies'],['地区-日本'])
        self.assertIn('geosite:cn',legacy['dns']['nameserver-policy'])
        self.assertEqual(full['proxies'][1]['network'],'xhttp')

    def test_missing_rule_dns_or_script_reference_is_rejected(self):
        for rule in ('DOMAIN,example.com,不存在','RULE-SET,不存在,DIRECT','SCRIPT,不存在,DIRECT'):
            value=copy.deepcopy(self.full);value['rules'].insert(0,rule)
            with self.assertRaises(ValueError):servers.check_profile(value)
        value=copy.deepcopy(self.full);value['dns']['nameserver-policy']['rule-set:missing']=['https://example.com/dns-query']
        with self.assertRaises(ValueError):servers.check_profile(value)

    def test_logical_rule_target_with_no_resolve_is_validated(self):
        value=copy.deepcopy(self.full)
        value['rules'].insert(0,'AND,((NETWORK,TCP),(DST-PORT,443)),日常线路,no-resolve')
        servers.check_profile(value)
        value['rules'][0]=value['rules'][0].replace('日常线路','missing')
        with self.assertRaises(ValueError):servers.check_profile(value)

    def test_empty_groups_are_not_a_complete_client_profile(self):
        value=copy.deepcopy(self.full);value['proxy-groups']=[];value['rules']=['MATCH,DIRECT']
        with self.assertRaises(ValueError):servers.check_profile(value)

    def test_differences_do_not_expose_values(self):
        value=copy.deepcopy(self.full);value['proxies'][0]['password']='private-secret'
        with self.assertRaises(ValueError) as ctx:servers.check_equivalent_profile(value,self.full,'test')
        self.assertNotIn('private-secret',str(ctx.exception))

    def test_old_plan_cannot_bypass_new_checks(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'plan.json';path.write_text('{}')
            with patch.object(servers,'PLAN',path),patch.object(servers,'native_preflight') as preflight,patch.object(servers,'request') as request:
                with self.assertRaisesRegex(ValueError,'重新 plan'):servers.publish({})
                preflight.assert_not_called();request.assert_not_called()

class ConnectorTests(unittest.TestCase):
    state={'protocols':{'xhttp-extra':{'type':'xhttp','enabled':True}}}
    def health(self,args,status=200):
        with patch.object(agent,'cmd',side_effect=['','42']) as cmd,patch.object(Path,'resolve',return_value=Path('/usr/local/bin/cloudflared')),patch.object(Path,'read_bytes',return_value=('cloudflared\0'+args).encode()),patch('http.client.HTTPConnection') as http:
            http.return_value.getresponse.return_value.status=status
            http.return_value.getresponse.return_value.read.return_value=b'cloudflared_tunnel_ha_connections 4\n'
            value=agent.cloudflare_health(self.state)
            self.assertTrue(all('restart' not in c.args[0] for c in cmd.call_args_list))
            return value,http

    def test_direct_only_needs_no_connector(self):
        with patch.object(agent,'cmd') as cmd:
            self.assertEqual(agent.cloudflare_health({'protocols':{'reality':{'enabled':True}}}),{'required':False})
            cmd.assert_not_called()

    def test_stopped_connector_is_not_ready(self):
        with patch.object(agent,'cmd',side_effect=subprocess.CalledProcessError(3,['systemctl'])):
            self.assertFalse(agent.cloudflare_health(self.state)['ready'])

    def test_explicit_loopback_readiness_and_unhealthy_status(self):
        for args in ('--metrics'+'\0'+'127.0.0.1:20241\0','--metrics=[::1]:20241\0'):
            for status,ready in ((200,True),(503,False),(302,False)):
                value,http=self.health(args,status)
                self.assertEqual(value['ready'],ready)
                requests=[c.args for c in http.return_value.request.call_args_list]
                self.assertEqual(requests,[('GET','/ready'),('GET','/metrics')] if ready else [('GET','/ready')])
                self.assertEqual(http.return_value.close.call_count,2 if ready else 1)

    def test_no_metrics_is_explicitly_unknown_and_remote_endpoint_not_contacted(self):
        value,http=self.health('tunnel\0run\0')
        self.assertIsNone(value['ready']);http.assert_not_called()
        for endpoint in ('0.0.0.0:20241','example.com:20241','127.0.0.1:99999'):
            value,http=self.health('--metrics='+endpoint+'\0')
            self.assertFalse(value['ready']);http.assert_not_called()

    def test_publication_gate_checks_cf_without_mutating_any_service(self):
        server={'id':'jp','protocols':self.state['protocols'],'certificates':{}}
        live={**server,'native_configuration_matches':True,'source_matches':True,'services_active':True,'unfinished_transactions':[],'certificate_health':{}}
        for health in ({},{'service_active':False},{'service_active':True,'ready':False}):
            with patch.object(fleetctl,'remote',return_value={**live,'cloudflare_health':health}),self.assertRaisesRegex(ValueError,'CF'):
                servers.native_preflight({'servers':[server]})
        with patch.object(fleetctl,'remote',return_value={**live,'cloudflare_health':{'service_active':True,'ready':True}}):
            servers.native_preflight({'servers':[server]})

if __name__=='__main__':unittest.main()
