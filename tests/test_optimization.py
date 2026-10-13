import copy,json,re,sys,tempfile,unittest,subprocess
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import agent,xhttp,tunnels
from protocols import validate_settings,export,classify,render
from inbounds import create
from test_core import fixtures
from storage import save
from routing_policy import AI_DOMAINS
from dns_policy import harden_config

SETTINGS={'enabled':True,'listen':'127.0.0.1','port':18084,'sni':'edge.example.com','path':'/fixture_xhttp','mode':'packet-up','client':{'client-fingerprint':'chrome'}}

class ClientCapabilityTests(unittest.TestCase):
    def test_cf_ech_processor_accepts_both_transports_and_rejects_direct(self):
        source=(Path(__file__).resolve().parents[1]/'ech-policy.js').read_text().replace('CF_HOSTS','["edge.example.com"]')
        script=source+'''
const assert=require('node:assert/strict');
for (const [type,network] of [['vmess','ws'],['vless','xhttp']]) {
 const p={type,network,tls:true,server:'edge.example.com',servername:'edge.example.com',encryption:'fixture'};
 const n=applyCfEch([p])[0];
 assert.equal(n.encryption,'fixture');assert.equal(n['ech-opts'].enable,true);
}
assert.throws(()=>applyCfEch([{type:'vless',network:'tcp',tls:true,server:'edge.example.com'}]));
'''
        subprocess.run(['node','-e',script],check=True,capture_output=True)
    def test_client_tuning_does_not_rewrite_native_defaults(self):
        c,_,s=fixtures();desired=copy.deepcopy(s['protocols'])
        desired['anytls']['client']['min-idle-session']=1
        self.assertEqual(render(c,s,desired),c)
    def test_cross_protocol_fields_rejected(self):
        for kind,params in [('hy2',{'fast-open':True}),('hy2',{'idle-session-timeout':60}),('anytls',{'udp-over-tcp-version':2})]:
            with self.assertRaises(ValueError):validate_settings({kind:{'client':params}})
        validate_settings({'anytls':{'client':{'min-idle-session':1}}})
        for value in (True,-1,9):
            with self.assertRaises(ValueError):validate_settings({'anytls':{'client':{'min-idle-session':value}}})
    def test_ai_dns_follows_selected_group_without_bootstrap_cycle(self):
        p=harden_config({'dns':{},'rules':['DOMAIN-SUFFIX,old.example,AI线路','MATCH,日常线路']},'clash',hosts={})
        for domain in AI_DOMAINS:self.assertTrue(all(u.endswith('#AI线路') for u in p['dns']['nameserver-policy']['+.'+domain]))
        self.assertTrue(all(u.endswith('#DIRECT') for u in p['dns']['proxy-server-nameserver']))
        self.assertNotIn('DOMAIN-SUFFIX,old.example,AI线路',p['rules'])
    def test_xhttp_route_keeps_uuid_and_sequence_suffix(self):
        row=tunnels.routes({'protocols':{'xhttp':SETTINGS}})[0]
        for suffix in ('','/','/session/123'):self.assertRegex(SETTINGS['path']+suffix,row['path'])
        self.assertIsNone(re.match(row['path'],SETTINGS['path']+'-unrelated'))
    def test_cf_origin_must_be_private_loopback(self):
        with self.assertRaises(ValueError):validate_settings({'xhttp':{**SETTINGS,'listen':'0.0.0.0'}})

class AdditiveXHTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);root=Path(self.tmp.name)
        c,_,s=fixtures()
        actual={str(root/Path(p).name):v for p,v in c.items()}
        for b in s['bindings'].values():b['path']=str(root/Path(b['path']).name)
        for p,v in actual.items():save(p,v)
        s['native_sha256']={p:agent.sha(Path(p).read_text()) for p in actual}
        self.original=copy.deepcopy(s);self.commands=[]
        patches=[patch.object(agent,'HOME',root),patch.object(agent,'STATE',root/'state.json'),patch.object(agent,'JOURNAL',root/'apply-journal.json'),patch.object(agent,'TARGET',root/'source.yaml'),patch.object(xhttp,'CONFIG',root/'xr-xhttp.json'),patch.object(xhttp,'UNIT',root/'xhttp.service'),patch.object(agent,'cmd',side_effect=lambda a:self.commands.append(a) or ''),patch.object(agent,'validate_native'),patch('listeners.check'),patch('inbounds.vless_encryption',return_value=('fixture-private','fixture-public'))]
        for p in patches:p.start();self.addCleanup(p.stop)
        save(agent.STATE,s);agent.TARGET.write_text('old-source')
        self.before={p:Path(p).read_bytes() for p in actual}
    def test_stage_does_not_publish_or_modify_existing_configs(self):
        self.assertTrue(xhttp.stage(SETTINGS)['ready']);xhttp.stage(SETTINGS)
        self.assertEqual(agent.load(),self.original);self.assertEqual(agent.TARGET.read_text(),'old-source')
        self.assertEqual(self.before,{p:Path(p).read_bytes() for p in self.before})
        node=xhttp.candidate();self.assertEqual(classify(node),'xhttp');self.assertEqual(node['encryption'],'fixture-public')
        self.assertFalse(any('restart' in a for a in self.commands))
        with patch.object(agent,'export_source',return_value={'nodes':4}):xhttp.commit()
        self.assertIn('xhttp',agent.load()['protocols']);self.assertFalse(xhttp.journal().exists())
    def test_recover_only_removes_new_entrance(self):
        xhttp.stage(SETTINGS)
        with patch.object(agent,'export_source'):xhttp.recover()
        self.assertEqual(agent.load(),self.original);self.assertFalse(xhttp.CONFIG.exists())
        self.assertEqual(self.before,{p:Path(p).read_bytes() for p in self.before})
        self.assertFalse(any('restart' in a for a in self.commands))
    def test_commit_rejects_concurrent_native_change(self):
        xhttp.stage(SETTINGS);p=next(iter(self.before));Path(p).write_text('{}')
        with self.assertRaises(ValueError):xhttp.commit()
        self.assertEqual(agent.load(),self.original)
    def test_source_drift_stops_commit_and_recovery(self):
        xhttp.stage(SETTINGS);agent.TARGET.write_text('external-source')
        for fn in (xhttp.commit,xhttp.recover):
            with self.assertRaises(ValueError):fn()
        self.assertEqual(agent.TARGET.read_text(),'external-source')
        self.assertTrue(xhttp.CONFIG.exists())
