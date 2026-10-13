import copy
import contextlib
import importlib.util
import json
import io
import os
from pathlib import Path
import subprocess
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import fleet
spec=importlib.util.spec_from_file_location('server_manager',ROOT/'servers.py')
manager=importlib.util.module_from_spec(spec);spec.loader.exec_module(manager)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.config=json.loads((ROOT/'templates/servers.example.json').read_text())

    def test_custom_country_host_and_source(self):
        s=self.config['servers'][0]
        s.update(id='gb',name='GB',country='GB',country_name='英国',ipv4='198.51.100.20',ipv6=None)
        s['domains']={'ipv4':'gb.example.net','ipv6':None,'cf':'edge.example.net'}
        s['subscription']={'name':'source-gb','url':'https://origin.example.net/private'}
        self.config['purpose_order']=['GB']
        fleet.validate(self.config)
        self.assertEqual(fleet.host_map(self.config),{'gb.example.net':'198.51.100.20'})
        self.assertEqual(fleet.region_spec(s)['cf'],'edge.example.net')

    def test_duplicate_node_prefix_rejected(self):
        self.config['servers'].append(copy.deepcopy(self.config['servers'][0]))
        with self.assertRaises(ValueError):fleet.validate(self.config)

    def test_ip_family_and_domain_pair_rejected(self):
        for field,value in [('ipv4','2001:db8::20'),('ipv6',None)]:
            config=copy.deepcopy(self.config);config['servers'][0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):fleet.validate(config)

    def test_invalid_ssh_and_plaintext_source_rejected(self):
        for field,value in [('port',0),('port',True),('host','-oProxyCommand=bad'),('user','root;bad')]:
            config=copy.deepcopy(self.config);config['servers'][0]['ssh'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):fleet.validate(config)
        self.config['servers'][0]['subscription']['url']='http://example.com/private'
        with self.assertRaises(ValueError):fleet.validate(self.config)

    def test_private_file_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'servers.json';path.write_text(json.dumps(self.config));path.chmod(0o644)
            with self.assertRaises(ValueError):fleet.read(path)
            path.chmod(0o600);self.assertEqual(fleet.read(path),self.config)

    def test_changed_destination_cannot_reuse_old_ssh_master(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(fleet,'WORKSPACE',Path(tmp)):
            p=Path(tmp)/'.vpn-deploy';p.mkdir()
            ssh=self.config['servers'][0]['ssh']
            (p/'ssh-sessions.json').write_text(json.dumps({'jp':{**ssh,'socket':'old.sock'}}))
            args=fleet.ssh_args('jp',self.config)
            self.assertEqual(args[2],str(Path(tmp)/'old.sock'))
            for field,value in [('host','192.0.2.20'),('port',2222),('user','admin')]:
                config=copy.deepcopy(self.config);config['servers'][0]['ssh'][field]=value
                args=fleet.ssh_args('jp',config)
                self.assertEqual(args[2],'none')

    def test_node_processor_custom_domains_cf_identity_and_ipv6(self):
        s=self.config['servers'][0];s['name']='JP2'
        script=(ROOT/'region-processor.js').read_text().replace('SPEC',json.dumps(fleet.region_spec(s)))
        nodes=[{'type':'vmess','tls':True,'network':'ws','server':'old.example.com','servername':'old.example.com','ws-opts':{'headers':{'Host':'old.example.com'}}},
               {'type':'hysteria2','obfs':'salamander','password':'fixture'},
               {'type':'anytls','password':'fixture'}]
        js=script+';process.stdout.write(JSON.stringify(operator('+json.dumps(nodes)+')));'
        result=subprocess.run(['node','-e',js],check=True,text=True,capture_output=True)
        actual=json.loads(result.stdout)
        cf=next(n for n in actual if n['type']=='vmess')
        self.assertEqual(cf['name'],'JP2-T-CF-VMess-WS-TLS')
        self.assertEqual(cf['server'],s['domains']['cf'])
        self.assertEqual(cf['servername'],cf['server'])
        self.assertEqual(cf['ws-opts']['headers']['Host'],cf['server'])
        self.assertEqual(len([n for n in actual if n['type']=='hysteria2']),1)
        self.assertEqual({n['server'] for n in actual if n['type']=='anytls'},{s['domains']['ipv4'],s['domains']['ipv6']})

    def test_generator_uses_configured_country_and_two_server_names(self):
        s=self.config['servers'][0]
        s.update(name='GB',country='GB',country_name='英国')
        other=copy.deepcopy(s);other.update(id='gb2',name='GB2')
        other['subscription']['name']='argo-gb2'
        self.config['servers'].append(other);self.config['purpose_order']=['GB']
        captured={}
        def capture(path,content,*a,**kw):captured['payload']=content
        work=ROOT
        with patch.object(fleet,'read',return_value=self.config),patch('storage.save',side_effect=capture),contextlib.redirect_stdout(io.StringIO()),patch.dict(sys.modules):
            sys.modules.pop('dns_policy',None);sys.path.insert(0,str(work))
            try:runpy.run_path(str(work/'generate.py'))
            finally:sys.path.remove(str(work))
        payload=captured['payload'];self.assertEqual(len(payload['subscriptions']),2)
        script=next(f for f in payload['files'] if f['name']=='clash')['process'][0]['args']['content']
        config={'proxies':[{'name':'GB-T-v4-AnyTLS'},{'name':'GB2-U-v4-Hysteria2'}]}
        js='const ProxyUtils={yaml:{safeLoad:JSON.parse,safeDump:JSON.stringify}};'+script+';process.stdout.write(operator({$content:'+json.dumps(json.dumps(config))+'}).$content);'
        rendered=json.loads(subprocess.run(['node','-e',js],check=True,text=True,capture_output=True).stdout)
        groups={g['name']:g for g in rendered['proxy-groups']}
        self.assertEqual(groups['日常线路']['proxies'],['地区-英国'])
        self.assertEqual(groups['地区-英国']['proxies'],[n['name'] for n in config['proxies']])
        self.assertEqual(groups['Telegram']['proxies'],['日常线路','地区-英国'])
        manager.check_profile(rendered)

    def test_missing_and_circular_group_references_rejected(self):
        for groups in [[{'name':'A','proxies':['missing']}],[{'name':'A','proxies':['B']},{'name':'B','proxies':['A']}]]:
            with self.subTest(groups=groups),self.assertRaises(ValueError):
                manager.check_profile({'proxies':[{'name':'node'}],'proxy-groups':groups,'rules':['MATCH,A']})

    def test_publish_rejects_stale_inventory_before_network(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(manager,'PLAN',Path(tmp)/'plan.json'),patch.object(manager,'JOURNAL',Path(tmp)/'journal.json'),patch.object(manager,'get') as get:
            manager.PLAN.write_text(json.dumps({'inventory_sha256':'old'}))
            with self.assertRaises(ValueError):manager.publish(self.config)
            get.assert_not_called()

    def test_publish_rolls_back_unknown_patch_result(self):
        old={'name':'clash','content':'before'};new={'name':'clash','content':'after'}
        plan={'inventory_sha256':manager.digest(self.config),'items':[{'kind':'file','name':'clash','before':old,'after':new}]}
        with tempfile.TemporaryDirectory() as tmp,patch.object(manager,'PLAN',Path(tmp)/'plan.json'),patch.object(manager,'JOURNAL',Path(tmp)/'journal.json'),patch.object(manager,'get',side_effect=[old,old,new,old]),patch.object(manager,'request',side_effect=[TimeoutError(),None]) as request:
            manager.PLAN.write_text(json.dumps(plan))
            with self.assertRaises(TimeoutError):manager.publish(self.config)
            self.assertEqual(request.call_args_list[-1].args[2],old)

    def test_rollback_does_not_overwrite_concurrent_change(self):
        old={'name':'clash','content':'before'};new={'name':'clash','content':'after'}
        plan={'inventory_sha256':manager.digest(self.config),'items':[{'kind':'file','name':'clash','before':old,'after':new}]}
        with tempfile.TemporaryDirectory() as tmp,patch.object(manager,'PLAN',Path(tmp)/'plan.json'),patch.object(manager,'JOURNAL',Path(tmp)/'journal.json'),patch.object(manager,'get',side_effect=[old,old,{'name':'clash','content':'other'}]),patch.object(manager,'request',side_effect=TimeoutError()) as request:
            manager.PLAN.write_text(json.dumps(plan))
            with self.assertRaises(RuntimeError):manager.publish(self.config)
            self.assertEqual(request.call_count,1)


if __name__=='__main__':unittest.main()
