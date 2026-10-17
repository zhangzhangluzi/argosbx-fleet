import contextlib,io,json,runpy,subprocess,sys,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fleet,servers

ROOT=Path(__file__).resolve().parents[1]

class StashDownloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config=json.loads((ROOT/'templates/servers.example.json').read_text());captured={}
        with patch('storage.save',side_effect=lambda path,value:captured.update(payload=value)),contextlib.redirect_stdout(io.StringIO()):
            runpy.run_path(str(ROOT/'generate.py'),init_globals={'inventory_override':config})
        cls.payload=captured['payload']
        cls.nodes=[{'name':'JP-U-v4-Hysteria2','type':'hysteria2','password':'fixture','sni':'tls.example.com'},
                   {'name':'JP-T-CF-VLESS-XHTTP-TLS','type':'vless','network':'xhttp','tls':True,'server':'edge-jp.example.com','servername':'edge-jp.example.com','encryption':'fixture-public','xhttp-opts':{'path':'/test','mode':'packet-up','reuse-settings':{'max-concurrency':'8-16'}}}]

    def render(self,request,nodes=None,files=None):
        op=self.payload['collections'][0]['process'][0]['args']
        script='''
const ProxyUtils={yaml:{safeLoad:JSON.parse,safeDump:JSON.stringify},
 parse:body=>JSON.parse(body).proxies,
 produce:(nodes,target)=>nodes.map(n=>{n=structuredClone(n);if(target==='Stash'&&n.type==='hysteria2'){n.auth=n.password;delete n.password;}return n;})};
const $substore={read:()=>FILES};
const $options={_req:REQUEST};const $arguments=ARGS;
let usedProfile;
async function produceArtifact({file,content,$options}) {
 usedProfile=file.name;
 const operator=new Function('ProxyUtils',file.process[0].args.content+'; return operator;')(ProxyUtils);
 return operator({$content:content,$options}).$content;
}
SCRIPT
(async()=>{try {
 const result=await transformFunction({body:JSON.stringify({proxies:NODES}),headers:{'Content-Length':'1',Vary:'Origin'}},{source:{_collection:{name:'all'}}});
 console.log(JSON.stringify({result,usedProfile}));
}catch(error){console.log(JSON.stringify({error:error.message}));}})();
'''.replace('FILES',json.dumps(self.payload['files'] if files is None else files)).replace('REQUEST',json.dumps(request)).replace('ARGS',json.dumps(op['arguments'])).replace('\nSCRIPT\n','\n'+op['content']+'\n').replace('NODES',json.dumps(self.nodes if nodes is None else nodes))
        return json.loads(subprocess.check_output(['node','-e',script],text=True))

    def check(self,result,count):
        self.assertNotIn('error',result)
        value=json.loads(result['result']['body']);servers.check_profile(value)
        self.assertEqual(len(value['proxies']),count)
        self.assertEqual(value['mode'],'rule');self.assertIn('dns',value)
        self.assertIn('去广告',[g['name'] for g in value['proxy-groups']])
        self.assertIn('content-type',result['result']['headers']);self.assertNotIn('Content-Length',result['result']['headers'])
        return value

    def test_stash_user_agent_receives_full_native_profile(self):
        r=self.render({'headers':{'User-Agent':'Stash/3.4.0 CFNetwork/1'}})
        v=self.check(r,1);self.assertEqual(r['usedProfile'],'stash')
        self.assertEqual(v['proxies'][0]['auth'],'fixture');self.assertNotIn('password',v['proxies'][0])
        self.assertNotIn('tun',v);self.assertEqual(r['result']['headers']['vary'],'Origin, User-Agent')

    def test_xhttp_is_gated_by_ios_and_macos_capabilities(self):
        for ua,count in [('Stash/3.4.0',1),('Stash/3.5.9',1),('Stash/3.6.0',2),('Stash/3.10.0',2),('StashMac/4.2.0',1),('StashMac/4.3.0',2),('Stash/4.2.0 Darwin/24',1),('Stash/4.0.0 iPhone',2)]:
            with self.subTest(ua=ua):self.check(self.render({'headers':{'user-agent':ua}}),count)

    def test_configured_health_cadence_has_no_stash_select_timer(self):
        for interval in (900,1800):
            config=json.loads((ROOT/'templates/servers.example.json').read_text())
            config['health']={'interval':interval,'tolerance':100};captured={}
            with patch('storage.save',side_effect=lambda path,value:captured.update(payload=value)),contextlib.redirect_stdout(io.StringIO()):
                runpy.run_path(str(ROOT/'generate.py'),init_globals={'inventory_override':config})
            self.payload=captured['payload']
            for ua in ('Stash/3.4.0','Stash/3.6.2','FlClash/0.8.99'):
                value=json.loads(self.render({'headers':{'User-Agent':ua}})['result']['body'])
                for group in value['proxy-groups']:
                    if group['type']=='url-test':
                        self.assertEqual(group['interval'],interval)
                        self.assertEqual(group['tolerance'],100)
                        self.assertTrue(group['lazy'])
                    elif ua.startswith('Stash'):
                        self.assertEqual(group['interval'],-1)
                    else:self.assertNotIn('interval',group)
            sr=next(f['content'] for f in self.payload['files'] if f['name']=='shadowrocket-config')
            for group in sr.splitlines():
                if '= url-test,' in group:self.assertIn('interval='+str(interval)+',',group)

    def test_versionless_explicit_stash_uses_compatible_subset(self):
        for ua in ['Stash','Mozilla/5.0','']:
            with self.subTest(ua=ua):self.check(self.render({'query':{'target':'Stash'},'headers':{'user-agent':ua}}),1)

    def test_filtered_nodes_do_not_leave_dangling_groups(self):
        value=self.check(self.render({'headers':{'user-agent':'Stash/3.4.0'}}),1)
        self.assertNotIn(self.nodes[1]['name'],json.dumps(value))
        self.assertEqual(next(g for g in value['proxy-groups'] if g['name']=='Telegram')['proxies'][0],'日常线路')

    def test_modern_stash_keeps_encryption_and_xhttp_parameters(self):
        value=self.check(self.render({'headers':{'user-agent':'Stash/3.6.2'}}),2)
        node=next(n for n in value['proxies'] if n.get('network')=='xhttp')
        self.assertEqual({k:v for k,v in node.items() if not k.startswith('benchmark-')},self.nodes[1])

    def test_stash_native_benchmark_fields_are_seconds_and_client_scoped(self):
        for ua in ('Stash/3.4.0','Stash/3.6.2','StashMac/4.3.0','Stash'):
            req={'headers':{'User-Agent':ua}}
            for output in (json.loads(self.render_file(req)['$content']),
                           json.loads(self.render(req)['result']['body'])):
                for node in output['proxies']:
                    self.assertEqual(node['benchmark-url'],'http://www.gstatic.com/generate_204')
                    self.assertEqual(node['benchmark-timeout'],8)
        clash=json.loads(self.render({'headers':{'User-Agent':'FlClash/1'}})['result']['body'])
        self.assertTrue(all(not any(k.startswith('benchmark-') for k in n) for n in clash['proxies']))

    def test_explicit_target_and_route_target_override_user_agent(self):
        r=self.render({'query':{'target':'ClashMeta'},'headers':{'user-agent':'Stash/3.4.0'}})
        self.check(r,2);self.assertEqual(r['usedProfile'],'clash')
        r=self.render({'params':{'target':'Stash'},'query':{'target':'ClashMeta'},'headers':{'user-agent':'FlClash/1'}})
        self.check(r,1);self.assertEqual(r['usedProfile'],'stash')

    def test_other_targets_remain_node_exports(self):
        r=self.render({'query':{'target':'Surge'},'headers':{'user-agent':'Stash/3.4.0'}})
        self.assertNotIn('usedProfile',r);self.assertEqual(json.loads(r['result']['body']),{'proxies':self.nodes})

    def test_missing_profile_or_empty_compatible_set_cannot_pass(self):
        request={'query':{'target':'Stash'}}
        self.assertIn('error',self.render(request,files=[]))
        self.assertIn('error',self.render(request,nodes=[self.nodes[1]]))

    def render_file(self,request,nodes=None):
        op=next(f for f in self.payload['files'] if f['name']=='stash')['process'][0]['args']['content']
        script='''
const ProxyUtils={yaml:{safeLoad:JSON.parse,safeDump:JSON.stringify},
 parse:body=>JSON.parse(body).proxies,
 produce:(nodes)=>nodes.map(n=>{n=structuredClone(n);if(n.type==='hysteria2'){n.auth=n.password;delete n.password;}return n;})};
SCRIPT
try {const input={$content:JSON.stringify({proxies:NODES}),$options:{_req:REQUEST,_res:{headers:{Vary:'Origin','Cache-Control':'public','Content-Length':'1'}}}};
 const output=operator(input);console.log(JSON.stringify(output));
}catch(error){console.log(JSON.stringify({error:error.message}));}
'''.replace('\nSCRIPT\n','\n'+op+'\n').replace('REQUEST',json.dumps(request)).replace('NODES',json.dumps(self.nodes if nodes is None else nodes))
        return json.loads(subprocess.check_output(['node','-e',script],text=True))

    def test_direct_file_matches_download_for_all_client_versions(self):
        for ua in ['Stash/3.4.0','Stash/3.6.2','StashMac/4.2.0','StashMac/4.3.0','Stash','Mozilla/5.0','']:
            with self.subTest(ua=ua):
                req={'query':{'target':'Stash'},'headers':{'User-Agent':ua}}
                file=self.render_file(req);download=self.render(req)
                self.assertNotIn('error',file)
                self.assertEqual(json.loads(file['$content']),json.loads(download['result']['body']))
                headers=file['$options']['_res']['headers']
                self.assertEqual(headers['cache-control'],'private, no-store')
                self.assertEqual(headers['vary'],'Origin, User-Agent')
                self.assertEqual(headers['content-type'],'text/yaml; charset=utf-8')
                self.assertNotIn('Content-Length',headers)

    def test_file_identity_cannot_be_overridden_to_skip_compatibility(self):
        output=self.render_file({'query':{'target':'ClashMeta'},'headers':{'user-agent':'FlClash/1'}})
        value=json.loads(output['$content']);servers.check_profile(value)
        self.assertEqual(len(value['proxies']),1)
        self.assertIn('auth',value['proxies'][0]);self.assertNotIn('password',value['proxies'][0])

    def test_file_filters_encryption_on_non_xhttp_and_removes_empty_country(self):
        from copy import deepcopy
        nodes=deepcopy(self.nodes)
        nodes[1].update(name='TW-T-Encrypted',network='tcp')
        output=self.render_file({'headers':{'user-agent':'Stash/3.4.0'}},nodes)
        value=json.loads(output['$content']);servers.check_profile(value)
        self.assertEqual([n['name'] for n in value['proxies']],[nodes[0]['name']])
        self.assertNotIn('TW-T-Encrypted',output['$content'])

    def test_file_refuses_an_empty_compatible_subset(self):
        self.assertIn('error',self.render_file({},[self.nodes[1]]))

    def test_stash_dns_capabilities_and_inline_ad_switch(self):
        for ua,modern in [('Stash/3.6.2',True),('StashMac/4.3.0',True),('Stash/3.4.0',False),('Stash',False)]:
            value=json.loads(self.render_file({'headers':{'User-Agent':ua}})['$content'])
            policy=value['dns']['nameserver-policy']
            self.assertIn('rule-set:国内域名' if modern else 'geosite:cn',policy)
            self.assertNotIn('geosite:cn' if modern else 'rule-set:国内域名',policy)
            self.assertNotIn('fleet-adblock-enabled',value.get('script',{}).get('shortcuts',{}))
            self.assertIn('RULE-SET,广告域名,去广告',value['rules'])
            groups={g['name']:g for g in value['proxy-groups']}
            self.assertEqual(groups['去广告']['proxies'],['开启去广告','关闭去广告'])
            self.assertEqual(groups['开启去广告']['proxies'],['REJECT'])
            self.assertEqual(groups['关闭去广告']['proxies'],['日常线路'])
            self.assertFalse(any('PASS' in g['proxies'] for g in groups.values()))
            # An installed legacy override must no longer control ad matching.
            self.assertFalse(any('fleet-adblock-enabled' in rule for rule in value['rules']))
        self.assertFalse(any(f['name'].endswith('.stoverride') for f in self.payload['files']))

    def test_stash_ad_switch_preserves_other_groups_rules_and_exceptions(self):
        value=json.loads(self.render_file({'headers':{'User-Agent':'Stash/3.6.2'}})['$content'])
        ad=value['rules'].index('RULE-SET,广告域名,去广告')
        self.assertLess(value['rules'].index('DOMAIN,ads.applovin.com,日常线路'),ad)
        self.assertLess(value['rules'].index('DOMAIN,ads.tiktok.com,日常线路'),ad)
        self.assertIn('RULE-SET,国内域名,DIRECT',value['rules'][ad+1:])
        self.assertIn('RULE-SET,国内IP,DIRECT',value['rules'][ad+1:])
        self.assertEqual(value['rules'][-1],'MATCH,日常线路')

    def test_clash_off_passes_and_stash_validator_refuses_pass(self):
        value=self.check(self.render({'headers':{'User-Agent':'FlClash/1'}}),2)
        off=next(g for g in value['proxy-groups'] if g['name']=='关闭去广告')
        self.assertEqual(off['proxies'],['PASS'])
        value['dns']['follow-rule']=True
        with self.assertRaises(ValueError):servers.check_profile(value)

    def test_shadowrocket_ad_domain_conversion_preserves_scope(self):
        op=next(f for f in self.payload['files'] if f['name']=='shadowrocket-ads')['process'][0]['args']['content']
        for body,wanted in [('# title\n+.ad.example\nexact.example\n+.ad.example\n','.ad.example\nexact.example\n'),('','ERROR'),('DOMAIN-SUFFIX,example.com','ERROR'),('<html>error</html>','ERROR')]:
            code=op+'\ntry {console.log(JSON.stringify(operator({$content:'+json.dumps(body)+'}).$content));}catch(e){console.log(JSON.stringify("ERROR"));}'
            result=json.loads(subprocess.check_output(['node','-e',code],text=True))
            self.assertEqual(result,wanted)
            if wanted!='ERROR':servers.check_sr_ads(result)

    def test_download_remains_compatible_during_file_processor_upgrade(self):
        from copy import deepcopy
        files=deepcopy(self.payload['files'])
        op=next(f for f in files if f['name']=='stash')['process'][0]['args']
        op['content']=op['content'].replace('stashCompatibleProxies(converted,input.$options?._req)','converted')
        self.check(self.render({'headers':{'user-agent':'Stash/3.4.0'}},files=files),1)

if __name__=='__main__':unittest.main()
