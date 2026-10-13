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
async function produceArtifact({file,content}) {
 usedProfile=file.name;
 const operator=new Function('ProxyUtils',file.process[0].args.content+'; return operator;')(ProxyUtils);
 return operator({$content:content}).$content;
}
SCRIPT
(async()=>{try {
 const result=await transformFunction({body:JSON.stringify({proxies:NODES}),headers:{'Content-Length':'1',Vary:'Origin'}},{source:{_collection:{name:'all'}}});
 console.log(JSON.stringify({result,usedProfile}));
}catch(error){console.log(JSON.stringify({error:error.message}));}})();
'''.replace('FILES',json.dumps(self.payload['files'] if files is None else files)).replace('REQUEST',json.dumps(request)).replace('ARGS',json.dumps(op['arguments'])).replace('SCRIPT',op['content']).replace('NODES',json.dumps(self.nodes if nodes is None else nodes))
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
        self.assertEqual(node,self.nodes[1])

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

if __name__=='__main__':unittest.main()
