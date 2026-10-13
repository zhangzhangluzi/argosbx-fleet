"""Gate new-machine publication on independent native clients with matching IP families."""
import copy,json,subprocess
from pathlib import Path
from fleet import ssh_args
from protocols import classify,protocol_type,families

def cases(server,nodes):
    templates={}
    for n in nodes:
        ident=n['name'][6:] if n['name'].startswith('fleet.') else classify(n)
        if ident in templates:raise ValueError('验收节点标识重复')
        templates[ident]=n
    result=[]
    for ident,p in server['protocols'].items():
        if not p['enabled']:continue
        n=templates.get(ident)
        if not n or classify(n)!=protocol_type(ident,p):raise ValueError('验收节点缺失或协议不符')
        for family in (['cf'] if protocol_type(ident,p) in ('cf','xhttp') else families(ident,p,server)):
            node=copy.deepcopy(n);node['server']=p['sni'] if family=='cf' else server[family]
            result.append({'name':ident+'/'+family,'node':node,'expected_ips':[server[f] for f in ('ipv4','ipv6') if server[f]]})
    if len(templates)!=sum(p['enabled'] for p in server['protocols'].values()):raise ValueError('验收节点集合不一致')
    return result

def observers(config,server,checks):
    peers=[p for p in config.get('servers',[]) if p['id']!=server['id'] and p.get('status','active')=='active']
    peers.sort(key=lambda p:p['id']!=config.get('coordinator'))
    if not peers:raise ValueError('新机需通过独立服务器验收后才能发布')
    groups={}
    for case in checks:
        family='ipv6' if case['name'].endswith('/ipv6') else 'ipv4'
        peer=next((p for p in peers if p.get(family)),None)
        if peer is None:raise ValueError('缺少独立 '+family+' 验收端；保持 pending，不发布节点')
        groups.setdefault(peer['id'],[]).append(case)
    return groups

def verify_new_server(config,server,nodes):
    groups=observers(config,server,cases(server,nodes))
    # Pass code and private credentials over SSH stdin; nothing is persisted remotely.
    source=(Path(__file__).parent/'probe.py').read_text()
    wrapper="import json,sys;sys.path.insert(0,'/opt/argosbx-fleet/current');p=json.load(sys.stdin);ns={'__name__':'fleet_probe'};exec(compile(p['code'],'fleet-probe','exec'),ns);print(json.dumps(ns['verify'](p['cases'])))"
    import shlex
    results=[]
    for peer,checks in groups.items():
        payload={'code':source,'cases':checks}
        proc=subprocess.run(ssh_args(peer,config)+[shlex.join(['python3','-c',wrapper])],input=json.dumps(payload),text=True,capture_output=True,timeout=max(180,len(checks)*60))
        if proc.returncode:raise RuntimeError('独立客户端验收未完成；保持 pending，不发布节点')
        result=json.loads(proc.stdout);values=result.get('results',[])
        if sorted(r['name'] for r in values)!=sorted(c['name'] for c in checks):raise ValueError('验收结果节点集合不符')
        failed=[r['name'] for r in values if not all(r.get(k) is True for k in ('https_ok','exit_ok','udp_ok'))]
        if result.get('passed') is not True or failed:raise RuntimeError('新机节点验收失败：'+','.join(failed)+'；保持 pending，不发布节点')
        results.extend({**r,'observer':peer} for r in values)
    return {'passed':True,'results':results}
