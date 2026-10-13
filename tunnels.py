"""Resumable, owned Cloudflare tunnel creation and DNS registration."""
import copy,json,re,secrets
from urllib.parse import urlencode
from storage import save
from protocols import protocol_type
from domains import build,stage,recover

def discover(cf,zone):
    found=[z for z in cf.zones() if z['name']==zone and z.get('status')=='active']
    if len(found)!=1:raise ValueError('Token 无权读取所选已激活域名')
    return found[0]

def routes(server):
    rows=[];seen=set()
    for ident,p in server['protocols'].items():
        if protocol_type(ident,p)!='cf' or not p['enabled']:continue
        path='/'+p['ws_path'].lstrip('/')
        key=(p['sni'],path)
        if key in seen:raise ValueError('CF 域名和 WS 路径重复')
        seen.add(key)
        rows.append({'hostname':p['sni'],'path':'^'+re.escape(path)+'$','service':'http://127.0.0.1:'+str(p['port'])})
    return rows+[{'service':'http_status:404'}]

def provision(cf,server,zone,journal):
    """Retry the same journal after any unknown HTTP outcome; never duplicate tunnels."""
    if journal.exists():
        j=json.loads(journal.read_text())
        if j['server']!=server or j['zone']!=zone:raise ValueError('接入日志属于另一配置，不能覆盖')
    else:
        z=discover(cf,zone)
        # Preflight names before allocating a remote resource.
        for host in {v for v in server['domains'].values() if v}|{server['onboarding']['certificate_host']}:
            if not host.endswith('.'+zone):raise ValueError('新机必须使用所选域名的子域名')
            records=cf.call('/zones/'+z['id']+'/dns_records?'+urlencode({'name':host}))['result']
            if records:raise ValueError('新机域名已被使用：'+host)
        j={'server':copy.deepcopy(server),'zone':zone,'account':z['account']['id'],'name':'argosbx-'+server['id']+'-'+secrets.token_hex(8),'tunnel_id':None}
        save(journal,j)
    base='/accounts/'+j['account']+'/cfd_tunnel'
    if not j['tunnel_id']:
        matches=[t for t in cf.call(base+'?'+urlencode({'name':j['name'],'is_deleted':'false'}))['result'] if t['name']==j['name']]
        if len(matches)>1:raise ValueError('隧道身份冲突')
        tunnel=matches[0] if matches else cf.call(base,{'name':j['name'],'config_src':'cloudflare'},'POST')['result']
        j['tunnel_id']=tunnel['id'];save(journal,j)
    endpoint=base+'/'+j['tunnel_id']
    if not j.get('routed'):
        wanted={'ingress':routes(server)}
        cf.call(endpoint+'/configurations',{'config':wanted},'PUT')
        if cf.call(endpoint+'/configurations')['result']['config'].get('ingress')!=wanted['ingress']:raise ValueError('CF 隧道配置回读不一致')
        j['routed']=True;save(journal,j)
    dns_journal=journal.with_suffix('.dns.json')
    if not j.get('dns_ready'):
        if dns_journal.exists():
            if not json.loads(dns_journal.read_text()).get('ready'):recover(cf,dns_journal)
        if not dns_journal.exists():
            names={**server['domains'],'certificate':server['onboarding']['certificate_host']}
            plan=build(cf,zone,server,{k:v for k,v in names.items() if k!='cf'},j['tunnel_id'])
            # DNS-only CNAME: tunnel routes have already been read back above.
            for host in sorted({p['sni'] for i,p in server['protocols'].items() if protocol_type(i,p)=='cf' and p['enabled']}):
                plan['records'].append({'name':host,'type':'CNAME','content':j['tunnel_id']+'.cfargotunnel.com','proxied':True,'ttl':1})
            stage(cf,plan,dns_journal)
        j['dns_ready']=True;save(journal,j)
    token=cf.call(endpoint+'/token')['result']
    if not isinstance(token,str) or not token:raise ValueError('Cloudflare 未返回连接凭据')
    return {'tunnel_id':j['tunnel_id'],'account_id':j['account'],'connector_token':token}

def remove_owned(cf,journal):
    """Only use after the new connector is stopped; existing tunnels are never accepted."""
    if not journal.exists():return
    j=json.loads(journal.read_text());recover(cf,journal.with_suffix('.dns.json'))
    base='/accounts/'+j['account']+'/cfd_tunnel'
    matches=[t for t in cf.call(base+'?'+urlencode({'name':j['name'],'is_deleted':'false'}))['result'] if t['name']==j['name']]
    for t in matches:
        if j['tunnel_id'] and t['id']!=j['tunnel_id']:raise ValueError('隧道身份变化，拒绝删除')
        cf.call(base+'/'+t['id'],method='DELETE')
    journal.unlink()
