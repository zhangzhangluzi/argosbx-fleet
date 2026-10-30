"""Resumable, owned Cloudflare tunnel creation and DNS registration."""
import copy,json,re,secrets
from urllib.parse import urlencode
from storage import save
from protocols import protocol_type,cf_origin,validate_settings
from domains import build,stage,recover

def assert_disconnected(cf,endpoint,detail):
    """The legacy detail.connections field is no longer authoritative."""
    if not isinstance(detail,dict) or detail.get('status') not in ('inactive','down'):
        raise ValueError('隧道未确认停止，保留日志与 DNS，拒绝删除')
    clients=cf.call(endpoint+'/connections').get('result')
    if not isinstance(clients,list) or clients:
        raise ValueError('隧道仍有连接器或连接状态未知，保留日志并拒绝删除')
    return {'checked':True,'connectors':0}

def discover(cf,zone):
    found=[z for z in cf.zones() if z['name']==zone and z.get('status')=='active']
    if len(found)!=1:raise ValueError('Token 无权读取所选已激活域名')
    return found[0]

def routes(server):
    validate_settings(server['protocols'])
    rows=[];seen=set()
    for ident,p in server['protocols'].items():
        kind=protocol_type(ident,p)
        if kind not in ('cf','xhttp') or not p['enabled']:continue
        path='/'+p['ws_path' if kind=='cf' else 'path'].lstrip('/')
        key=(p['sni'],path)
        if key in seen:raise ValueError('CF 域名和 WS 路径重复')
        seen.add(key)
        rows.append({'hostname':p['sni'],'path':'^'+re.escape(path)+('(?:/.*)?$' if kind=='xhttp' else '$'),'service':cf_origin(p)})
    return rows+[{'service':'http_status:404'}]

def provision(cf,server,zone,journal):
    """Retry the same journal after any unknown HTTP outcome; never duplicate tunnels."""
    if journal.exists():
        j=json.loads(journal.read_text())
        if j['server']!=server or j['zone']!=zone:raise ValueError('接入日志属于另一配置，不能覆盖')
    else:
        z=discover(cf,zone)
        # Preflight names before allocating a remote resource.
        hosts={v for v in server['domains'].values() if v}|{server['onboarding']['certificate_host']}
        hosts|={p['sni'] for i,p in server['protocols'].items() if protocol_type(i,p) in ('cf','xhttp') and p['enabled']}
        routes(server)
        for host in hosts:
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
            for host in sorted({p['sni'] for i,p in server['protocols'].items() if protocol_type(i,p) in ('cf','xhttp') and p['enabled']}):
                plan['records'].append({'name':host,'type':'CNAME','content':j['tunnel_id']+'.cfargotunnel.com','proxied':True,'ttl':1})
            stage(cf,plan,dns_journal)
        j['dns_ready']=True;save(journal,j)
    token=cf.call(endpoint+'/token')['result']
    if not isinstance(token,str) or not token:raise ValueError('Cloudflare 未返回连接凭据')
    return {'tunnel_id':j['tunnel_id'],'account_id':j['account'],'connector_token':token}

def remove_owned(cf,journal):
    """Only use after the new connector is stopped; existing tunnels are never accepted."""
    if not journal.exists():return
    j=json.loads(journal.read_text())
    base='/accounts/'+j['account']+'/cfd_tunnel'
    matches=[t for t in cf.call(base+'?'+urlencode({'name':j['name'],'is_deleted':'false'}))['result'] if t['name']==j['name']]
    for t in matches:
        if j['tunnel_id'] and t['id']!=j['tunnel_id']:raise ValueError('隧道身份变化，拒绝删除')
        detail=cf.call(base+'/'+t['id'])['result']
        if detail.get('name')!=j['name']:raise ValueError('隧道身份变化，拒绝删除')
        assert_disconnected(cf,base+'/'+t['id'],detail)
    recover(cf,journal.with_suffix('.dns.json'))
    for t in matches:
        assert_disconnected(cf,base+'/'+t['id'],cf.call(base+'/'+t['id'])['result'])
        cf.call(base+'/'+t['id'],method='DELETE')
    journal.unlink()

def change_plan(cf,server,previous):
    """Synchronize this server's registered WS routes, preserving unrelated ingress."""
    def selected(settings):return {i:p for i,p in settings.items() if protocol_type(i,p) in ('cf','xhttp') and p['enabled']}
    old,new=selected(previous),selected(server['protocols'])
    if old==new:return None
    hosts={p['sni'] for p in old.values()}|{p['sni'] for p in new.values()}
    if server['domains'].get('cf'):hosts.add(server['domains']['cf'])
    zones=[z for z in cf.zones() if z.get('status')=='active' and all(h.endswith('.'+z['name']) for h in hosts)]
    if len(zones)!=1:raise ValueError('CF 入站域名必须属于同一个授权 zone')
    z=zones[0];dns='/zones/'+z['id']+'/dns_records';records={}
    for host in hosts:records[host]=cf.call(dns+'?'+urlencode({'name':host}))['result']
    tunnel_ids={r['content'].removesuffix('.cfargotunnel.com') for rows in records.values() for r in rows if r['type']=='CNAME' and r['content'].endswith('.cfargotunnel.com')}
    if len(tunnel_ids)!=1:raise ValueError('不能确定本机固定隧道；先完成 onboard.py install')
    tid=tunnel_ids.pop();endpoint='/accounts/'+z['account']['id']+'/cfd_tunnel/'+tid+'/configurations'
    before=cf.call(endpoint)['result']['config'];after=copy.deepcopy(before)
    old_rows=routes({'protocols':old})[:-1];new_rows=routes({'protocols':new})[:-1]
    def owned(row):
        return any(row.get('hostname')==o['hostname'] and row.get('service')==o['service'] and row.get('path') in (None,o['path']) for o in old_rows)
    retained=[row for row in before['ingress'] if not owned(row)]
    for row in retained:
        if any(row.get('hostname')==n['hostname'] and row.get('path') in (None,n['path']) for n in new_rows):raise ValueError('CF 新路由与未托管入口冲突')
    after['ingress']=new_rows+retained
    changes=[]
    for host in {p['sni'] for p in new.values()}:
        wanted={'name':host,'type':'CNAME','content':tid+'.cfargotunnel.com','proxied':True,'ttl':1}
        existing=records[host]
        if any(not all(r.get(k)==wanted[k] for k in ('name','type','content','proxied')) for r in existing):raise ValueError('CF 域名记录冲突')
        if not existing:changes.append(wanted)
    return {'dns_path':dns,'records':changes,'tunnel_path':endpoint,'before':before,'after':after,'server_id':server['id'],'names':{}}
