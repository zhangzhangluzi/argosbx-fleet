"""Additive Cloudflare domain migration. Existing names and subscriptions stay intact."""
import copy
import json
import re
import secrets
from pathlib import Path
from urllib.parse import urlencode
import urllib.request
from storage import save

class Cloudflare:
    def __init__(self,token_file):
        p=Path(token_file).expanduser()
        if p.stat().st_mode&0o077:raise ValueError('CF Token 文件权限必须为 0600')
        self.token=p.read_text().strip()
        if not self.token:raise ValueError('CF Token 为空')
    def call(self,path,body=None,method=None):
        req=urllib.request.Request('https://api.cloudflare.com/client/v4'+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json'})
        try:
            with urllib.request.urlopen(req,timeout=30) as r:result=json.load(r)
        except Exception:raise RuntimeError('Cloudflare 请求失败，请检查 Token 权限和网络') from None
        if not result.get('success'):raise RuntimeError('Cloudflare 拒绝请求')
        return result
    def zones(self):
        out=[];page=1
        while True:
            d=self.call('/zones?'+urlencode({'page':page,'per_page':50}));out+=d['result']
            if page>=d.get('result_info',{}).get('total_pages',1):return out
            page+=1

def build(cf,zone_name,server,names,tunnel_id):
    zones=[z for z in cf.zones() if z['name']==zone_name and z['status']=='active']
    if len(zones)!=1:raise ValueError('所选域名不可管理或尚未激活')
    z=zones[0];dns='/zones/'+z['id']+'/dns_records';records=[]
    if not re.fullmatch(r'[a-fA-F0-9-]{36}',tunnel_id):raise ValueError('固定隧道 ID 无效')
    for role,host in names.items():
        if role not in ('ipv4','ipv6','cf','certificate'):raise ValueError('未知域名角色')
        if host is None:continue
        if not re.fullmatch(r'[a-zA-Z0-9.-]+',host) or not host.endswith('.'+zone_name):raise ValueError('只能使用所选域名的子域名')
        targets=[('CNAME',tunnel_id+'.cfargotunnel.com',True)] if role=='cf' else [('A',server['ipv4'],False)] if role=='ipv4' else [('AAAA',server['ipv6'],False)] if role=='ipv6' else [(k,server[f],False) for k,f in [('A','ipv4'),('AAAA','ipv6')] if server[f]]
        existing=cf.call(dns+'?'+urlencode({'name':host,'per_page':100}))['result']
        expected=[{'name':host,'type':t,'content':address,'proxied':proxy,'ttl':1} for t,address,proxy in targets]
        if any(not address for _,address,_ in targets):raise ValueError('域名没有对应 IP')
        for e in existing:
            if not any(all(e.get(k)==v[k] for k in ('name','type','content','proxied')) for v in expected):raise ValueError('已有 DNS 记录冲突：'+host)
        records.extend(v for v in expected if not any(all(e.get(k)==v[k] for k in ('name','type','content','proxied')) for e in existing))
    tunnel='/accounts/'+z['account']['id']+'/cfd_tunnel/'+tunnel_id+'/configurations'
    before=cf.call(tunnel)['result']['config'];after=copy.deepcopy(before)
    if names.get('cf'):
        ingress=after.get('ingress',[]);service='http://127.0.0.1:'+str(server['protocols']['cf']['port'])
        found=[r for r in ingress if r.get('hostname')==names['cf']]
        if found and (len(found)!=1 or found[0].get('service')!=service):raise ValueError('已有隧道路由冲突')
        if not found:ingress.insert(0,{'hostname':names['cf'],'service':service})
        after['ingress']=ingress
    return {'dns_path':dns,'records':records,'tunnel_path':tunnel,'before':before,'after':after,'server_id':server['id'],'names':names}

def stage(cf,plan,journal):
    if journal.exists():raise ValueError('域名迁移有未完成日志，先执行 domain-recover')
    plan=copy.deepcopy(plan)
    for record in plan['records']:record['comment']='argosbx-fleet-'+secrets.token_hex(12)
    j={'plan':plan,'dns_attempted':[],'tunnel_attempted':False,'ready':False};save(journal,j)
    try:
        for record in plan['records']:
            # Record intent before POST: a lost response must never trigger an untracked duplicate.
            j['dns_attempted'].append(record);save(journal,j)
            existing=cf.call(plan['dns_path']+'?'+urlencode({'name':record['name'],'type':record['type']}))['result']
            if existing:raise ValueError('DNS 已被并发修改')
            cf.call(plan['dns_path'],record,'POST')
        if plan['before']!=plan['after']:
            if cf.call(plan['tunnel_path'])['result']['config']!=plan['before']:raise ValueError('隧道路由已被并发修改')
            j['tunnel_attempted']=True;save(journal,j);cf.call(plan['tunnel_path'],{'config':plan['after']},'PUT')
            if cf.call(plan['tunnel_path'])['result']['config']!=plan['after']:raise ValueError('CF 隧道回读不一致')
        j['ready']=True;save(journal,j)
    except Exception:
        recover(cf,journal);raise
    return {'dns_created':len(plan['records']),'existing_routes_preserved':True,'subscription_changed':False}

def recover(cf,journal):
    if not journal.exists():return
    j=json.loads(journal.read_text());p=j['plan']
    if j['tunnel_attempted']:
        current=cf.call(p['tunnel_path'])['result']['config']
        if current==p['after']:cf.call(p['tunnel_path'],{'config':p['before']},'PUT')
        elif current!=p['before']:raise ValueError('隧道被其他操作修改，保留恢复日志')
    for record in reversed(j['dns_attempted']):
        matches=cf.call(p['dns_path']+'?'+urlencode({'name':record['name'],'type':record['type']}))['result']
        for r in matches:
            if not all(r.get(k)==record[k] for k in ('name','type','content','proxied','comment')):raise ValueError('DNS 已改变，保留恢复日志')
            cf.call(p['dns_path']+'/'+r['id'],method='DELETE')
    journal.unlink()
