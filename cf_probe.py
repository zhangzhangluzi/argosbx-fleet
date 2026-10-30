"""Opt-in write round trips on disposable DNS/tunnel resources, with owned cleanup."""
import hashlib
import json
import re
import secrets
from pathlib import Path
from urllib.parse import urlencode

from storage import save
from domains import CloudflareAPIError


def zones_for(cf,server):
    hosts={h for h in server['domains'].values() if h}
    found={}
    zones=cf.zones()
    for host in hosts:
        matches=sorted((z for z in zones if z.get('status')=='active' and (host==z['name'] or host.endswith('.'+z['name']))),key=lambda z:len(z['name']),reverse=True)
        if not matches:raise ValueError('域名不在授权区域中，未创建测试资源')
        found[matches[0]['id']]=matches[0]
    return list(found.values())


def recover(cf,journal):
    journal=Path(journal)
    if not journal.exists():return {'cleaned':True,'resources':0}
    value=json.loads(journal.read_text())
    if value.get('token_sha256')!=hashlib.sha256(cf.token.encode()).hexdigest():raise ValueError('测试日志与当前 Token 不匹配；未清理')
    count=0
    for item in reversed(value['items']):
        nonce=item['nonce']
        if not re.fullmatch(r'[a-f0-9]{24}',nonce):raise ValueError('无效测试资源身份')
        if item['kind']=='tunnel':
            base='/accounts/'+item['account']+'/cfd_tunnel'
            rows=cf.call(base+'?'+urlencode({'name':'argosbx-permission-check-'+nonce,'is_deleted':'false'}))['result']
            for row in rows:
                if row.get('name')!='argosbx-permission-check-'+nonce:continue
                detail=cf.call(base+'/'+row['id'])['result']
                if detail.get('name')!=row['name']:raise ValueError('测试隧道身份变化，保留日志并停止清理')
                if item.get('configuration_attempted'):
                    try:config=cf.call(base+'/'+row['id']+'/configurations')['result']['config']
                    except CloudflareAPIError as error:
                        if error.status!=404:raise
                        config=None
                    if config is not None and config.get('ingress')!=[{'service':'http_status:404'}]:raise ValueError('测试隧道配置已变化，保留日志并停止清理')
                from tunnels import assert_disconnected
                assert_disconnected(cf,base+'/'+row['id'],detail)
                cf.call(base+'/'+row['id'],method='DELETE');count+=1
            remaining=cf.call(base+'?'+urlencode({'name':'argosbx-permission-check-'+nonce,'is_deleted':'false'}))['result']
            if any(r.get('name')=='argosbx-permission-check-'+nonce for r in remaining):raise ValueError('测试隧道删除未确认，保留日志')
        elif item['kind']=='dns':
            base='/zones/'+item['zone']+'/dns_records'
            name='_fleet-permission-check-'+nonce+'.'+item['zone_name']
            rows=cf.call(base+'?'+urlencode({'name':name,'type':'TXT'}))['result']
            for row in rows:
                if row.get('name')!=name:continue
                if row.get('type')!='TXT' or row.get('comment')!='argosbx-permission-check-'+nonce or row.get('content') not in ('first-'+nonce,'second-'+nonce):
                    raise ValueError('测试 DNS 已被其他操作修改，保留日志')
                cf.call(base+'/'+row['id'],method='DELETE');count+=1
            if cf.call(base+'?'+urlencode({'name':name,'type':'TXT'}))['result']:raise ValueError('测试 DNS 删除未确认，保留日志')
        else:raise ValueError('未知测试资源，未清理')
    journal.unlink()
    return {'cleaned':True,'resources':count}


def verify(cf,server,journal):
    journal=Path(journal)
    if journal.exists():raise ValueError('有未清理的测试资源，先运行 cf-audit --recover-writes')
    zones=zones_for(cf,server)
    value={'token_sha256':hashlib.sha256(cf.token.encode()).hexdigest(),'items':[]}
    results=[];phase='preflight'
    try:
        for zone in zones:
            nonce=secrets.token_hex(12);item={'kind':'dns','nonce':nonce,'zone':zone['id'],'zone_name':zone['name']}
            value['items'].append(item);save(journal,value)
            base='/zones/'+zone['id']+'/dns_records';name='_fleet-permission-check-'+nonce+'.'+zone['name']
            # Intent is durable before POST; cleanup can locate a response-lost create.
            expected={'name':name,'type':'TXT','content':'first-'+nonce,'ttl':120,'comment':'argosbx-permission-check-'+nonce}
            phase='dns_create';row=cf.call(base,expected,'POST')['result'];endpoint=base+'/'+row['id']
            got=cf.call(endpoint)['result']
            if any(got.get(k)!=v for k,v in expected.items()):raise ValueError('测试 DNS 创建回读不一致')
            phase='dns_update';cf.call(endpoint,{'content':'second-'+nonce},'PATCH')
            got=cf.call(endpoint)['result']
            if got.get('content')!='second-'+nonce or got.get('comment')!=expected['comment']:raise ValueError('测试 DNS 更新回读不一致')
            results.append({'kind':'dns','zone':zone['name'],'create_verified':True,'update_verified':True})
        for account in sorted({z['account']['id'] for z in zones}):
            nonce=secrets.token_hex(12);item={'kind':'tunnel','nonce':nonce,'account':account}
            value['items'].append(item);save(journal,value)
            base='/accounts/'+account+'/cfd_tunnel';name='argosbx-permission-check-'+nonce
            phase='tunnel_create';row=cf.call(base,{'name':name,'config_src':'cloudflare'},'POST')['result']
            if row.get('name')!=name:raise ValueError('测试隧道身份回读不一致')
            endpoint=base+'/'+row['id']+'/configurations'
            expected={'ingress':[{'service':'http_status:404'}]}
            item['configuration_attempted']=True;save(journal,value)
            phase='tunnel_configure';cf.call(endpoint,{'config':expected},'PUT')
            if cf.call(endpoint)['result']['config'].get('ingress')!=expected['ingress']:raise ValueError('测试隧道配置回读不一致')
            results.append({'kind':'tunnel','account':account,'create_verified':True,'configuration_verified':True,
                            'connectors_started':False,'dns_routes_created':False})
    except Exception as error:
        try:recover(cf,journal)
        except Exception:raise RuntimeError('测试结果未确认且清理未完成；保留私有日志，运行 cf-audit --recover-writes') from None
        detail={'phase':phase,'type':type(error).__name__,'http_status':getattr(error,'status',None),'api_codes':list(getattr(error,'codes',()))}
        raise RuntimeError('独立资源写权限测试失败 '+json.dumps(detail)+'；已清理测试资源，正式配置未修改') from None
    cleanup=recover(cf,journal)
    return {'writes_tested':True,'passed':True,'cleanup_verified':cleanup['cleaned'],'results':results,
            'production_dns_changed':False,'production_tunnels_changed':False}
