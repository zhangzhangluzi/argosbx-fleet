#!/usr/bin/env python3
"""Edit servers.json, validate, inspect a plan, then publish existing subscriptions."""
import argparse
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time
import urllib.request
import urllib.error
from urllib.parse import parse_qsl, urlencode, urlsplit

sys.dont_write_bytecode = True
from fleet import WORKSPACE, STATE, read, active_config

WORK = Path(__file__).resolve().parent
PLAN = STATE/'server-plan.json'
VALIDATION_VERSION = 4


from storage import save, lock
from lease import ensure_owned
import publication
import ad_rules
import stash_refresh
JOURNAL=STATE/'publication-journal.json'
STAGING=STATE/'staging-journal.json'


def digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def generate(config=None):
    sys.path.insert(0, str(WORK))
    # This established generator owns client-specific conversions, rules and ECH.
    with contextlib.redirect_stdout(io.StringIO()):
        runpy.run_path(str(WORK/'generate.py'),init_globals={'inventory_override':config})
    return json.loads((STATE/'substore-payload.json').read_text())


def request(config, path, value=None, method=None, raw=False, user_agent='FlClash/0.8.99'):
    ensure_owned()
    base = config['subscription']['backend_url'].rstrip('/')
    req = urllib.request.Request(base+path, data=None if value is None else json.dumps(value).encode(),
                                 method=method, headers={'Content-Type':'application/json','User-Agent':user_agent})
    with urllib.request.urlopen(req, timeout=45) as r: body = r.read().decode()
    ensure_owned()
    if raw: return body
    result = json.loads(body)
    if result.get('status') != 'success': raise ValueError('Sub-Store API 未成功')
    return result.get('data')


def get(config, kind, name):
    if name not in publication.temporary_names(config,kind,request):return None
    return request(config, '/api/'+('wholeFile' if kind=='file' else kind)+'/'+name)


def summarize(plan):
    return {'服务器数':plan['servers'], '变更对象':[item['kind']+'/'+item['name'] for item in plan['items']
             if item['before']!=item['after']], '已保存计划':str(PLAN), '订阅地址保持':True}


def native_preflight(config):
    from fleetctl import remote
    from protocols import protocol_type
    from concurrent.futures import ThreadPoolExecutor
    configured=[s for s in config['servers'] if s.get('status','active')=='active' and s.get('protocols')]
    def check(server):
        live=remote(config,server['id'],'inspect')
        if live['protocols']!=server['protocols'] or live['certificates']!=server['certificates']:
            raise ValueError(server['id']+'：原生参数尚未应用，不能先发布客户端引用')
        if not live.get('native_configuration_matches') or not live.get('services_active'):
            raise ValueError(server['id']+'：服务未就绪或原生配置存在漂移')
        if live.get('unfinished_transactions') or live.get('source_matches') is not True:
            raise ValueError(server['id']+'：事务未恢复或订阅源与服务端不一致')
        uses_cf=any(p.get('enabled') and protocol_type(ident,p) in ('cf','xhttp') for ident,p in server['protocols'].items())
        cf=live.get('cloudflare_health',{})
        if uses_cf and (not cf.get('service_active') or cf.get('ready') is False):
            raise ValueError(server['id']+'：CF 隧道未就绪，未发布订阅')
        if live.get('certificate_health') is None or any(not v['usable'] for v in live['certificate_health'].values()):
            raise ValueError(server['id']+'：证书尚未验收或已失效')
    with ThreadPoolExecutor(max_workers=min(4,max(1,len(configured)))) as pool:list(pool.map(check,configured))


def prepare(config,owner=None):
    if JOURNAL.exists() or STAGING.exists():raise ValueError('有未完成发布事务，请先执行 recover')
    native_preflight(config)
    snapshot = ad_rules.load(config)
    if snapshot:
        ad_rules.verify_asset(config, snapshot)
    payload=generate(config)
    items=[]
    for key,kind in [('subscriptions','sub'),('collections','collection'),('files','file')]:
        for candidate in payload[key]:
            before=get(config,kind,candidate['name'])
            after=copy.deepcopy(before or {}); after.update(candidate)
            items.append({'kind':kind,'name':candidate['name'],'before':before,'after':after})
    plan={'validation_version':VALIDATION_VERSION,'inventory_sha256':digest(config),'servers':len(config['servers']),'items':items}
    if snapshot:
        plan['ad_rules_sha256']=digest(snapshot)
    # Validate in isolated native Sub-Store objects before changing production.
    plan['rendered_sha256']=stage(config, payload,owner=owner) if owner else stage(config,payload)
    save(PLAN,plan)
    return plan


def stage(config, payload,owner=None):
    import secrets
    import yaml
    journal=publication.begin(STAGING,config,digest,owner=owner)
    prefix='server-check-'+secrets.token_hex(5)
    created=journal['temporary']
    def creating(kind,name):
        created.append((kind,name));save(STAGING,journal)
    rendered={}
    ad_domains = None
    has_ads = any(file['name'] == 'shadowrocket-ads' for file in payload['files'])
    aliases={s['name']:prefix+'-'+str(i) for i,s in enumerate(payload['subscriptions'])}
    try:
        for source in payload['subscriptions']:
            sub=copy.deepcopy(source);sub['name']=aliases[source['name']]
            for op in sub['process']:
                if op['type']=='Response Transformer':op['args']['arguments'].update(profile=prefix+'-clash',stash_profile=prefix+'-stash')
            creating('sub',sub['name'])
            request(config,'/api/subs',sub,'POST')
        col=copy.deepcopy(payload['collections'][0]);col['name']=prefix
        col['subscriptions']=[aliases[n] for n in col['subscriptions']];col['process']=[]
        creating('collection',prefix);request(config,'/api/collections',col,'POST')
        # Sub-Store's mihomoConfig file path does not forward noCache to its
        # collection. Refresh the isolated collection before validating files.
        request(config,'/download/collection/'+prefix+'?target=URI&noCache=true',raw=True)
        expected=[]
        for source in payload['files']:
            if source['name']=='shadowrocket-config': continue
            f=copy.deepcopy(source);f['name']=prefix+'-'+source['name'];f['sourceName']=prefix
            if source['name']=='stash':
                args=f['process'][0]['args']
                args['content']=stash_refresh.template(args['content'], 'stash', config['subscription']['public_url'], staged_name=f['name'])
            creating('file',f['name']);request(config,'/api/files',f,'POST')
            if source['name']=='shadowrocket-ads':
                raw=request(config,'/api/file/'+f['name'],raw=True)
                check_sr_ads(raw)
                ad_domains = raw
                rendered[source['name']]=digest(raw)
                continue
            raw=stash_file(config,f['name'],'Stash/3.6.0') if source['name']=='stash' else request(config,'/api/file/'+f['name'],raw=True)
            value=yaml.safe_load(raw)
            check_profile(value)
            if has_ads:
                ad_rules.check_profile(value, source['name'])
            save(STATE/('validated-'+source['name']+'.json'),value)
            rendered[source['name']]=digest(value)
            names=[n['name'] for n in value['proxies']]
            if expected and names!=expected:raise ValueError('两种客户端节点名称不一致')
            expected=names
            if source['name']=='stash':rendered.update(check_stash_file_cases(config,f['name'],value))
        sr=next(f['content'] for f in payload['files'] if f['name']=='shadowrocket-config')
        if ad_domains is not None:
            ad_rules.check_shadowrocket(sr, ad_domains, config['subscription']['backend_url'].rstrip('/')+'/api/file/shadowrocket-ads')
        body=sr.split('[Proxy Group]',1)[1].split('\n[',1)[0]
        sr_names=[]
        for line in body.splitlines():
            if '= url-test,' in line:
                sr_names += [x.strip() for x in line.split('= url-test,',1)[1].split(',') if '=' not in x]
        if set(sr_names)!=set(expected):raise ValueError('Shadowrocket 分组与实际节点不一致')
        rendered['shadowrocket-config']=digest(sr)
        if any(op['type']=='Response Transformer' for op in payload['collections'][0].get('process',[])):
            # Exercise the actual download route as well as the canonical files.
            # Native node conversion alone did not verify a full Stash profile.
            col=copy.deepcopy(payload['collections'][0]);col['name']=prefix
            col['subscriptions']=[aliases[n] for n in col['subscriptions']]
            for op in col['process']:
                if op['type']=='Response Transformer':op['args']['arguments'].update(profile=prefix+'-clash',stash_profile=prefix+'-stash')
            request(config,'/api/collection/'+prefix,col,'PATCH')
            for key,(target,ua) in DOWNLOAD_CASES.items():
                raw=request(config,'/download/collection/'+prefix+'?target='+target,raw=True,user_agent=ua)
                stash_refresh.check(raw)
                value=yaml.safe_load(raw)
                check_profile(value)
                full=json.loads((STATE/('validated-'+('stash' if target=='Stash' else 'clash')+'.json')).read_text())
                expected=stash_expected_profile(full,key!='download-stash') if target=='Stash' else full
                check_equivalent_profile(value,expected,key)
                rendered[key]=digest(value)
        for country in payload['collections'][1:]:
            col=copy.deepcopy(country);col['name']=prefix+'-'+country['name']
            for op in col['process']:
                if op['type']=='Response Transformer':op['args']['arguments'].update(profile=prefix+'-clash',stash_profile=prefix+'-stash')
            col['subscriptions']=[aliases[n] for n in country['subscriptions']]
            creating('collection',col['name']);request(config,'/api/collections',col,'POST')
            prefixes=[s['name'] for s in active_config(config)['servers'] if s['subscription']['name'] in country['subscriptions']]
            for key,(target,ua) in DOWNLOAD_CASES.items():
                raw=request(config,'/download/collection/'+col['name']+'?target='+target,raw=True,user_agent=ua)
                stash_refresh.check(raw)
                value=yaml.safe_load(raw)
                full=json.loads((STATE/('validated-'+('stash' if target=='Stash' else 'clash')+'.json')).read_text())
                expected=stash_expected_profile(full,key!='download-stash') if target=='Stash' else full
                expected=subset_profile(expected,[n for n in expected['proxies'] if any(n['name'].startswith(p+'-T-') or n['name'].startswith(p+'-U-') for p in prefixes)])
                check_equivalent_profile(value,expected,country['name']+'/'+key)
                rendered['country-profile:'+country['name']+':'+key]=digest(value)
            uri=request(config,'/download/collection/'+col['name']+'?target=URI',raw=True)
            rendered[country['name']]=digest(uri)
    finally:
        publication.recover(STAGING,config,get,request,digest,owner=owner)
    return rendered


DOWNLOAD_CASES={
    'download-clash':('ClashMeta','FlClash/0.8.99'),
    'download-stash':('Stash','Stash/3.4.0'),
    'download-stash-modern':('Stash','Stash/3.6.0'),
}

STASH_FILE_CASES={
    'file-stash-compatible':'Stash/3.4.0',
    'file-stash-mac-compatible':'StashMac/4.2.0',
    'file-stash-mac-modern':'StashMac/4.3.0',
    'file-stash-versionless':'Stash',
}

def stash_file(config,name,user_agent):
    raw=request(config,'/api/file/'+name,raw=True,user_agent=user_agent)
    stash_refresh.check(raw,stash_refresh.update_url('stash',config['subscription']['public_url']))
    return raw


def check_stash_file_cases(config,name,full):
    import yaml
    rendered={}
    for key,ua in STASH_FILE_CASES.items():
        value=yaml.safe_load(stash_file(config,name,ua))
        expected=stash_expected_profile(full,key=='file-stash-mac-modern')
        check_equivalent_profile(value,expected,key)
        rendered[key]=digest(value)
    return rendered


def stash_expected_profile(full,modern):
    expected=copy.deepcopy(full)
    if not modern:
        expected=subset_profile(expected,[n for n in expected['proxies'] if n.get('network')!='xhttp' and not(n['type']=='vless' and n.get('encryption') not in (None,'','none'))])
        policy=expected['dns']['nameserver-policy']
        policy['geosite:cn']=policy.pop('rule-set:国内域名')
    return expected


def subset_profile(full,nodes):
    """Retain exact settings and order while removing absent nodes/country groups."""
    expected=copy.deepcopy(full);expected['proxies']=copy.deepcopy(nodes)
    groups=expected['proxy-groups']
    allowed={n['name'] for n in nodes}|{g['name'] for g in groups}|{'DIRECT','REJECT','PASS'}
    while True:
        for g in groups:g['proxies']=[p for p in g['proxies'] if p in allowed]
        empty={g['name'] for g in groups if not g['proxies']}
        if not empty:break
        groups[:]=[g for g in groups if g['name'] not in empty];allowed-=empty
    check_profile(expected)
    return expected


def check_equivalent_profile(value,expected,label):
    check_profile(value)
    if value!=expected:
        # Field names only: node values and private DNS/source URLs stay private.
        fields=sorted(k for k in set(value)|set(expected) if value.get(k)!=expected.get(k))
        raise ValueError('客户端完整配置与预期不符：'+label+'；字段：'+','.join(fields))


def check_sr_ads(raw):
    import re
    lines=raw.splitlines()
    if not lines or any(not re.fullmatch(r'\.?[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+',s) for s in lines):
        raise ValueError('Shadowrocket 广告域名集格式无效')
    if len(lines)!=len(set(lines)):raise ValueError('Shadowrocket 广告域名集重复')


def check_profile(value):
    if not isinstance(value,dict) or not all(k in value for k in ('proxies','proxy-groups','rules')):raise ValueError('Sub-Store 未生成完整配置，处理器可能报错')
    nodes=[n['name'] for n in value['proxies']]
    groups=value['proxy-groups'];group_names=[g['name'] for g in groups]
    if not nodes or not groups or len(set(nodes+group_names))!=len(nodes+group_names) or not value['rules']:
        raise ValueError('节点、分组重复或规则为空')
    allowed=set(nodes+group_names+['DIRECT','REJECT']+([] if value.get('dns',{}).get('follow-rule') else ['PASS']))
    for g in groups:
        if not g['proxies'] or any(p not in allowed for p in g['proxies']):raise ValueError('分组引用无效')
    graph={g['name']:[p for p in g['proxies'] if p in group_names] for g in groups}
    def visit(name,path):
        if name in path:raise ValueError('分组循环引用')
        for nxt in graph[name]:visit(nxt,path|{name})
    for name in graph:visit(name,set())

    providers=value.get('rule-providers',{})
    for rule in value['rules']:
        parts=rule.split(',')
        if parts[-1]=='no-resolve':parts=parts[:-1]
        if len(parts)<2 or parts[-1] not in allowed:raise ValueError('规则目标引用无效')
        if parts[0]=='RULE-SET' and (len(parts)!=3 or parts[1] not in providers):raise ValueError('规则集引用无效')
        if parts[0]=='SCRIPT' and parts[1] not in value.get('script',{}).get('shortcuts',{}):raise ValueError('规则脚本引用无效')
    for key in value.get('dns',{}).get('nameserver-policy',{}):
        if key.startswith('rule-set:') and any(p not in providers for p in key[9:].split(',')):
            raise ValueError('DNS 规则集引用无效')


def verify_published(config,plan):
    import yaml
    for fmt in ['clash','stash']:
        raw=stash_file(config,fmt,'Stash/3.6.0') if fmt=='stash' else request(config,'/api/file/'+fmt,raw=True)
        value=yaml.safe_load(raw)
        check_profile(value)
        ad_rules.check_profile(value, fmt)
        if digest(value)!=plan['rendered_sha256'][fmt]:raise ValueError('线上输出与已校验计划不符')
        if fmt=='stash':
            for key,sha in check_stash_file_cases(config,fmt,value).items():
                if sha!=plan['rendered_sha256'][key]:raise ValueError('Stash 文件输出与已校验计划不符：'+key)
    if digest(request(config,'/api/file/shadowrocket-config',raw=True))!=plan['rendered_sha256']['shadowrocket-config']:
        raise ValueError('Shadowrocket 策略与已校验计划不符')
    if 'shadowrocket-ads' in plan['rendered_sha256']:
        raw=request(config,'/api/file/shadowrocket-ads',raw=True);check_sr_ads(raw)
        if digest(raw)!=plan['rendered_sha256']['shadowrocket-ads']:raise ValueError('广告域名集已更新，请重新 plan')
    for key,(target,ua) in DOWNLOAD_CASES.items():
        if key not in plan['rendered_sha256']:continue
        raw=request(config,'/download/collection/all?target='+target,raw=True,user_agent=ua)
        refresh=stash_refresh.update_url('stash',config['subscription']['public_url']) if target=='Stash' else None
        stash_refresh.check(raw,refresh)
        value=yaml.safe_load(raw)
        check_profile(value)
        if digest(value)!=plan['rendered_sha256'][key]:raise ValueError('客户端导出与已校验计划不符：'+key)
    for key,wanted in plan['rendered_sha256'].items():
        if not key.startswith('country-profile:'):continue
        _,name,case=key.split(':');target,ua=DOWNLOAD_CASES[case]
        raw=request(config,'/download/collection/'+name+'?target='+target,raw=True,user_agent=ua)
        stash_refresh.check(raw)
        value=yaml.safe_load(raw)
        check_profile(value)
        if digest(value)!=wanted:raise ValueError('国家完整配置与已校验计划不符：'+name+'/'+case)
    for name,wanted in plan['rendered_sha256'].items():
        if not name.startswith('shadowrocket-') or name in ('shadowrocket-config','shadowrocket-ads'):continue
        value=request(config,'/download/collection/'+name+'?target=URI',raw=True)
        if digest(value)!=wanted:raise ValueError('国家订阅与已校验计划不符：'+name)
    public=config['subscription']['public_url']
    req=urllib.request.Request(public,headers={'User-Agent':'FlClash/0.8.99'})
    with urllib.request.urlopen(req,timeout=45) as r:value=yaml.safe_load(r.read())
    if value!=yaml.safe_load(request(config,'/api/file/clash',raw=True)):
        raise ValueError('原统一订阅回读不一致')
    stash_url=stash_refresh.update_url('stash',public)
    req=urllib.request.Request(stash_url,headers={'User-Agent':'Mozilla/5.0'})
    with urllib.request.urlopen(req,timeout=45) as r:raw=r.read().decode()
    stash_refresh.check(raw,stash_url)
    check_equivalent_profile(yaml.safe_load(raw),yaml.safe_load(stash_file(config,'stash','Mozilla/5.0')),'原统一 Stash 订阅')


def publish(config,defer_commit=False,owner=None):
    plan=json.loads(PLAN.read_text())
    if plan.get('validation_version')!=VALIDATION_VERSION:raise ValueError('验收规则已更新，请重新 plan')
    if plan['inventory_sha256']!=digest(config):raise ValueError('资料已改变，请重新 plan')
    native_preflight(config)
    snapshot = ad_rules.load(config)
    if plan.get('ad_rules_sha256') != (digest(snapshot) if snapshot else None):
        raise ValueError('广告名单版本已改变，请重新 plan')
    if snapshot:
        ad_rules.verify_asset(config, snapshot)
    if any(get(config,x['kind'],x['name'])!=x['before'] for x in plan['items']):
        raise ValueError('线上配置已改变，请重新 plan')
    if defer_commit and not owner:raise ValueError('延迟提交需要接入事务标识')
    journal=publication.begin(JOURNAL,config,digest,owner=owner)
    attempted=journal['attempted']
    try:
        for item in plan['items']:
            if item['before']==item['after']:continue
            if get(config,item['kind'],item['name'])!=item['before']:raise ValueError('检测到并发修改')
            attempted.append(item);save(JOURNAL,journal)
            request(config,'/api/'+({'sub':'subs','collection':'collections','file':'files'}[item['kind']] if item['before'] is None else item['kind']+'/'+item['name']),item['after'],'POST' if item['before'] is None else 'PATCH')
            if get(config,item['kind'],item['name'])!=item['after']:raise ValueError('发布回读不一致')
        verify_published(config,plan)
    except Exception:
        publication.recover(JOURNAL,config,get,request,digest,owner=owner)
        raise
    if not defer_commit:
        JOURNAL.unlink();PLAN.unlink()
    return {'发布成功':True,'修改对象数':len(attempted),'原订阅回读':True,'代理进程重启':False,'待接入提交':defer_commit}


def verify_committed_plan(config):
    if not PLAN.exists():raise ValueError('接入发布计划缺失')
    plan=json.loads(PLAN.read_text())
    if plan.get('validation_version')!=VALIDATION_VERSION or plan['inventory_sha256']!=digest(config):
        raise ValueError('接入发布计划与服务器资料不一致')
    if any(get(config,item['kind'],item['name'])!=item['after'] for item in plan['items']):
        raise ValueError('接入发布后线上对象发生变化，保留事务')
    native_preflight(config)
    verify_published(config,plan)
    return {'verified':True}

def commit_deferred(config,owner):
    if not JOURNAL.exists():raise ValueError('接入发布事务缺失')
    journal=json.loads(JOURNAL.read_text())
    if journal.get('owner')!=owner or journal.get('backend_sha256')!=digest(config['subscription']['backend_url']):raise ValueError('接入发布归属或后端已变化')
    verify_committed_plan(config)
    JOURNAL.unlink()
    return {'committed':True}


def sync_standard_rules(config):
    """Run after releasing the publication lease; the remote command locks itself."""
    from fleet import ssh_args
    ident=config.get('coordinator')
    if not ident:return {'status':'not_configured'}
    try:
        proc=subprocess.run(ssh_args(ident,config)+[
            'python3 -B /opt/argosbx-fleet/current/standard_rule_source.py refresh --if-configured'],
            text=True,capture_output=True,timeout=150)
        if proc.returncode:return {'status':'failed'}
        value=json.loads(proc.stdout)
        if value.get('configured') is False:return {'status':'not_configured'}
        if value.get('configured') is True and value.get('verified') is True:
            return {'status':'verified','updated':value.get('updated',0)}
    except (OSError,ValueError,TypeError,subprocess.SubprocessError):
        pass
    return {'status':'failed'}


def sync_retired_countries(config):
    """Retire only countries without an active server and verify the old URL."""
    from fleet import ssh_args
    active={s['country'] for s in config['servers'] if s.get('status','active')=='active'}
    retired=sorted({s['country'] for s in config['servers'] if s.get('status','active')=='pending'}-active)
    ident=config.get('coordinator')
    if not ident:return {'status':'not_configured'}
    args=ssh_args(ident,config);script='/opt/argosbx-fleet/current/country_routes.py '
    def command(action,body=None):
        proc=subprocess.run(args+['python3 -B '+script+action],input=None if body is None else json.dumps(body),
                            text=True,capture_output=True,timeout=45)
        if proc.returncode:raise RuntimeError('国家订阅路由操作失败')
        return json.loads(proc.stdout)
    changed=False
    try:
        staged=command('retired-stage',{'countries':retired});changed=staged.get('changed') is True
        parsed=urlsplit(config['subscription']['public_url'])
        base=[(k,v) for k,v in parse_qsl(parsed.query,keep_blank_values=True) if k!='format']
        for country in sorted(active|set(retired)):
            url=parsed._replace(query=urlencode(base+[('format','shadowrocket-'+country.lower())])).geturl()
            req=urllib.request.Request(url,headers={'User-Agent':'Shadowrocket/2.2.72'})
            wanted=410 if country in retired else 200
            for attempt in range(5):
                try:
                    with urllib.request.urlopen(req,timeout=10) as response:status=response.status
                except urllib.error.HTTPError as error:
                    status=error.code;error.close()
                if status==wanted:break
                if attempt<4:time.sleep(.25)
            if status!=wanted:raise ValueError('国家订阅回读失败')
        if changed:command('retired-finish')
        return {'status':'verified','retired':retired}
    except (OSError,ValueError,RuntimeError,TypeError,subprocess.SubprocessError):
        if changed:
            try:command('retired-recover')
            except (OSError,ValueError,RuntimeError,TypeError,subprocess.SubprocessError):
                return {'status':'failed_recovery_pending'}
        return {'status':'failed'}


def main():
    p=argparse.ArgumentParser(description='ArgoSBX 服务器资料与原 Sub-Store 订阅维护')
    p.add_argument('command',choices=['check','generate','plan','publish','recover'])
    p.add_argument('--config',help='0600 私有 JSON，默认 .vpn-deploy/servers.json')
    args=p.parse_args()
    if args.config:os.environ['ARGOSBX_SERVERS_FILE']=str(Path(args.config).expanduser().resolve())
    try:
        config=read()
        if args.command in ('plan','publish','recover') and (STATE/'onboarding-publication.json').exists():
            raise ValueError('存在未完成新机接入发布；请先运行原 onboard.py install 继续恢复')
        from lease import coordinator
        with (coordinator(config) if args.command in ('plan','publish','recover') else contextlib.nullcontext()):
            if args.command=='check':result={'校验通过':True,'服务器':[s['id'] for s in config['servers']]}
            elif args.command=='generate':result={'生成成功':True,'文件':str(STATE/'substore-payload.json'),'订阅源数量':len(generate(config)['subscriptions'])}
            elif args.command=='plan':result=summarize(prepare(config))
            elif args.command=='publish':result=publish(config)
            else:result=[publication.recover(p,config,get,request,digest) for p in [JOURNAL,STAGING]]
        if args.command=='publish':
            result['独立规则同步']=sync_standard_rules(config)
            result['国家订阅路由']=sync_retired_countries(config)
            if result['独立规则同步']['status']=='failed' or result['国家订阅路由']['status'].startswith('failed'):
                print(json.dumps(result,ensure_ascii=False));raise SystemExit(2)
        print(json.dumps(result,ensure_ascii=False))
    except Exception as error:
        # Library/network exceptions can contain private subscription URLs.
        message=str(error) if isinstance(error,(ValueError,RuntimeError)) else type(error).__name__
        print('操作停止：'+message,file=sys.stderr);raise SystemExit(1)


if __name__=='__main__':
    with lock(STATE/'publisher.lock'):main()
