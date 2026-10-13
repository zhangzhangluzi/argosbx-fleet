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
import sys
import urllib.request

sys.dont_write_bytecode = True
from fleet import WORKSPACE, STATE, read

WORK = Path(__file__).resolve().parent
PLAN = STATE/'server-plan.json'


from storage import save, lock
from lease import ensure_owned
import publication
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


def request(config, path, value=None, method=None, raw=False):
    ensure_owned()
    base = config['subscription']['backend_url'].rstrip('/')
    req = urllib.request.Request(base+path, data=None if value is None else json.dumps(value).encode(),
                                 method=method, headers={'Content-Type':'application/json','User-Agent':'FlClash/0.8.99'})
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
    from concurrent.futures import ThreadPoolExecutor
    configured=[s for s in config['servers'] if s.get('protocols')]
    def check(server):
        live=remote(config,server['id'],'inspect')
        if live['protocols']!=server['protocols'] or live['certificates']!=server['certificates']:
            raise ValueError(server['id']+'：原生参数尚未应用，不能先发布客户端引用')
        if not live.get('native_configuration_matches') or not live.get('services_active'):
            raise ValueError(server['id']+'：服务未就绪或原生配置存在漂移')
        if live.get('unfinished_transactions') or live.get('source_matches') is not True:
            raise ValueError(server['id']+'：事务未恢复或订阅源与服务端不一致')
        if live.get('certificate_health') is None or any(not v['usable'] for v in live['certificate_health'].values()):
            raise ValueError(server['id']+'：证书尚未验收或已失效')
    with ThreadPoolExecutor(max_workers=min(4,max(1,len(configured)))) as pool:list(pool.map(check,configured))


def prepare(config):
    if JOURNAL.exists() or STAGING.exists():raise ValueError('有未完成发布事务，请先执行 recover')
    native_preflight(config)
    payload=generate(config)
    items=[]
    for key,kind in [('subscriptions','sub'),('collections','collection'),('files','file')]:
        for candidate in payload[key]:
            before=get(config,kind,candidate['name'])
            after=copy.deepcopy(before or {}); after.update(candidate)
            items.append({'kind':kind,'name':candidate['name'],'before':before,'after':after})
    plan={'inventory_sha256':digest(config),'servers':len(config['servers']),'items':items}
    # Validate in isolated native Sub-Store objects before changing production.
    plan['rendered_sha256']=stage(config, payload)
    save(PLAN,plan)
    return plan


def stage(config, payload):
    import secrets
    import yaml
    journal=publication.begin(STAGING,config,digest)
    prefix='server-check-'+secrets.token_hex(5)
    created=journal['temporary']
    def creating(kind,name):
        created.append((kind,name));save(STAGING,journal)
    rendered={}
    aliases={s['name']:prefix+'-'+str(i) for i,s in enumerate(payload['subscriptions'])}
    try:
        for source in payload['subscriptions']:
            sub=copy.deepcopy(source);sub['name']=aliases[source['name']]
            for op in sub['process']:
                if op['type']=='Response Transformer':op['args']['arguments']['profile']=prefix+'-clash'
            creating('sub',sub['name'])
            request(config,'/api/subs',sub,'POST')
        col=copy.deepcopy(payload['collections'][0]);col['name']=prefix
        col['subscriptions']=[aliases[n] for n in col['subscriptions']];col['process']=[]
        creating('collection',prefix);request(config,'/api/collections',col,'POST')
        expected=[]
        for source in payload['files']:
            if source['name']=='shadowrocket-config': continue
            f=copy.deepcopy(source);f['name']=prefix+'-'+source['name'];f['sourceName']=prefix
            creating('file',f['name']);request(config,'/api/files',f,'POST')
            value=yaml.safe_load(request(config,'/api/file/'+f['name'],raw=True))
            check_profile(value)
            save(STATE/('validated-'+source['name']+'.json'),value)
            rendered[source['name']]=digest(value)
            names=[n['name'] for n in value['proxies']]
            if expected and names!=expected:raise ValueError('两种客户端节点名称不一致')
            expected=names
        sr=next(f['content'] for f in payload['files'] if f['name']=='shadowrocket-config')
        body=sr.split('[Proxy Group]',1)[1].split('\n[',1)[0]
        sr_names=[]
        for line in body.splitlines():
            if '= url-test,' in line:
                sr_names += [x.strip() for x in line.split('= url-test,',1)[1].split(',') if '=' not in x]
        if set(sr_names)!=set(expected):raise ValueError('Shadowrocket 分组与实际节点不一致')
        rendered['shadowrocket-config']=digest(sr)
    finally:
        publication.recover(STAGING,config,get,request,digest)
    return rendered


def check_profile(value):
    if not isinstance(value,dict) or not all(k in value for k in ('proxies','proxy-groups','rules')):raise ValueError('Sub-Store 未生成完整配置，处理器可能报错')
    nodes=[n['name'] for n in value['proxies']]
    groups=value['proxy-groups'];group_names=[g['name'] for g in groups]
    if not nodes or len(set(nodes+group_names))!=len(nodes+group_names) or not value['rules']:
        raise ValueError('节点、分组重复或规则为空')
    allowed=set(nodes+group_names+['DIRECT','REJECT'])
    for g in groups:
        if not g['proxies'] or any(p not in allowed for p in g['proxies']):raise ValueError('分组引用无效')
    graph={g['name']:[p for p in g['proxies'] if p in group_names] for g in groups}
    def visit(name,path):
        if name in path:raise ValueError('分组循环引用')
        for nxt in graph[name]:visit(nxt,path|{name})
    for name in graph:visit(name,set())


def publish(config):
    plan=json.loads(PLAN.read_text())
    if plan['inventory_sha256']!=digest(config):raise ValueError('资料已改变，请重新 plan')
    native_preflight(config)
    if any(get(config,x['kind'],x['name'])!=x['before'] for x in plan['items']):
        raise ValueError('线上配置已改变，请重新 plan')
    journal=publication.begin(JOURNAL,config,digest)
    attempted=journal['attempted']
    try:
        for item in plan['items']:
            if item['before']==item['after']:continue
            if get(config,item['kind'],item['name'])!=item['before']:raise ValueError('检测到并发修改')
            attempted.append(item);save(JOURNAL,journal)
            request(config,'/api/'+({'sub':'subs','collection':'collections','file':'files'}[item['kind']] if item['before'] is None else item['kind']+'/'+item['name']),item['after'],'POST' if item['before'] is None else 'PATCH')
            if get(config,item['kind'],item['name'])!=item['after']:raise ValueError('发布回读不一致')
        import yaml
        for fmt in ['clash','stash']:
            value=yaml.safe_load(request(config,'/api/file/'+fmt,raw=True))
            check_profile(value)
            if digest(value)!=plan['rendered_sha256'][fmt]:raise ValueError('线上输出与已校验计划不符')
        if digest(request(config,'/api/file/shadowrocket-config',raw=True))!=plan['rendered_sha256']['shadowrocket-config']:
            raise ValueError('Shadowrocket 策略与已校验计划不符')
        public=config['subscription']['public_url']
        req=urllib.request.Request(public,headers={'User-Agent':'FlClash/0.8.99'})
        with urllib.request.urlopen(req,timeout=45) as r:value=yaml.safe_load(r.read())
        if value!=yaml.safe_load(request(config,'/api/file/clash',raw=True)):
            raise ValueError('原统一订阅回读不一致')
    except Exception:
        publication.recover(JOURNAL,config,get,request,digest)
        raise
    JOURNAL.unlink()
    PLAN.unlink()
    return {'发布成功':True,'修改对象数':len(attempted),'原订阅回读':True,'代理进程重启':False}


def main():
    p=argparse.ArgumentParser(description='ArgoSBX 服务器资料与原 Sub-Store 订阅维护')
    p.add_argument('command',choices=['check','generate','plan','publish','recover'])
    p.add_argument('--config',help='0600 私有 JSON，默认 .vpn-deploy/servers.json')
    args=p.parse_args()
    if args.config:os.environ['ARGOSBX_SERVERS_FILE']=str(Path(args.config).expanduser().resolve())
    try:
        config=read()
        from lease import coordinator
        with (coordinator(config) if args.command in ('plan','publish','recover') else contextlib.nullcontext()):
            if args.command=='check':result={'校验通过':True,'服务器':[s['id'] for s in config['servers']]}
            elif args.command=='generate':result={'生成成功':True,'文件':str(STATE/'substore-payload.json'),'订阅源数量':len(generate(config)['subscriptions'])}
            elif args.command=='plan':result=summarize(prepare(config))
            elif args.command=='publish':result=publish(config)
            else:result=[publication.recover(p,config,get,request,digest) for p in [JOURNAL,STAGING]]
        print(json.dumps(result,ensure_ascii=False))
    except Exception as error:
        # Library/network exceptions can contain private subscription URLs.
        message=str(error) if isinstance(error,(ValueError,RuntimeError)) else type(error).__name__
        print('操作停止：'+message,file=sys.stderr);raise SystemExit(1)


if __name__=='__main__':
    with lock(STATE/'publisher.lock'):main()
