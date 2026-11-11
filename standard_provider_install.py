"""Publish rules-only shares with scoped rollback and no service restarts."""
import copy,hashlib,json,secrets,subprocess,sys,urllib.error,urllib.parse,urllib.request
from pathlib import Path
import yaml

sys.path.insert(0,'/opt/argosbx-fleet/current')
from storage import save
import country_routes

ROOT='http://127.0.0.1:3001'
JOURNAL=Path('/etc/argosbx-fleet/standard-provider-publish.json')
ROUTE_JOURNAL=Path('/etc/argosbx-fleet/standard-provider-route.json')
ROUTE=Path('/etc/caddy-sub/argosbx.caddy')
MAIN=Path('/etc/caddy-sub/Caddyfile')
SOURCE='standard-rule-source'

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

def request(base,path,body=None,method=None,ua='Stash/3.6.0'):
    req=urllib.request.Request(base+path,data=None if body is None else json.dumps(body,ensure_ascii=False).encode(),
         method=method,headers={'Content-Type':'application/json','User-Agent':ua})
    try:
        with urllib.request.build_opener(NoRedirect()).open(req,timeout=55) as r:
            return r.status,r.read().decode(errors='replace')
    except urllib.error.HTTPError as e:return e.code,e.read().decode(errors='replace')

def api(base,path,body=None,method=None):
    status,raw=request(base,path,body,method)
    try:result=json.loads(raw)
    except Exception as e:raise ValueError('Sub-Store 返回非 JSON') from e
    if status>=300 or result.get('status')!='success':raise ValueError('Sub-Store 操作失败')
    return result.get('data')

def file_names(base):return {x['name'] for x in api(base,'/api/files')}
def pid(unit):
    x=subprocess.check_output(['systemctl','show',unit,'-p','MainPID','--value'],text=True).strip()
    if not x.isdigit() or int(x)<=1:raise ValueError('服务未运行：'+unit)
    return int(x)

def digest(obj):return hashlib.sha256(json.dumps(obj,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
def fingerprint(base):
    values=[api(base,'/api/wholeFile/'+x) for x in ('clash','stash')]
    values.append(api(base,'/api/collection/all'))
    return digest(values)

def rendered(base,name,ua):
    status,body=request(base,'/api/file/'+name,ua=ua)
    if status!=200 or len(body)<200:raise ValueError('既有独立规则无法生成')
    return body

def rollback(j):
    base=ROOT+j['backend_path']
    if ROUTE_JOURNAL.exists():country_routes.compression_finish(restore=True,journal=ROUTE_JOURNAL)
    for item in reversed(j.get('attempted_old',[])):
        now=api(base,'/api/wholeFile/'+item['name'])
        if now.get('url')==item['before'].get('url') and now.get('process')==item['before'].get('process'):continue
        if now.get('url')!=item['url'] or now.get('process')!=item['process']:
            raise ValueError('原独立规则被并发修改，保留事务')
        api(base,'/api/file/'+item['name'],{'url':item['before']['url'],'process':item['before']['process']},'PATCH')
    existing=file_names(base)
    for name in reversed(j.get('temporary',[])):
        if not name.startswith('server-check-standard-'):raise ValueError('临时对象范围错误')
        if name in existing:api(base,'/api/file/'+name,method='DELETE')
    for item in reversed(j['items']):
        name=item['name'];token=item.get('token')
        if name not in existing:continue
        actual=api(base,'/api/wholeFile/'+name)
        if item['kind']=='local':
            if actual.get('source')!='local' or digest(actual.get('content'))!=item['content_sha']:
                raise ValueError('规则源被并发修改，保留事务')
        else:
            try:script=actual['process'][0]['args']['content']
            except (KeyError,IndexError,TypeError):raise ValueError('规则对象被并发修改')
            if (actual.get('source')!='remote' or actual.get('url')!=item['url'] or
                    hashlib.sha256(script.encode()).hexdigest()!=item['script_sha256']):
                raise ValueError('规则对象被并发修改，保留事务')
        if token:
            tokens=api(base,'/api/tokens?'+urllib.parse.urlencode({'type':'file','name':name}))
            if any(x.get('token')==token for x in tokens):
                api(base,'/api/token/'+token+'?'+urllib.parse.urlencode({'type':'file','name':name}),method='DELETE')
        api(base,'/api/file/'+name,method='DELETE')
    JOURNAL.unlink();return {'rolled_back':True}

def stage(data):
    if JOURNAL.exists() or ROUTE_JOURNAL.exists():raise ValueError('存在未完成的标准规则集事务')
    parsed=urllib.parse.urlsplit(data['backend_url']);path=parsed.path.rstrip('/')
    if not path.startswith('/') or not parsed.netloc:raise ValueError('无法确认订阅后端')
    base=ROOT+path;wanted={SOURCE,'standard-rule-provider','standard-process-provider'}
    if wanted & file_names(base):raise ValueError('标准规则源名称已存在，保留现有配置')
    before={'caddy':pid('caddy-sub'),'substore':pid('sub-store'),'fingerprint':fingerprint(base)}
    env={'__name__':'standard_rule_source_library'};exec(data['sanitizer'],env)
    origin=parsed.scheme+'://'+parsed.netloc
    safe={}
    for client in ('stash','clash'):
        status,raw=request(base,'/api/file/'+client,ua='Stash/3.6.0' if client=='stash' else 'FlClash/0.9.1')
        if status!=200:raise ValueError('原订阅无法生成')
        safe[client]=env['sanitize'](yaml.safe_load(raw),origin)
    content=json.dumps(safe,ensure_ascii=False,separators=(',',':'))
    if any(x in content.lower() for x in ('"proxies"','"password"','"uuid"',path.lower())):
        raise ValueError('规则源未通过脱敏校验')
    safe_url=base+'/api/file/'+SOURCE+'?noCache=true'
    scripts={'standard-rule-provider':data['standard'].replace('STANDARD_AD_ORIGIN',origin),
             'standard-process-provider':data['process']}
    items=[{'kind':'local','name':SOURCE,'content_sha':digest(content)}]
    for name,client in [('standard-rule-provider','stash'),('standard-process-provider','clash')]:
        items.append({'kind':'remote','name':name,'client':client,'token':secrets.token_urlsafe(32),
                      'url':safe_url,'script_sha256':hashlib.sha256(scripts[name].encode()).hexdigest()})
    journal={'backend_path':path,'items':items,'before':before,'temporary':[],
             'attempted_old':[],'old_hashes':{}}
    save(JOURNAL,journal)
    try:
        api(base,'/api/files',{'name':SOURCE,'displayName':'脱敏规则源','source':'local',
                              'content':content,'process':[]},'POST')
        # Repoint the two earlier shares only after temporary clones reproduce
        # their current output exactly; URLs and share tokens remain unchanged.
        for client in ('stash','clash'):
            name='standalone-stash' if client=='stash' else 'standalone-flclash'
            ua='Stash/3.6.0' if client=='stash' else 'FlClash/0.9.1'
            old=api(base,'/api/wholeFile/'+name);old_body=rendered(base,name,ua)
            proc=copy.deepcopy(old['process'])
            if len(proc)!=1 or proc[0].get('type')!='Script Operator':raise ValueError('原独立规则处理器异常')
            proc[0]['args']['content']=data['standalone'].replace('STANDALONE_FORMAT',client)
            temp='server-check-standard-'+secrets.token_hex(6)
            journal['temporary'].append(temp);save(JOURNAL,journal)
            candidate={**old,'name':temp,'url':safe_url,'process':proc}
            api(base,'/api/files',candidate,'POST')
            if rendered(base,temp,ua)!=old_body:raise ValueError('安全规则源与原独立链接的输出不同')
            api(base,'/api/file/'+temp,method='DELETE');journal['temporary'].remove(temp);save(JOURNAL,journal)
            if api(base,'/api/wholeFile/'+name)!=old:raise ValueError('原独立规则发生并发变化')
            item={'name':name,'before':old,'url':safe_url,'process':proc}
            journal['attempted_old'].append(item);journal['old_hashes'][name]=hashlib.sha256(old_body.encode()).hexdigest();save(JOURNAL,journal)
            api(base,'/api/file/'+name,{'url':safe_url,'process':proc},'PATCH')
            if hashlib.sha256(rendered(base,name,ua).encode()).hexdigest()!=journal['old_hashes'][name]:
                raise ValueError('原独立规则回读不一致')
        for item in items[1:]:
            obj={'name':item['name'],'displayName':'标准规则集 · '+item['client'],'source':'remote',
                 'url':safe_url,'noCache':True,
                 'process':[{'type':'Script Operator','args':{'mode':'script','content':scripts[item['name']]}}]}
            api(base,'/api/files',obj,'POST')
            api(base,'/api/token',{'payload':{'type':'file','name':item['name'],'token':item['token']}},'POST')
            query={'token':item['token']}
            if item['client']=='stash':query['part']='ai'
            target='/share/file/'+item['name']+'?'+urllib.parse.urlencode(query)
            status,body=request(ROOT,target)
            if status!=200 or not body.strip():raise ValueError('标准规则集生成失败')
            if request(ROOT,'/share/file/'+item['name'])[0]==200:raise ValueError('规则集可被未授权访问')
            if request(ROOT,target+'&content=invalid')[0]==200:raise ValueError('规则集源覆盖未被拒绝')
            if item['client']=='stash':
                code,body=request(ROOT,'/share/file/'+item['name']+'?'+urllib.parse.urlencode({'token':item['token'],'part':'unknown'}))
                if code!=503 or body:raise ValueError('异常时规则集未安全关闭')
        env={};exec(data['routes'],env)
        changed=country_routes.stage_import(env['render'],ROUTE,MAIN,ROUTE_JOURNAL)
        if pid('caddy-sub')!=before['caddy'] or pid('sub-store')!=before['substore']:
            raise ValueError('既有服务进程发生变化')
        return {'staged':True,'route_changed':changed['changed'],
                'tokens':{item['client']:item['token'] for item in items if item.get('token')},
                'old_links_preserved':True,'pids':before}
    except Exception:
        rollback(journal)
        raise

def finish():
    if not JOURNAL.exists():raise ValueError('未找到标准规则集事务')
    j=json.loads(JOURNAL.read_text());before=j['before'];base=ROOT+j['backend_path']
    if pid('caddy-sub')!=before['caddy'] or pid('sub-store')!=before['substore'] or fingerprint(base)!=before['fingerprint']:
        raise ValueError('既有订阅或服务发生变化，保留事务以便核对')
    for name,sha in j['old_hashes'].items():
        ua='Stash/3.6.0' if name=='standalone-stash' else 'FlClash/0.9.1'
        if hashlib.sha256(rendered(base,name,ua).encode()).hexdigest()!=sha:
            raise ValueError('既有独立规则链接输出发生变化')
    result=country_routes.compression_finish(journal=ROUTE_JOURNAL) if ROUTE_JOURNAL.exists() else {'pending':False}
    JOURNAL.unlink();return {'accepted':True,'route':result,'pids':{'caddy':before['caddy'],'substore':before['substore']}}

if __name__=='__main__':
    action=sys.argv[1]
    if action=='stage':result=stage(json.load(sys.stdin))
    elif action=='finish':result=finish()
    elif action=='rollback':result=rollback(json.loads(JOURNAL.read_text()))
    else:raise ValueError('未知操作')
    print(json.dumps(result,ensure_ascii=False))
