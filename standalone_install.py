"""Install isolated rule shares using existing Sub-Store and a Caddy hot reload.

The process reads private runtime details from stdin. New resources are recorded
before creation; the temporary journal enables recovery without touching the
existing subscription objects or restarting services.
"""
import hashlib
import json
import secrets
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, '/opt/argosbx-fleet/current')
from storage import save
import country_routes

JOURNAL = Path('/etc/argosbx-fleet/standalone-rules-publish.json')
ROUTE_JOURNAL = Path('/etc/argosbx-fleet/standalone-rules-route-journal.json')
ROUTE = Path('/etc/caddy-sub/argosbx.caddy')
MAIN = Path('/etc/caddy-sub/Caddyfile')
ROOT = 'http://127.0.0.1:3001'


def request(base, path, body=None, method=None, ua='FlClash/0.8.99'):
    data = None if body is None else json.dumps(body, ensure_ascii=False).encode()
    req = urllib.request.Request(base+path, data=data, method=method,
                                 headers={'Content-Type':'application/json','User-Agent':ua})
    try:
        with urllib.request.urlopen(req, timeout=55) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def api(base, path, body=None, method=None):
    status, raw = request(base, path, body, method)
    try:
        result = json.loads(raw)
    except Exception as error:
        raise ValueError('Sub-Store 返回非 JSON') from error
    if status >= 300 or result.get('status') != 'success':
        raise ValueError('Sub-Store 操作失败：'+path.split('?')[0])
    return result.get('data')


def names(base):
    data = api(base, '/api/files')
    return {item['name'] for item in data}


def pid(unit):
    value = subprocess.check_output(['systemctl','show',unit,'-p','MainPID','--value'], text=True).strip()
    if not value.isdigit() or int(value) <= 1:
        raise ValueError('服务未运行：'+unit)
    return int(value)


def original_fingerprint(base):
    objects = [api(base, '/api/wholeFile/'+name) for name in ('clash','stash')]
    objects.append(api(base, '/api/collection/all'))
    raw = json.dumps(objects,sort_keys=True,ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def get_journal():
    if not JOURNAL.exists(): raise ValueError('未找到发布事务')
    return json.loads(JOURNAL.read_text())


def rollback(j):
    base = ROOT+j['backend_path']
    if ROUTE_JOURNAL.exists():
        country_routes.compression_finish(restore=True, journal=ROUTE_JOURNAL)
    current = names(base)
    for item in reversed(j['items']):
        name, token = item['name'], item['token']
        if name not in current: continue
        actual = api(base, '/api/wholeFile/'+name)
        content = actual.get('process', [{}])[0].get('args', {}).get('content','')
        if (actual.get('source') != 'remote' or actual.get('url') != item['url'] or
                hashlib.sha256(content.encode()).hexdigest() != item['script_sha256']):
            raise ValueError('发布对象被并发修改，保留事务：'+name)
        tokens = api(base, '/api/tokens?'+urllib.parse.urlencode({'type':'file','name':name}))
        if any(t.get('token') == token for t in tokens):
            api(base, '/api/token/'+token+'?'+urllib.parse.urlencode({'type':'file','name':name}),method='DELETE')
        api(base, '/api/file/'+name, method='DELETE')
    JOURNAL.unlink()
    return {'rolled_back':True}


def stage(data):
    if JOURNAL.exists() or ROUTE_JOURNAL.exists():
        raise ValueError('存在未完成的独立规则发布事务')
    path = urllib.parse.urlsplit(data['backend_url']).path.rstrip('/')
    if not path or not path.startswith('/'):
        raise ValueError('无法确认 Sub-Store 管理路径')
    base = ROOT+path
    expected = {'standalone-stash','standalone-flclash'}
    if names(base) & expected:
        raise ValueError('独立规则文件名已存在，保留现有配置')
    before = {'caddy':pid('caddy-sub'),'substore':pid('sub-store'),
              'original_fingerprint':original_fingerprint(base)}
    local = {}
    exec(data['routes'], local)
    render = local['render']
    # The journal records planned resources before any remote API mutation.
    items = []
    for client in ('stash','clash'):
        name='standalone-stash' if client == 'stash' else 'standalone-flclash'
        script=data['operator'].replace('STANDALONE_FORMAT',client)
        items.append({'name':name,'client':client,'token':secrets.token_urlsafe(32),
                      'url':base+'/api/file/'+client+'?noCache=true',
                      'script_sha256':hashlib.sha256(script.encode()).hexdigest()})
    journal={'backend_path':path,'items':items,'before':before}
    save(JOURNAL,journal)
    try:
        for item in items:
            script=data['operator'].replace('STANDALONE_FORMAT',item['client'])
            obj={'name':item['name'],'displayName':'独立规则 · '+item['client'],
                 'source':'remote','url':item['url'],'noCache':True,
                 'process':[{'type':'Script Operator','args':{'mode':'script','content':script}}]}
            api(base,'/api/files',obj,'POST')
            api(base,'/api/token',{'payload':{'type':'file','name':item['name'],
                                            'token':item['token']},'options':{}},'POST')
            target='/share/file/'+item['name']+'?'+urllib.parse.urlencode({'token':item['token']})
            status, body=request(ROOT,target,ua='Stash/3.6.0' if item['client']=='stash' else 'FlClash/0.8.99')
            if status != 200 or len(body)<500:
                raise ValueError('独立规则生成失败：'+item['client'])
            for extra in ('', '?token=invalid'):
                if request(ROOT,'/share/file/'+item['name']+extra)[0] == 200:
                    raise ValueError('未授权的独立规则请求被放行')
            if request(ROOT,target+'&content=invalid')[0] == 200:
                raise ValueError('分享源覆盖未被拒绝')
        routed=country_routes.stage_import(render,ROUTE,MAIN,ROUTE_JOURNAL)
        if pid('caddy-sub') != before['caddy'] or pid('sub-store') != before['substore']:
            raise ValueError('既有服务进程发生变化')
        return {'staged':True,'route_changed':routed['changed'],'pids':before,
                'links':{item['client']:'/share/file/'+item['name']+'?'+urllib.parse.urlencode({'token':item['token']})
                         for item in items}}
    except Exception:
        rollback(journal)
        raise


def finish():
    j=get_journal()
    if pid('caddy-sub') != j['before']['caddy'] or pid('sub-store') != j['before']['substore']:
        raise ValueError('既有服务进程发生变化，保留事务')
    if original_fingerprint(ROOT+j['backend_path']) != j['before']['original_fingerprint']:
        raise ValueError('原订阅配置发生变化，保留事务以便核对')
    result=country_routes.compression_finish(journal=ROUTE_JOURNAL) if ROUTE_JOURNAL.exists() else {'pending':False}
    JOURNAL.unlink()
    return {'accepted':True,'pids':j['before'],'route':result}


if __name__ == '__main__':
    action=sys.argv[1]
    if action == 'stage': result=stage(json.load(sys.stdin))
    elif action == 'finish': result=finish()
    elif action == 'rollback': result=rollback(get_journal())
    else: raise ValueError('未知操作')
    print(json.dumps(result,ensure_ascii=False))
