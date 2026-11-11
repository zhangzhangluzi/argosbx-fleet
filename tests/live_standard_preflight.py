"""Disposable Sub-Store objects exercise sanitized sources and fail-closed output."""
import copy,json,secrets,sys,urllib.error,urllib.parse,urllib.request
import yaml

data=json.load(sys.stdin);root='http://127.0.0.1:3001'
parsed=urllib.parse.urlsplit(data['backend_url']);base=root+parsed.path.rstrip('/')
origin=parsed.scheme+'://'+parsed.netloc

def req(path,body=None,method=None,ua='Stash/3.6.0'):
    r=urllib.request.Request(base+path,data=None if body is None else json.dumps(body,ensure_ascii=False).encode(),
          method=method,headers={'Content-Type':'application/json','User-Agent':ua})
    try:
        with urllib.request.urlopen(r,timeout=55) as o:return o.status,o.read().decode()
    except urllib.error.HTTPError as e:return e.code,e.read().decode()

def api(path,body=None,method=None):
    status,raw=req(path,body,method);obj=json.loads(raw)
    if status>=300 or obj.get('status')!='success':raise ValueError('Sub-Store 临时对象操作失败')
    return obj.get('data')

def get(name,query='',ua='Stash/3.6.0'):
    return req('/api/file/'+name+query,ua=ua)

temporary=[]
def create(obj):
    name='server-check-standard-'+secrets.token_hex(6);obj={**obj,'name':name}
    api('/api/files',obj,'POST');temporary.append(name);return name

try:
    env={'__name__':'safe_source_test'};exec(data['sanitizer'],env)
    snapshots={}
    for client,ua in [('stash','Stash/3.6.0'),('clash','FlClash/0.9.1')]:
        status,raw=get(client,ua=ua);assert status==200
        snapshots[client]=env['sanitize'](yaml.safe_load(raw),origin)
    content=json.dumps(snapshots,ensure_ascii=False,separators=(',',':'))
    assert '"proxies"' not in content and '"password"' not in content and '"uuid"' not in content.lower()
    source=create({'source':'local','content':content,'process':[]})
    safe_url=base+'/api/file/'+source+'?noCache=true'
    for client,name,ua in [('stash','standalone-stash','Stash/3.6.0'),
                           ('clash','standalone-flclash','FlClash/0.9.1')]:
        old=api('/api/wholeFile/'+name);status,before=get(name,ua=ua);assert status==200
        proc=copy.deepcopy(old['process']);proc[0]['args']['content']=data['standalone'].replace('STANDALONE_FORMAT',client)
        clone=create({**old,'url':safe_url,'process':proc})
        status,after=get(clone,ua=ua);assert status==200 and before==after
    standard=create({'source':'remote','url':safe_url,'noCache':True,'process':[{'type':'Script Operator',
      'args':{'mode':'script','content':data['standard'].replace('STANDARD_AD_ORIGIN',origin)}}]})
    status,body=get(standard,'?part=ai');assert status==200 and 'chatgpt.com' in body and 'AI线路' not in body
    status,body=get(standard,'?part=unknown');assert status==503 and body==''
    process=create({'source':'remote','url':safe_url,'noCache':True,'process':[{'type':'Script Operator',
      'args':{'mode':'script','content':data['process']}}]})
    status,body=get(process);assert status==200 and body.startswith('PROCESS-NAME-REGEX,') and 'DIRECT' not in body
    # If an operator cannot be evaluated at all, Sub-Store can return the source.
    # Even that worst case must not return node credentials.
    bad=create({'source':'remote','url':safe_url,'noCache':True,'process':[{'type':'Script Operator',
      'args':{'mode':'script','content':'function operator('}}]})
    status,body=get(bad)
    assert '"proxies"' not in body and '"password"' not in body and '"uuid"' not in body.lower()
    print(json.dumps({'old_share_outputs_equal':2,'unknown_part_status':503,
                      'parse_failure_contains_node_credentials':False,'process_rule':True}))
finally:
    for name in reversed(temporary):api('/api/file/'+name,method='DELETE')
