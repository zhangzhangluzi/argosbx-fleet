"""Write-ahead publication journal. Unknown HTTP outcomes are recovered by readback."""
import json
from storage import save

def temporary_names(config,kind,request):
    values=request(config,'/api/'+{'sub':'subs','collection':'collections','file':'files'}[kind])
    if isinstance(values,dict):values=list(values.values())
    if not isinstance(values,list) or any(not isinstance(v,dict) or not isinstance(v.get('name'),str) for v in values):
        raise ValueError('无法确认临时对象清单')
    return {v['name'] for v in values}

def cleanup(path,j,config,request):
    for kind,name in reversed(list(j.get('temporary',[]))):
        if not name.startswith('server-check-'):raise ValueError('恢复日志中存在非临时命名空间，拒绝删除')
        if name in temporary_names(config,kind,request):
            try:request(config,'/api/'+kind+'/'+name,method='DELETE')
            except Exception:
                # A response can be lost after deletion. Confirm absence before
                # retrying; the API reports missing resources inconsistently.
                pass
            if name in temporary_names(config,kind,request):raise RuntimeError('临时对象尚未删除：'+kind+'/'+name)
        j['temporary'].remove([kind,name] if [kind,name] in j['temporary'] else (kind,name))
        save(path,j)

def recover(path,config,get,request,digest):
    if not path.exists():return {'recovered':False}
    j=json.loads(path.read_text())
    if j['backend_sha256']!=digest(config['subscription']['backend_url']):raise ValueError('恢复日志属于另一订阅后端')
    failures=[];pending=[]
    for item in reversed(j.get('attempted',[])):
        try:
            current=get(config,item['kind'],item['name'])
            if current==item['after']:pending.append(item)
            elif current!=item['before']:raise ValueError('存在并发修改')
        except Exception:failures.append(item['kind']+'/'+item['name'])
    if failures:raise RuntimeError('恢复前发现冲突，尚未修改任何对象：'+','.join(failures))
    for item in pending:
        try:
            request(config,'/api/'+item['kind']+'/'+item['name'],item['before'],'PATCH')
            if get(config,item['kind'],item['name'])!=item['before']:raise ValueError('恢复回读不一致')
        except Exception:failures.append(item['kind']+'/'+item['name'])
    if failures:raise RuntimeError('保留日志，以下对象需恢复核对：'+','.join(failures))
    cleanup(path,j,config,request)
    path.unlink();return {'recovered':True}

def begin(path,config,digest):
    if path.exists():raise ValueError('有未完成发布事务，请先执行 recover')
    j={'backend_sha256':digest(config['subscription']['backend_url']),'attempted':[],'temporary':[]}
    save(path,j);return j
