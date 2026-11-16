"""Write-ahead publication journal. Unknown HTTP outcomes are recovered by readback."""
import copy,json
from storage import save

# Sub-Store PATCH merges fields rather than removing them.  These optional
# fields may be explicitly set to null when restoring a legacy object.
NULLABLE_ROLLBACK_FIELDS={('file','shadowrocket-config'):{'type','sourceType','sourceName'},
                          ('collection','all'):{'ignoreFailedRemoteSub'}}


def restore_payload(item):
    before=item.get('before')
    if before is None:return None
    result=copy.deepcopy(before)
    for key in NULLABLE_ROLLBACK_FIELDS.get((item.get('kind'),item.get('name')),set()):
        if key not in before and key in item.get('after',{}):result[key]=None
    return result


def restored_equivalent(current,item):
    if current==item.get('before'):return True
    before=item.get('before')
    if before is None or not isinstance(current,dict):return False
    normalized=copy.deepcopy(current)
    for key in NULLABLE_ROLLBACK_FIELDS.get((item.get('kind'),item.get('name')),set()):
        if key not in before and normalized.get(key) is None:normalized.pop(key,None)
    return normalized==before

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

def recover(path,config,get,request,digest,owner=None):
    if not path.exists():return {'recovered':False}
    j=json.loads(path.read_text())
    if owner is not None and j.get('owner')!=owner:raise ValueError('发布事务归属不符，拒绝恢复')
    if j['backend_sha256']!=digest(config['subscription']['backend_url']):raise ValueError('恢复日志属于另一订阅后端')
    failures=[];pending=[]
    for item in reversed(j.get('attempted',[])):
        try:
            current=get(config,item['kind'],item['name'])
            if current==item['after']:pending.append(item)
            elif not restored_equivalent(current,item):raise ValueError('存在并发修改')
        except Exception:failures.append(item['kind']+'/'+item['name'])
    if failures:raise RuntimeError('恢复前发现冲突，尚未修改任何对象：'+','.join(failures))
    for item in pending:
        try:
            request(config,'/api/'+item['kind']+'/'+item['name'],restore_payload(item),'DELETE' if item['before'] is None else 'PATCH')
            if not restored_equivalent(get(config,item['kind'],item['name']),item):raise ValueError('恢复回读不一致')
        except Exception:failures.append(item['kind']+'/'+item['name'])
    if failures:raise RuntimeError('保留日志，以下对象需恢复核对：'+','.join(failures))
    cleanup(path,j,config,request)
    path.unlink();return {'recovered':True}

def begin(path,config,digest,owner=None):
    if path.exists():raise ValueError('有未完成发布事务，请先执行 recover')
    j={'backend_sha256':digest(config['subscription']['backend_url']),'attempted':[],'temporary':[]}
    if owner is not None:j['owner']=owner
    save(path,j);return j
