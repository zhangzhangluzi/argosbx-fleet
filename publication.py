"""Write-ahead publication journal. Unknown HTTP outcomes are recovered by readback."""
import json
from storage import save

def recover(path,config,get,request,digest):
    if not path.exists():return {'recovered':False}
    j=json.loads(path.read_text())
    if j['backend_sha256']!=digest(config['subscription']['backend_url']):raise ValueError('恢复日志属于另一订阅后端')
    failures=[]
    for item in reversed(j.get('attempted',[])):
        try:
            current=get(config,item['kind'],item['name'])
            if current==item['after']:
                request(config,'/api/'+item['kind']+'/'+item['name'],item['before'],'PATCH')
                if get(config,item['kind'],item['name'])!=item['before']:raise ValueError('恢复回读不一致')
            elif current!=item['before']:raise ValueError('存在并发修改')
        except Exception:failures.append(item['kind']+'/'+item['name'])
    for kind,name in reversed(j.get('temporary',[])):
        try:
            # DELETE is safe only for this transaction's random private namespace.
            request(config,'/api/'+kind+'/'+name,method='DELETE')
        except Exception:failures.append(kind+'/'+name)
    if failures:raise RuntimeError('保留日志，以下对象需恢复核对：'+','.join(failures))
    path.unlink();return {'recovered':True}

def begin(path,config,digest):
    if path.exists():raise ValueError('有未完成发布事务，请先执行 recover')
    j={'backend_sha256':digest(config['subscription']['backend_url']),'attempted':[],'temporary':[]}
    save(path,j);return j
