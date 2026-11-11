"""Update existing rules-only shares under the publisher lock, with recovery."""
import copy
import hashlib
import json
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import standard_rule_source as source
from storage import lock, save

JOURNAL=Path('/etc/argosbx-fleet/standard-provider-update.json')
PROVIDER='standard-rule-provider'
PARTS=('applovin-console','business-overseas','business-cn','business-all',
       'magic-dns','dns-block','dns-dot','priority-direct','priority-proxy',
       'china-console','foreign-console','dns-direct','dns-proxy-1','google-dns',
       'dns-proxy-2','telegram','lan','ai','china-sites','overseas','udp',
       'ads','china-domains','china-ip','unknown')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


def rendered(base,name,part):
    req=urllib.request.Request(base+'/api/file/'+name+'?'+urllib.parse.urlencode({'part':part}),
                               headers={'User-Agent':'Stash/3.6.0'})
    try:response=urllib.request.build_opener(NoRedirect()).open(req,timeout=55)
    except urllib.error.HTTPError as error:response=error
    with response:
        body=response.read()
        return {'status':response.code,'body':hashlib.sha256(body).hexdigest(),
                'location':response.headers.get('Location')}


def render_all(base,name):
    values={part:rendered(base,name,part) for part in PARTS}
    for part,value in values.items():
        wanted=503 if part=='unknown' else 302 if part in ('ads','china-domains','china-ip') else 200
        if value['status']!=wanted:raise ValueError('独立规则集预检失败：'+part)
    return values


def cleanup(base,journal):
    files={v['name'] for v in source.api(base,'/api/files')}
    for name in reversed(journal['temporary']):
        if not name.startswith('server-check-rule-update-'):raise ValueError('临时对象范围异常')
        if name in files:source.api(base,'/api/file/'+name,method='DELETE')


def rollback(base,journal):
    current=source.api(base,'/api/wholeFile/'+source.SOURCE)
    before=journal['source_before'];after=journal['source_after']
    if current.get('content') not in (before,after):raise ValueError('规则源已被外部修改，保留事务')
    if current.get('content')!=before:
        source.api(base,'/api/file/'+source.SOURCE,{'content':before},'PATCH')
        if source.api(base,'/api/wholeFile/'+source.SOURCE).get('content')!=before:
            raise ValueError('规则源回滚未完成，保留事务')
    current=source.api(base,'/api/wholeFile/'+PROVIDER)
    before=journal['process_before'];after=journal['process_after']
    if current.get('process') not in (before,after):raise ValueError('规则处理器已被外部修改，保留事务')
    if current.get('process')!=before:
        source.api(base,'/api/file/'+PROVIDER,{'process':before},'PATCH')
        if source.api(base,'/api/wholeFile/'+PROVIDER).get('process')!=before:
            raise ValueError('规则处理器回滚未完成，保留事务')
    cleanup(base,journal)
    JOURNAL.unlink()
    return {'rolled_back':True}


def update(settings):
    if JOURNAL.exists():raise ValueError('独立规则集存在待恢复事务')
    base=source.api_config(settings)['subscription']['backend_url'].rstrip('/')
    origin_parts=urllib.parse.urlsplit(settings['backend_url'])
    origin=origin_parts.scheme+'://'+origin_parts.netloc
    old_source=source.api(base,'/api/wholeFile/'+source.SOURCE)
    provider=source.api(base,'/api/wholeFile/'+PROVIDER)
    if old_source.get('source')!='local' or old_source.get('process') or provider.get('source')!='remote':
        raise ValueError('既有独立规则对象类型异常')
    old_process=provider.get('process')
    if not isinstance(old_process,list) or len(old_process)!=1 or old_process[0].get('type')!='Script Operator':
        raise ValueError('既有独立规则处理器异常')
    new_process=copy.deepcopy(old_process)
    new_process[0]['args']['content']=(Path(__file__).parent/'templates'/'standard-rule-provider.js').read_text().replace('STANDARD_AD_ORIGIN',origin)
    names={'process':'standard-process-provider','stash':'standalone-stash','clash':'standalone-flclash'}
    scripts={key:source.api(base,'/api/wholeFile/'+name)['process'][0]['args']['content'] for key,name in names.items()}
    scripts['standard']=new_process[0]['args']['content']
    fresh={fmt:json.loads(source.snapshot(base,origin,fmt)) for fmt in source.CLIENTS}
    previous=json.loads(old_source['content'])
    source.validate_candidates(previous,scripts)
    source.validate_candidates(fresh,scripts)
    fresh_body=json.dumps(fresh,ensure_ascii=False,separators=(',',':'))
    prefix='server-check-rule-update-'
    temporary=[prefix+secrets.token_hex(6) for _ in range(3)]
    journal={'source_before':old_source['content'],'source_after':fresh_body,
             'process_before':old_process,'process_after':new_process,'temporary':temporary}
    save(JOURNAL,journal)
    try:
        baseline=render_all(base,PROVIDER)
        source.api(base,'/api/files',{'name':temporary[0],'source':'local','content':fresh_body,'process':[]},'POST')
        source.api(base,'/api/files',{**provider,'name':temporary[1],'process':new_process},'POST')
        test_url=base+'/api/file/'+temporary[0]+'?noCache=true'
        source.api(base,'/api/files',{**provider,'name':temporary[2],'url':test_url,'process':new_process},'POST')
        if render_all(base,temporary[1])!=baseline:raise ValueError('旧规则链接输出发生变化')
        wanted=render_all(base,temporary[2])
        if source.api(base,'/api/wholeFile/'+PROVIDER).get('process')!=old_process:
            raise ValueError('独立规则处理器发生并发变化')
        source.api(base,'/api/file/'+PROVIDER,{'process':new_process},'PATCH')
        if source.api(base,'/api/wholeFile/'+PROVIDER).get('process')!=new_process or render_all(base,PROVIDER)!=baseline:
            raise ValueError('独立规则处理器回读不一致')
        result=source.refresh(settings)
        if source.api(base,'/api/wholeFile/'+source.SOURCE).get('content')!=fresh_body:
            raise ValueError('规则源与验收结果不一致')
        if render_all(base,PROVIDER)!=wanted:raise ValueError('独立规则公开输出与验收结果不一致')
        cleanup(base,journal)
        JOURNAL.unlink()
        return {'updated':True,'rules':result['rules'],'parts_verified':len(PARTS),'subscription_links_changed':False}
    except Exception:
        rollback(base,journal)
        raise


if __name__=='__main__':
    try:
        with lock('/run/argosbx-publisher.lock'):
            settings=source.read_config(source.CONFIG)
            base=source.api_config(settings)['subscription']['backend_url'].rstrip('/')
            if len(sys.argv)>1 and sys.argv[1]=='recover':result=rollback(base,json.loads(JOURNAL.read_text()))
            else:result=update(settings)
        print(json.dumps(result,ensure_ascii=False))
    except Exception as error:
        print('独立规则更新停止：'+(str(error) if isinstance(error,ValueError) else type(error).__name__),file=sys.stderr)
        raise SystemExit(1)
