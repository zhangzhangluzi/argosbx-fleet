"""Maintain a rules-only Sub-Store source without copying proxy credentials."""
import argparse,copy,json,re,subprocess,sys,urllib.error,urllib.parse,urllib.request
from pathlib import Path

import yaml

sys.path.insert(0,'/opt/argosbx-fleet/current')
from storage import lock
from ad_delivery import CONFIG,read_config,api_config

SOURCE='standard-rule-source'
CLIENTS=('stash','clash')
PROVIDERS={'广告域名':('domain','mrs'),'国内域名':('domain','mrs'),'国内IP':('ipcidr','mrs')}
PROVIDER_FIELDS={'type','behavior','format','url','path','interval','proxy','size-limit'}
RULE_TYPES={'DOMAIN','DOMAIN-SUFFIX','DOMAIN-KEYWORD','IP-CIDR','IP-CIDR6','DST-PORT',
            'PROCESS-NAME-REGEX','RULE-SET','NETWORK','MATCH'}

def sanitize(profile,origin):
    if not isinstance(profile,dict) or not isinstance(profile.get('rules'),list):
        raise ValueError('原订阅缺少规则')
    rules=profile['rules']
    if not 20<=len(rules)<=10000:raise ValueError('原订阅规则数量异常')
    for rule in rules:
        if (not isinstance(rule,str) or len(rule)>2048 or '\n' in rule or '\r' in rule or
            rule.split(',',1)[0] not in RULE_TYPES or '://' in rule or
            re.search(r'(?i)(password|private.?key|uuid|authorization)\s*[:=]',rule)):
            raise ValueError('规则包含不支持的内容')
    source=profile.get('rule-providers')
    if not isinstance(source,dict):raise ValueError('原订阅缺少规则集')
    providers={}
    for name,(behavior,fmt) in PROVIDERS.items():
        value=source.get(name)
        if not isinstance(value,dict) or value.get('behavior')!=behavior or value.get('format')!=fmt:
            raise ValueError('原订阅规则集格式变化')
        url=value.get('url','')
        if name=='广告域名':
            valid=bool(re.fullmatch(re.escape(origin)+r'/rules/ad/ads-[0-9a-f]{64}\.mrs',url))
        else:
            valid=url=='https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/'+(
                'geosite/cn.mrs' if name=='国内域名' else 'geoip/cn.mrs')
        if not valid:raise ValueError('原订阅规则集地址变化')
        cleaned={k:copy.deepcopy(v) for k,v in value.items() if k in PROVIDER_FIELDS}
        for k in ('url','path','proxy'):
            if k in cleaned and (not isinstance(cleaned[k],str) or '?' in cleaned[k] or '#' in cleaned[k]):
                raise ValueError('规则集包含意外的引用')
        providers[name]=cleaned
    # This strict whitelist is the security boundary: never serialize proxies,
    # TLS settings, subscription URLs, passwords, UUIDs or other profile data.
    return {'rules':list(rules),'rule-providers':providers}

def request(base,path,body=None,method=None,ua='Stash/3.6.0'):
    data=None if body is None else json.dumps(body,ensure_ascii=False).encode()
    req=urllib.request.Request(base+path,data=data,method=method,
        headers={'Content-Type':'application/json','User-Agent':ua})
    try:
        with urllib.request.urlopen(req,timeout=55) as r:return r.status,r.read().decode()
    except urllib.error.HTTPError as e:return e.code,e.read().decode()

def api(base,path,body=None,method=None):
    status,raw=request(base,path,body,method)
    try:result=json.loads(raw)
    except Exception as e:raise ValueError('Sub-Store 返回非 JSON') from e
    if status>=300 or result.get('status')!='success':raise ValueError('Sub-Store 请求失败')
    return result.get('data')

def snapshot(base,origin,fmt):
    status,raw=request(base,'/api/file/'+fmt,ua='Stash/3.6.0' if fmt=='stash' else 'FlClash/0.9.1')
    if status!=200:raise ValueError('原订阅当前无法生成')
    clean=sanitize(yaml.safe_load(raw),origin)
    return json.dumps(clean,ensure_ascii=False,separators=(',',':'))

def validate_candidates(candidates,scripts,node='/opt/sub-store/node'):
    """Refuse updates that would invalidate any public rule-only output."""
    js=r'''
    const vm=require('vm'),fs=require('fs'),v=JSON.parse(fs.readFileSync(0,'utf8'));
    function run(script,part) {
      const input={$content:JSON.stringify(v.source),$options:{_req:{query:{part}}}};
      const ctx={input,ProxyUtils:{yaml:{safeLoad:JSON.parse,safeDump:JSON.stringify}}};
      vm.createContext(ctx);vm.runInContext(script+'\noperator(input);',ctx,{timeout:5000});
      return input;
    }
    const parts=['applovin-console','business-overseas','business-cn','business-all',
      'magic-dns','dns-block','dns-dot','priority-direct','priority-proxy',
      'china-console','foreign-console','dns-direct','dns-proxy-1','google-dns','dns-proxy-2',
      'telegram','lan','ai','china-sites','overseas','udp'];
    for (const part of parts) {
      const out=run(v.standard,part);
      if (!out.$content || out.$options?._res?.status) throw Error('invalid rule part');
    }
    for (const part of ['ads','china-domains','china-ip']) {
      const out=run(v.standard,part);
      if (out.$options?._res?.status!==302 || !out.$options?._res?.headers?.Location) throw Error('invalid MRS');
    }
    const bad=run(v.standard,'unknown');
    if (bad.$content || bad.$options?._res?.status!==503) throw Error('unsafe failure');
    const process=run(v.process,'');
    if (!process.$content.startsWith('PROCESS-NAME-REGEX,') || process.$options?._res?.status) throw Error('invalid process');
    for (const s of [v.stash,v.clash]) {
      const out=run(s,'');
      if (!out.$content || out.$options?._res?.status) throw Error('invalid previous share');
    }
    '''
    payload={'source':candidates,**scripts}
    result=subprocess.run([node,'-e',js],input=json.dumps(payload,ensure_ascii=False),
                          text=True,capture_output=True,timeout=30)
    if result.returncode:raise ValueError('规则结构变化，保留上次有效规则源')

def refresh(settings,verify=False):
    backend=api_config(settings)['subscription']['backend_url'].rstrip('/')
    parsed=urllib.parse.urlsplit(settings['backend_url']);origin=parsed.scheme+'://'+parsed.netloc
    # A single atomic Sub-Store object contains both strictly sanitized clients.
    candidates={fmt:json.loads(snapshot(backend,origin,fmt)) for fmt in CLIENTS}
    body=json.dumps(candidates,ensure_ascii=False,separators=(',',':'))
    old=api(backend,'/api/wholeFile/'+SOURCE)
    if not isinstance(old,dict) or old.get('source')!='local' or old.get('process'):
        raise ValueError('规则源对象类型异常')
    changed=old.get('content')!=body
    if changed:
        if verify:raise ValueError('规则源与现行订阅不一致')
        names={'standard':'standard-rule-provider','process':'standard-process-provider',
               'stash':'standalone-stash','clash':'standalone-flclash'}
        scripts={key:api(backend,'/api/wholeFile/'+name)['process'][0]['args']['content']
                 for key,name in names.items()}
        validate_candidates(candidates,scripts)
        # A lost response is resolved by readback; no proxy or other file changes.
        try:api(backend,'/api/file/'+SOURCE,{'content':body},'PATCH')
        except Exception:
            if api(backend,'/api/wholeFile/'+SOURCE).get('content')!=body:raise
        if api(backend,'/api/wholeFile/'+SOURCE).get('content')!=body:raise ValueError('规则源回读不一致')
    return {'verified':True,'updated':int(changed),'rules':{k:len(v['rules']) for k,v in candidates.items()}}

def refresh_if_configured(config_path=CONFIG,verify=False):
    if not config_path.is_file():return {'configured':False}
    settings=read_config(config_path)
    backend=api_config(settings)['subscription']['backend_url'].rstrip('/')
    files=api(backend,'/api/files')
    if not any(isinstance(f,dict) and f.get('name')==SOURCE for f in files):
        return {'configured':False}
    return {'configured':True,**refresh(settings,verify=verify)}

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=('refresh','verify'));parser.add_argument('--if-configured',action='store_true');args=parser.parse_args()
    try:
        with lock('/run/argosbx-publisher.lock'):
            result=(refresh_if_configured(verify=args.action=='verify') if args.if_configured
                    else refresh(read_config(CONFIG),verify=args.action=='verify'))
        print(json.dumps(result,ensure_ascii=False))
    except Exception as error:
        print('规则源刷新失败：'+(str(error) if isinstance(error,ValueError) else type(error).__name__),file=sys.stderr)
        raise SystemExit(1)
