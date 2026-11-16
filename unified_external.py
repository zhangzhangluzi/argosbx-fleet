"""Merge external regions into the existing unified subscription safely."""
import copy
import json
import re
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

SELF_PREFIX = 'JP-T-v4-CF-自建-'
SELF_REGION = '日本自建'
ENTRY_PREFIX = 'CF入口-'
VALID_NAME = re.compile(r'[A-Za-z0-9_-]{1,64}')


def validate(spec):
    if not isinstance(spec, dict) or set(spec) != {'sources', 'countries', 'chain_source'}:
        raise ValueError('外部地区配置需要 sources、countries 和 chain_source')
    sources, countries = spec['sources'], spec['countries']
    if (not isinstance(sources, list) or not sources or
            any(not isinstance(x, str) or not VALID_NAME.fullmatch(x) for x in sources) or len(sources) != len(set(sources))):
        raise ValueError('外部订阅源名称无效或重复')
    if spec['chain_source'] not in sources:
        raise ValueError('日本自建链式来源不在外部订阅源中')
    if not isinstance(countries, dict) or SELF_REGION not in countries:
        raise ValueError('外部地区缺少日本自建分组')
    for label, prefixes in countries.items():
        if (not isinstance(label,str) or not re.fullmatch(r'[^,=\[\]#;\r\n]{1,40}',label) or
                not isinstance(prefixes,list) or not prefixes or
                any(not isinstance(p,str) or not re.fullmatch(r'[A-Z][A-Za-z0-9-]{0,31}',p) for p in prefixes) or len(prefixes)!=len(set(prefixes))):
            raise ValueError('外部地区名称或前缀无效')
    return spec


def merge_countries(native, external):
    result=copy.deepcopy(native)
    if SELF_REGION in native:
        raise ValueError('日本自建分组已存在')
    for label, prefixes in external.items():
        result.setdefault(label,[])
        for prefix in prefixes:
            if prefix not in result[label]:result[label].append(prefix)
    return result


def patch_profile(item, external):
    result=copy.deepcopy(item)
    args=result['process'][0]['args']
    code=args['content']
    match=re.search(r'(?m)^ const countryCodes=(.*);$',code)
    if not match:raise ValueError('原统一订阅地区映射缺失')
    countries=merge_countries(json.loads(match.group(1)),external)
    code=code[:match.start(1)]+json.dumps(countries,ensure_ascii=False,separators=(',',':'))+code[match.end(1):]
    old=" const inCountry=(n,c)=>countryCodes[c].some(prefix=>n.startsWith(prefix+'-T-')||n.startsWith(prefix+'-U-'));"
    new=(" const isSelf=n=>n.startsWith("+json.dumps(SELF_PREFIX,ensure_ascii=False)+");\n"
         " const inCountry=(n,c)=>c==="+json.dumps(SELF_REGION,ensure_ascii=False)+"?isSelf(n):!isSelf(n)&&countryCodes[c].some(prefix=>n.startsWith(prefix+'-T-')||n.startsWith(prefix+'-U-'));" )
    if code.count(old)!=1:raise ValueError('原统一订阅地区匹配逻辑发生变化')
    code=code.replace(old,new,1)
    purpose=re.findall(r'(?<=\.\.\.)(\[(?:"地区-[^"\\]+"(?:,\s*)?)+\])(?=\]?\.filter\()',code)
    if len(purpose)!=2 or json.loads(purpose[0])!=json.loads(purpose[1]):
        raise ValueError('原统一订阅用途分组发生变化')
    order=json.loads(purpose[0])
    for country in countries:
        group='地区-'+country
        if group not in order:order.append(group)
    code=code.replace(purpose[0],json.dumps(order,ensure_ascii=False))
    args['content']=code
    return result,countries,order


def patch_response(item, chain_source):
    result=copy.deepcopy(item)
    args=result['process'][0]['args']
    code=args['content']
    marker="  // Sub-Store's legacy VMess JSON URI omits ECH."
    if code.count(marker)!=1:raise ValueError('原统一订阅导出处理器发生变化')
    setup="""  const isShadowrocket = target ? ['uri','shadowrocket'].includes(target) : ua.includes('shadowrocket');
  if (isShadowrocket && target !== 'uri') {
    res.body = await produceArtifact({type:'collection',name:sourceName,platform:'URI',noFlow:true});
  }
"""
    code=code.replace(marker,setup+marker,1)
    if code.count("  if (target === 'uri') {")!=1:raise ValueError('原 URI 转换处理器发生变化')
    code=code.replace("  if (target === 'uri') {","  if (isShadowrocket) {",1)
    marker='  if (!isMihomo && !isStash) return res;'
    if code.count(marker)!=1:raise ValueError('原客户端导出分支发生变化')
    handler="""  if (isShadowrocket) {
    res.body = attachJapanChains(res.body);
    res.headers = {...res.headers,'content-type':'text/plain; charset=utf-8'};
    for (const key of Object.keys(res.headers)) if (key.toLowerCase()==='content-length') delete res.headers[key];
    return res;
  }
"""
    code=code.replace(marker,handler+marker,1)
    helper=(Path(__file__).with_name('unified-shadowrocket.js')).read_text()
    if code.count('async function transformFunction(')!=1:raise ValueError('响应处理器入口不唯一')
    code=code.replace('async function transformFunction(',helper+'\nasync function transformFunction(',1)
    args['content']=code
    return result


def patch_shadowrocket(item,countries,order,interval):
    result=copy.deepcopy(item)
    old=result.get('content','')
    if old.count('[Proxy Group]')!=1 or '[General]' not in old:
        raise ValueError('原 Shadowrocket 配置结构发生变化')
    head=old.split('[Proxy Group]',1)[0]
    head=re.sub(r'(?im)^\s*close-if-proxy-chain-missing\s*=.*\n','',head)
    head=head.replace('[General]','[General]\nclose-if-proxy-chain-missing = true',1)
    template=(Path(__file__).with_name('unified-shadowrocket-profile.js')).read_text()
    for key,value in [('BASE',head),('COUNTRIES',countries),('PURPOSE',order),('INTERVAL',interval)]:
        template=template.replace('__'+key+'__',json.dumps(value,ensure_ascii=False,separators=(',',':')))
    result.update(type='mihomoConfig',sourceType='collection',sourceName='all',
                  process=[{'type':'Script Operator','args':{'mode':'script','content':template}}])
    return result


def apply(payload,spec,interval=1800):
    validate(spec)
    result=copy.deepcopy(payload)
    collection=next((x for x in result['collections'] if x['name']=='all'),None)
    if not collection:raise ValueError('原统一聚合不存在')
    if any(name in collection['subscriptions'] for name in spec['sources']):
        raise ValueError('外部来源已存在于原统一聚合')
    collection['subscriptions']+=spec['sources']
    collection['ignoreFailedRemoteSub']='fallbackQuiet'
    collection['displayName']='统一 · 六地区与日本自建'
    collection=patch_response(collection,spec['chain_source'])
    result['collections'][result['collections'].index(next(x for x in result['collections'] if x['name']=='all'))]=collection
    countries=order=None
    for i,item in enumerate(result['files']):
        if item['name'] in ('clash','stash'):
            result['files'][i],current,current_order=patch_profile(item,spec['countries'])
            if countries is not None and (countries!=current or order!=current_order):
                raise ValueError('Clash 与 Stash 的地区映射不一致')
            countries,order=current,current_order
    if countries is None:raise ValueError('原统一客户端配置缺失')
    for i,item in enumerate(result['files']):
        if item['name']=='shadowrocket-config':result['files'][i]=patch_shadowrocket(item,countries,order,interval)
    return result


def check_dynamic_profile(actual,expected,native_names):
    """Allow external address churn while protecting policy and native nodes."""
    for key in set(actual)|set(expected):
        if key not in ('proxies','proxy-groups') and actual.get(key)!=expected.get(key):
            raise ValueError('动态聚合改变了原配置字段：'+key)
    old={p['name']:p for p in expected['proxies']}
    new={p['name']:p for p in actual['proxies']}
    if not native_names or any(name not in old or new.get(name)!=old[name] for name in native_names):
        raise ValueError('动态聚合改变了自建节点')
    old_groups={g['name']:g for g in expected['proxy-groups']}
    new_groups={g['name']:g for g in actual['proxy-groups']}
    for name in ('日常线路','AI线路','Telegram','去广告','开启去广告','关闭去广告'):
        if name not in old_groups or name not in new_groups:
            raise ValueError('动态聚合缺少原策略组：'+name)
        if {k:v for k,v in old_groups[name].items() if k!='proxies'}!={k:v for k,v in new_groups[name].items() if k!='proxies'}:
            raise ValueError('动态聚合改变了策略组设置：'+name)
        if name in ('去广告','开启去广告','关闭去广告') and old_groups[name]['proxies']!=new_groups[name]['proxies']:
            raise ValueError('动态聚合改变了去广告开关')
    for name,group in old_groups.items():
        baseline=set(group.get('proxies',[]))&set(native_names)
        if baseline and (name not in new_groups or set(new_groups[name].get('proxies',[]))&set(native_names)!=baseline):
            raise ValueError('动态聚合改变了自建节点分组：'+name)


def check_shadowrocket_chains(body):
    links=[urlsplit(line) for line in body.splitlines() if line.startswith('vless://')]
    names={unquote(link.fragment) for link in links}
    for link in links:
        name=unquote(link.fragment)
        if not name.startswith(SELF_PREFIX):continue
        expected=ENTRY_PREFIX+name[len(SELF_PREFIX):]
        if expected not in names or parse_qs(link.query).get('chain')!=[expected]:
            raise ValueError('Shadowrocket 日本自建链引用无效')
