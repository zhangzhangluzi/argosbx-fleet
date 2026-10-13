"""Prepare native Sub-Store source processors and client configuration templates."""
import json,pathlib,re,yaml,sys

from fleet import read, region_spec, host_map
from storage import save
from protocols import LABELS
from dns_policy import harden_config, harden_shadowrocket
root=pathlib.Path(__file__).parent
inventory=globals().get('inventory_override') or read()
node_hosts=host_map(inventory)
specs={s['id']:s for s in inventory['servers']}
countries={s['country']:s['country_name'] for s in specs.values()}
country_prefixes={label:[s['name'] for s in specs.values() if s['country']==code] for code,label in countries.items()}
purpose_groups=['地区-'+countries[c] for c in inventory['purpose_order']]
subscriptions=[]
for country,server in specs.items():
    script=(root/'region-processor.js').read_text().replace('SPEC',json.dumps(region_spec(server),ensure_ascii=False))
    subscriptions.append({'name':server['subscription']['name'],'displayName':server['name']+' · ArgoSBX','source':'remote','url':server['subscription']['url'],'ua':'ClashMeta','process':[{'type':'Script Operator','args':{'mode':'script','content':script}}]})
files=[]
for fmt in ('clash','stash'):
    base=yaml.safe_load((root/'templates'/('base-'+fmt+'.yaml')).read_text())
    base.pop('proxies',None);base.pop('proxy-groups',None)
    base['rules']=[r.replace(',UDP线路', ',日常线路') for r in base['rules']]
    base=harden_config(base,fmt,hosts=node_hosts)
    health={'url':'https://www.gstatic.com/generate_204','interval':inventory.get('health',{}).get('interval',900),'tolerance':50,'lazy':False}
    if fmt == 'clash':
        base['unified-delay']=True
        health.update({'timeout':8000,'max-failed-times':3,'expected-status':'204','tolerance':100})
    script='''function operator(input) {
 const source=ProxyUtils.yaml.safeLoad(input.$content);
 const proxies=CONVERSION;
 const config=BASE;
 config.proxies=proxies;
 const names=proxies.map(p=>p.name);
 const countryCodes=COUNTRY_PREFIXES;
 const inCountry=(n,c)=>countryCodes[c].some(prefix=>n.startsWith(prefix+'-T-')||n.startsWith(prefix+'-U-'));
 const countries=Object.keys(countryCodes).filter(c=>names.some(n=>inCountry(n,c)));
 const regions=countries.map(c=>'地区-'+c);
 config['proxy-groups']=[
  {name:'日常线路',type:'select',proxies:regions},
  {name:'AI线路',type:'select',proxies:['日常线路',...PURPOSE_GROUPS.filter(n=>regions.includes(n))]},
  {name:'Telegram',type:'select',proxies:['日常线路',...PURPOSE_GROUPS].filter(n=>n==='日常线路'||regions.includes(n))},
  ...countries.map(c=>({name:'地区-'+c,type:'url-test',proxies:names.filter(n=>inCountry(n,c)),...HEALTHCHECK})),
  {name:'去广告',type:'select',proxies:['开启去广告','关闭去广告']},
  {name:'开启去广告',type:'select',proxies:['REJECT'],hidden:true},
  {name:'关闭去广告',type:'select',proxies:['日常线路'],hidden:true}
 ];
 for(const g of config['proxy-groups'])if(!g.proxies.length)throw new Error('Missing country '+g.name);
 input.$content=ProxyUtils.yaml.safeDump(config);
 return input;
}'''.replace('COUNTRY_PREFIXES',json.dumps(country_prefixes,ensure_ascii=False)).replace('PURPOSE_GROUPS',json.dumps(purpose_groups,ensure_ascii=False)).replace('BASE',json.dumps(base,ensure_ascii=False)).replace('HEALTHCHECK',json.dumps(health,ensure_ascii=False)).replace('CONVERSION',"ProxyUtils.produce(ProxyUtils.parse(ProxyUtils.yaml.safeDump(source)), 'Stash', 'internal')" if fmt=='stash' else 'source.proxies')
    if fmt == 'clash':
        script = (root/'ech-policy.js').read_text().replace('CF_HOSTS',json.dumps([s['domains']['cf'] for s in specs.values() if s['domains']['cf']])) + '\n' + script.replace('const proxies=source.proxies;', 'const proxies=applyCfEch(source.proxies);')
    files.append({'name':fmt,'displayName':'ArgoSBX · '+fmt,'type':'mihomoConfig','sourceType':'collection','sourceName':'all','process':[{'type':'Script Operator','args':{'mode':'script','content':script}}]})
# Shadowrocket configuration keeps the accepted DNS, Play and Telegram rules.
sr=harden_shadowrocket((root/'templates'/'base-shadowrocket.conf').read_text(),hosts=node_hosts)
sr+='\n[Proxy Group]\n';start=sr.index('[Proxy Group]');end=len(sr)
groups=['[Proxy Group]','日常线路 = select, '+', '.join('地区-'+label for label in countries.values()),'AI线路 = select, 日常线路, '+', '.join(purpose_groups),'Telegram = select, 日常线路, '+', '.join(purpose_groups)]
for code,label in countries.items():
    names=[]
    for server in (s for s in specs.values() if s['country']==code):
        def node_name(protocol,family):
            transport='U' if protocol.startswith('Hysteria2') else 'T'
            return f"{server['name']}-{transport}-{family.replace('IP','')}-{protocol}"
        def enabled(label):
            ident=next(k for k,v in LABELS.items() if v==label)
            configured=server.get('protocols',{})
            return not configured or configured.get(ident,{}).get('enabled',False)
        families=[family for family,key in [('IPv4','ipv4'),('IPv6','ipv6')] if server[key]]
        names += [node_name(protocol,family) for protocol in ('VLESS-REALITY-Vision','Hysteria2') if enabled(protocol) for family in families]
        if server['domains']['cf'] and enabled('CF入口-VMess-WS-TLS'): names.append(server['name']+'-T-CF入口-VMess-WS-TLS')
        names += [node_name(protocol,family) for protocol in ('AnyTLS','SS2022-ShadowTLS-v3','Hysteria2-Salamander') if enabled(protocol) for family in families if family!='IPv6' or protocol!='Hysteria2-Salamander' or server['salamander_ipv6']]
    groups.append('地区-'+label+' = url-test, '+', '.join(names)+f", url=https://www.gstatic.com/generate_204, interval={inventory.get('health',{}).get('interval',900)}, timeout=5, tolerance=50")
sr=sr[:start]+'\n'.join(groups)+'\n'+sr[end:]
sr=sr.replace('PROTOCOL,UDP,UDP线路', 'PROTOCOL,UDP,日常线路')
files.append({'name':'shadowrocket-config','displayName':'Shadowrocket 自动策略','source':'local','content':sr,'process':[]})
payload={'subscriptions':subscriptions,'collections':[{'name':'all','displayName':' · '.join(countries.values()),'subscriptions':[s['subscription']['name'] for s in specs.values()],'process':[]}],'files':files}
export_processor={'type':'Response Transformer','customName':'FlClash 完整配置导出','args':{'mode':'script','content':(root/'flclash-response-transformer.js').read_text().replace('PROFILE_TITLES',json.dumps({'all':'ArgoSBX '+'-'.join(countries),**{s['subscription']['name']:'ArgoSBX '+s['name'] for s in specs.values()}},ensure_ascii=False)),'arguments':{'profile':'clash'}}}
for item in payload['subscriptions']+payload['collections']:
    item['process'].append(export_processor)
from fleet import STATE
p=STATE/'substore-payload.json';save(p,payload)
print(json.dumps({'subscriptions':len(subscriptions),'collections':1,'files':len(files),'groups_per_yaml':len(countries)+6,'visible_groups_per_yaml':len(countries)+4}))
