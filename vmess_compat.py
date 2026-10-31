"""Preserve existing TLS/auto VMess clients when updating Xray without zero support."""
import copy
from reality_compat import direct_only,DNS_TAG,OUT_TAG

def to_sing(native,settings):
    if native.get('protocol')!='vmess' or set(native)-{'tag','listen','port','protocol','settings','streamSettings','sniffing'}:
        raise ValueError('只迁移标准 VMess WebSocket 入站')
    values=native['settings'];stream=native['streamSettings']
    if set(values)-{'clients','disableInsecureEncryption'} or values.get('disableInsecureEncryption'):
        raise ValueError('VMess 具有不能无损迁移的安全设置')
    if set(stream)-{'network','security','wsSettings'} or stream.get('network')!='ws' or stream.get('security','none')!='none':
        raise ValueError('CF 源站必须为标准回环 WebSocket')
    if set(stream['wsSettings'])!={'path'} or '/'+stream['wsSettings']['path'].lstrip('/')!='/'+settings['ws_path'].lstrip('/'):
        raise ValueError('WebSocket 路径或监听参数需要先核对')
    users=[]
    for user in values['clients']:
        if set(user)-{'id','alterId','email'} or user.get('alterId',0)!=0:
            raise ValueError('VMess 用户具有不能迁移的选项')
        item={'uuid':user['id']}
        if user.get('email'):item['name']=user['email']
        users.append(item)
    return {'type':'vmess','tag':native['tag'],'listen':settings['listen'],'listen_port':settings['port'],
            'users':users,'transport':{'type':'ws','path':'/'+settings['ws_path'].lstrip('/')}}

def migrate(configs,state):
    from protocols import protocol_type,entry,export
    from inbounds import engines
    before=export(configs,state);result=copy.deepcopy(configs);updated=copy.deepcopy(state);engine_map=engines(state)
    choices=[p for p,e in engine_map.items() if e['core']=='sing-box']
    if not choices:raise ValueError('尚未安装稳定 sing-box')
    target=sorted(choices,key=lambda p:not p.endswith('/sb.json'))[0];retired=[]
    for ident,b in updated['bindings'].items():
        if protocol_type(ident,updated['protocols'][ident])!='cf' or b['core']=='sing-box':continue
        old_path=b['path'];old=result[old_path];settings=updated['protocols'][ident]
        native=entry(old,b) if settings['enabled'] else copy.deepcopy(b['inbound'])
        strategy=direct_only(old);converted=to_sing(native,settings);sb=result[target]
        if any(n.get('tag')==converted['tag'] for n in sb['inbounds']):raise ValueError('CF 入站 tag 冲突')
        sniff=native.get('sniffing',{})
        if set(sniff)-{'enabled','destOverride','metadataOnly','routeOnly'} or sniff.get('metadataOnly') or sniff.get('routeOnly'):
            raise ValueError('CF 嗅探策略不能自动映射')
        rules=sb.setdefault('route',{}).setdefault('rules',[])
        if sniff.get('enabled'):
            sniffers=sniff.get('destOverride',['http','tls','quic'])
            if set(sniffers)-{'http','tls','quic'}:raise ValueError('未知嗅探协议')
            rules.insert(0,{'inbound':[converted['tag']],'action':'sniff','sniffer':sniffers})
        if strategy not in ('AsIs','ForceIPv4v6'):raise ValueError('CF 出站地址策略不能自动映射')
        if strategy=='ForceIPv4v6':
            dns=sb.setdefault('dns',{}).setdefault('servers',[])
            resolver={'type':'local','tag':DNS_TAG};out={'type':'direct','tag':OUT_TAG,'domain_resolver':{'server':DNS_TAG,'strategy':'prefer_ipv4'}}
            if any(v.get('tag')==DNS_TAG and v!=resolver for v in dns) or any(v.get('tag')==OUT_TAG and v!=out for v in sb['outbounds']):
                raise ValueError('CF 出站或 DNS tag 冲突')
            if resolver not in dns:dns.append(resolver)
            if out not in sb['outbounds']:sb['outbounds'].append(out)
            rules.append({'inbound':[converted['tag']],'action':'route','outbound':OUT_TAG})
        if settings['enabled']:sb['inbounds'].append(converted);old['inbounds'].remove(native)
        b.update(path=target,core='sing-box',service=engine_map[target]['service'],inbound=copy.deepcopy(converted))
        if not old['inbounds'] and not any(x['path']==old_path for x in updated['bindings'].values()):
            retired.append({'path':old_path,**engine_map[old_path]});result.pop(old_path);engine_map.pop(old_path);updated.get('native_sha256',{}).pop(old_path,None)
    updated['engines']=engine_map
    if export(result,updated)!=before:raise ValueError('迁移改变了已有客户端节点，拒绝继续')
    return result,updated,retired
