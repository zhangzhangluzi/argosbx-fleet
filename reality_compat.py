"""Use the existing stable sing-box REALITY server without changing client identities."""
import copy,ipaddress

LOCAL_DNS_RULE={'action':'allow','network':'udp','ip':['127.0.0.53/32'],'port':53}
DNS_TAG='fleet-reality-local-dns'
OUT_TAG='fleet-reality-direct'

def direct_only(config):
    if set(config)-{'log','inbounds','outbounds','routing'}:raise ValueError('旧 REALITY 具有额外内核功能，不自动迁移')
    outs=config.get('outbounds',[])
    if len(outs)!=1 or outs[0].get('protocol')!='freedom' or set(outs[0].get('settings',{}))-{'domainStrategy'}:raise ValueError('旧 REALITY 具有自定义出站，不自动迁移')
    for rule in config.get('routing',{}).get('rules',[]):
        if (set(rule)-{'type','ip','network','outboundTag'} or rule.get('type')!='field' or rule.get('outboundTag')!=outs[0].get('tag') or rule.get('network','tcp,udp')!='tcp,udp' or ('ip' in rule and set(rule['ip'])!={'::/0','0.0.0.0/0'})):
            raise ValueError('旧 REALITY 具有非默认路由规则，需要先映射再迁移')
    return outs[0].get('settings',{}).get('domainStrategy','AsIs')

def cleanup_routes(config,tag):
    rules=config.get('route',{}).get('rules',[])
    for rule in list(rules):
        inbound=rule.get('inbound')
        if inbound==tag or inbound==[tag]:rules.remove(rule)
        elif isinstance(inbound,list) and tag in inbound:rule['inbound']=[v for v in inbound if v!=tag]
    if any(rule.get('outbound')==OUT_TAG for rule in rules):return
    for out in list(config.get('outbounds',[])):
        if out=={'type':'direct','tag':OUT_TAG,'domain_resolver':{'server':DNS_TAG,'strategy':'prefer_ipv4'}}:config['outbounds'].remove(out)
    # Do not remove a resolver used by other manually configured consumers.
    dns=config.get('dns',{}).get('servers',[])
    remaining=copy.deepcopy(config)
    if 'dns' in remaining:remaining['dns']['servers']=[v for v in remaining['dns'].get('servers',[]) if v!={'type':'local','tag':DNS_TAG}]
    import json
    if DNS_TAG not in json.dumps(remaining):
        dns[:]=[v for v in dns if v!={'type':'local','tag':DNS_TAG}]

def xray_targets(configs):
    result=copy.deepcopy(configs)
    for config in result.values():
        for outbound in config.get('outbounds',[]):
            if outbound.get('protocol')!='freedom':continue
            rules=outbound.setdefault('settings',{}).setdefault('finalRules',[])
            if LOCAL_DNS_RULE not in rules:
                if rules:raise ValueError('已有 Freedom finalRules，需要先核对本机 DNS 例外')
                rules.append(copy.deepcopy(LOCAL_DNS_RULE))
    return result

def to_sing(native,settings):
    if native.get('protocol')!='vless' or native['settings'].get('decryption')!='none':raise ValueError('只迁移未启用额外 VLESS Encryption 的 REALITY')
    stream=native['streamSettings'];r=stream['realitySettings']
    if set(native)-{'tag','listen','port','protocol','settings','streamSettings','sniffing'} or set(native['settings'])-{'clients','decryption'} or set(stream)-{'network','security','realitySettings'}:raise ValueError('存在不能无损迁移的 REALITY 监听选项')
    if stream.get('network') not in ('tcp','raw') or stream.get('security')!='reality':raise ValueError('REALITY 传输类型不兼容')
    if set(r)-{'serverNames','target','dest','privateKey','shortIds','fingerprint','show','maxTimeDiff'}:raise ValueError('存在不能无损迁移的 REALITY 参数')
    if r['serverNames']!=[settings['sni']]:raise ValueError('sing-box REALITY 需要唯一且一致的 SNI')
    users=[]
    for client in native['settings']['clients']:
        if set(client)-{'id','flow','email'}:raise ValueError('存在不能迁移的 REALITY 用户选项')
        user={'uuid':client['id'],'flow':client.get('flow','')}
        if client.get('email'):user['name']=client['email']
        users.append(user)
    address=settings['listen']
    if ipaddress.ip_address(address).is_unspecified:address='::'
    reality={'enabled':True,'handshake':{'server':settings['cover_host'],'server_port':settings['cover_port']},'private_key':r['privateKey'],'short_id':copy.deepcopy(r['shortIds'])}
    if r.get('maxTimeDiff'):reality['max_time_difference']=str(r['maxTimeDiff'])+'ms'
    return {'type':'vless','tag':native['tag'],'listen':address,'listen_port':settings['port'],'users':users,'tls':{'enabled':True,'server_name':settings['sni'],'reality':reality}}

def migrate(configs,state):
    from protocols import protocol_type,entry,export
    from inbounds import engines
    before=export(configs,state);result=copy.deepcopy(configs);updated=copy.deepcopy(state);engine_map=engines(state);retired=[]
    choices=[path for path,e in engine_map.items() if e['core']=='sing-box']
    if not choices:raise ValueError('尚未安装稳定 sing-box')
    target=sorted(choices,key=lambda p:not p.endswith('/sb.json'))[0]
    for ident,binding in updated['bindings'].items():
        if protocol_type(ident,updated['protocols'][ident])!='reality' or binding['core']=='sing-box':continue
        old_path=binding['path'];old_config=result[old_path];settings=updated['protocols'][ident]
        native=entry(old_config,binding) if settings['enabled'] else copy.deepcopy(binding['inbound'])
        # Arbitrary routing/outbound policies must not disappear during a backend move.
        strategy=direct_only(old_config)
        converted=to_sing(native,settings);sb=result[target]
        if any(n.get('tag')==converted['tag'] for n in sb['inbounds']):raise ValueError('REALITY 入站 tag 冲突')
        sniff=native.get('sniffing',{})
        if sniff.get('metadataOnly') or set(sniff)-{'enabled','destOverride','metadataOnly','routeOnly'}:raise ValueError('存在不能迁移的嗅探参数')
        rules=sb.setdefault('route',{}).setdefault('rules',[])
        if sniff.get('enabled'):
            sniffers=sniff.get('destOverride',['http','tls','quic'])
            if set(sniffers)-{'http','tls','quic'}:raise ValueError('存在不能迁移的嗅探协议')
            rules.insert(0,{'inbound':[converted['tag']],'action':'sniff','sniffer':sniffers})
        if strategy not in ('AsIs','ForceIPv4v6'):raise ValueError('REALITY 出站地址策略不能自动映射')
        if strategy=='ForceIPv4v6':
            dns_tag=DNS_TAG;out_tag=OUT_TAG
            dns=sb.setdefault('dns',{}).setdefault('servers',[])
            dns_value={'type':'local','tag':dns_tag};out_value={'type':'direct','tag':out_tag,'domain_resolver':{'server':dns_tag,'strategy':'prefer_ipv4'}}
            if any(v.get('tag')==dns_tag and v!=dns_value for v in dns) or any(v.get('tag')==out_tag and v!=out_value for v in sb['outbounds']):raise ValueError('REALITY 出站或 DNS tag 冲突')
            if dns_value not in dns:dns.append(dns_value)
            if out_value not in sb['outbounds']:sb['outbounds'].append(out_value)
            rules.append({'inbound':[converted['tag']],'action':'route','outbound':out_tag})
        if settings['enabled']:
            sb['inbounds'].append(converted);old_config['inbounds'].remove(native)
        binding.update(path=target,core='sing-box',service=engine_map[target]['service'],inbound=copy.deepcopy(converted))
        if not old_config['inbounds'] and not any(v['path']==old_path for v in updated['bindings'].values()):
            retired.append({'path':old_path,**engine_map[old_path]});result.pop(old_path);engine_map.pop(old_path);updated['native_sha256'].pop(old_path,None)
    updated['engines']=engine_map
    if export(result,updated)!=before:raise ValueError('迁移改变了客户端节点信息，拒绝继续')
    return result,updated,retired
