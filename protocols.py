"""Stable protocol identities and native configuration adapters; secrets stay on VPS."""
import copy
import ipaddress
import re

IDS=('reality','hy2','cf','anytls','shadowtls','salamander','xhttp')
LABELS={'reality':'VLESS-REALITY-Vision','hy2':'Hysteria2','cf':'CF入口-VMess-WS-TLS','anytls':'AnyTLS','shadowtls':'SS2022-ShadowTLS-v3','salamander':'Hysteria2-Salamander','xhttp':'CF入口-VLESS-XHTTP-TLS'}
FIELDS={'type','enabled','port','sni','certificate','cover_host','cover_port','listen','padding_scheme','ws_path','alpn','client','path','mode'}
CLIENT_FIELDS={'idle-session-check-interval','idle-session-timeout','min-idle-session','fast-open','client-fingerprint','udp-over-tcp','udp-over-tcp-version'}
CLIENT_BY_TYPE={
    'reality':{'fast-open','client-fingerprint'}, 'cf':{'fast-open','client-fingerprint'},
    'xhttp':{'client-fingerprint'}, 'hy2':set(), 'salamander':set(),
    'anytls':{'fast-open','client-fingerprint','idle-session-check-interval','idle-session-timeout','min-idle-session'},
    'shadowtls':{'fast-open','client-fingerprint','udp-over-tcp','udp-over-tcp-version'},
}
COMMON={'enabled','port','listen','client'}
EXTRA={'reality':{'sni','cover_host','cover_port'},'hy2':{'sni','certificate','alpn'},
       'cf':{'sni','ws_path'},'anytls':{'sni','certificate','alpn','padding_scheme'},
       'shadowtls':{'cover_host','cover_port'},'salamander':{'sni','certificate','alpn'},'xhttp':{'sni','path','mode'}}

def protocol_type(ident,settings):
    kind=settings.get('type',ident)
    if not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}',ident) or kind not in IDS:
        raise ValueError('未知协议类型或无效入站 ID: '+ident)
    return kind

def node_label(ident,settings):
    kind=protocol_type(ident,settings)
    return LABELS[kind]+('' if ident==kind else '@'+ident)

def validate_settings(settings,complete=False):
    if not isinstance(settings,dict):raise ValueError('协议参数必须为对象')
    for ident,p in settings.items():
        if not isinstance(p,dict) or set(p)-FIELDS:raise ValueError('未知协议参数: '+ident)
        kind=protocol_type(ident,p)
        if set(p)-(COMMON|EXTRA[kind]|{'type'}):raise ValueError('该协议不支持参数: '+ident)
        if complete and (COMMON|EXTRA[kind])-set(p):raise ValueError('缺少显式协议参数: '+ident)
        for k in ('port','cover_port'):
            if k in p and (type(p[k]) is not int or not 1<=p[k]<=65535):raise ValueError('端口无效: '+ident)
        if 'enabled' in p and type(p['enabled']) is not bool:raise ValueError('enabled 必须为布尔值')
        for k in ('sni','cover_host'):
            if k in p and not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}',p[k]):raise ValueError('TLS 域名无效')
        if 'listen' in p:
            ipaddress.ip_address(p['listen'])
            if kind in ('cf','xhttp') and not ipaddress.ip_address(p['listen']).is_loopback:raise ValueError('CF 源站只允许监听回环地址')
        if 'listen' in p and kind not in ('cf','xhttp') and (ipaddress.ip_address(p['listen']).is_loopback or ipaddress.ip_address(p['listen']).is_multicast):raise ValueError('公开直连入站不能只监听回环或组播地址')
        if 'path' in p and (not isinstance(p['path'],str) or not re.fullmatch(r'/[A-Za-z0-9_-]{8,128}',p['path'])):raise ValueError('XHTTP 路径无效')
        if 'mode' in p and p['mode'] not in ('packet-up','stream-up'):raise ValueError('CF XHTTP 仅支持 packet-up / stream-up')
        if 'ws_path' in p and isinstance(p['ws_path'],str) and any(c in p['ws_path'] for c in ('?','#','%','\\',':')):raise ValueError('WS 路径必须为纯路径，不能包含查询参数、片段或编码分隔符')
        if 'ws_path' in p and (not isinstance(p['ws_path'],str) or not 1<=len(p['ws_path'])<=2048 or any(c.isspace() for c in p['ws_path'])):raise ValueError('WS 路径无效')
        if 'certificate' in p and not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}',p['certificate']):raise ValueError('证书引用无效')
        if 'padding_scheme' in p and (kind!='anytls' or not isinstance(p['padding_scheme'],list) or any(not isinstance(x,str) for x in p['padding_scheme'])):raise ValueError('padding_scheme 无效')
        if 'alpn' in p and (not isinstance(p['alpn'],list) or any(not isinstance(x,str) or not x for x in p['alpn'])):raise ValueError('ALPN 无效')
        if 'client' in p:
            if not isinstance(p['client'],dict) or set(p['client'])-CLIENT_BY_TYPE[kind]:raise ValueError('该协议的客户端参数无效: '+ident)
            for key,value in p['client'].items():
                if key in ('fast-open','udp-over-tcp') and type(value) is not bool:raise ValueError('客户端开关必须为布尔值')
                if key in ('idle-session-check-interval','idle-session-timeout') and (type(value) is not int or not 0<=value<=86400):raise ValueError('连接复用周期无效')
                if key=='min-idle-session' and (type(value) is not int or not 0<=value<=8):raise ValueError('保留空闲会话必须为 0 到 8')
                if key=='udp-over-tcp-version' and (type(value) is not int or value not in (1,2)):raise ValueError('UDP over TCP 版本无效')
                if key=='client-fingerprint' and (not isinstance(value,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,32}',value)):raise ValueError('客户端 TLS 指纹无效')

def families(ident,p,server):
    kind=protocol_type(ident,p);listen=ipaddress.ip_address(p.get('listen','::'))
    # Xray treats its unspecified address as dual-stack; sing-box binds the literal family.
    both=listen.is_unspecified and (listen.version==6 or kind in ('reality','hy2'))
    return [f for f in ('ipv4','ipv6') if server.get(f) and (both or listen.version==(4 if f=='ipv4' else 6)) and not (f=='ipv6' and kind=='salamander' and not server['salamander_ipv6'])]

def cf_origin(p):
    ip=ipaddress.ip_address(p['listen'])
    if not ip.is_loopback:raise ValueError('CF 源站只允许回环地址')
    return 'http://'+('['+str(ip)+']' if ip.version==6 else str(ip))+':'+str(p['port'])

def migrate_references(server,names,certificate=None):
    target=copy.deepcopy(server);old=server['domains'].get('cf')
    for role,name in names.items():
        if role!='certificate':target['domains'][role]=name
    if names.get('cf'):
        for ident,p in target['protocols'].items():
            if protocol_type(ident,p) in ('cf','xhttp') and p['sni']==old:p['sni']=names['cf']
    if certificate:
        target['certificates']['domain']=certificate
        for ident,p in target['protocols'].items():
            if protocol_type(ident,p) in ('hy2','anytls','salamander'):p.update(certificate='domain',sni=names['certificate'])
    return target

def classify(node):
    t=node.get('type')
    if t=='vless' and node.get('network')=='xhttp':return 'xhttp'
    if t=='vless' and node.get('reality-opts'):return 'reality'
    if t=='hysteria2':return 'salamander' if node.get('obfs')=='salamander' else 'hy2'
    if t=='vmess' and node.get('network')=='ws' and node.get('tls'):return 'cf'
    if t=='anytls':return 'anytls'
    if t=='ss' and node.get('plugin')=='shadow-tls' and node.get('cipher','').startswith('2022-'):return 'shadowtls'
    raise ValueError('未识别的源节点协议')

def entry(config,binding):
    found=[x for x in config['inbounds'] if x.get('tag')==binding['tag']]
    if len(found)!=1:raise ValueError('协议映射缺失或重复: '+binding['tag'])
    return found[0]

def adopt(configs,clients,services):
    bindings={};templates={}
    for n in clients:
        if n.get('type')=='vmess' and n.get('network')=='ws' and not n.get('tls'):continue
        ident=classify(n)
        if ident in templates:raise ValueError('同协议源节点重复')
        templates[ident]=copy.deepcopy(n)
    for path,c in configs.items():
        for n in c['inbounds']:
            t=n.get('type',n.get('protocol'))
            ident={'hysteria':'hy2','anytls':'anytls','shadowtls':'shadowtls','hysteria2':'salamander','vmess':'cf','vless':'reality'}.get(t)
            if t=='vless' and n.get('streamSettings',{}).get('network')=='xhttp':ident='xhttp'
            if not ident:continue
            if ident in bindings:raise ValueError('同协议存在多个入站，需要显式映射')
            bindings[ident]={'path':path,'tag':n['tag'],'core':'sing-box' if 'type' in n else 'xray','service':services[path],'inbound':copy.deepcopy(n)}
    if set(bindings)!=set(templates):raise ValueError('服务端与源节点的协议集合不一致')
    state={'schema':1,'bindings':bindings,'templates':templates,'certificates':{},'protocols':{}}
    for ident,b in bindings.items():
        n=entry(configs[b['path']],b);p={'enabled':True,'port':n.get('listen_port',n.get('port')),'listen':n.get('listen','0.0.0.0')}
        tls=n.get('tls',n.get('streamSettings',{}).get('tlsSettings'))
        if tls:
            if b['core']=='sing-box': cert,key=tls['certificate_path'],tls['key_path']
            else:cert,key=tls['certificates'][0]['certificateFile'],tls['certificates'][0]['keyFile']
            pair={'certificate_file':cert,'key_file':key}
            ref=next((k for k,v in state['certificates'].items() if v==pair), 'tls'+str(len(state['certificates'])+1))
            state['certificates'][ref]=pair;p.update(certificate=ref,sni=templates[ident].get('sni',templates[ident].get('servername')),alpn=tls.get('alpn',[]))
        if ident=='reality':
            r=n['streamSettings']['realitySettings'];host,port=r.get('target',r.get('dest')).rsplit(':',1)
            p.update(sni=r['serverNames'][0],cover_host=host,cover_port=int(port))
        if ident=='shadowtls':p.update(cover_host=n['handshake']['server'],cover_port=n['handshake']['server_port'])
        if ident=='cf':p.update(sni=templates[ident]['servername'],ws_path=n['streamSettings']['wsSettings']['path'])
        if ident=='xhttp':p.update(sni=templates[ident]['servername'],path=n['streamSettings']['xhttpSettings']['path'],mode=n['streamSettings']['xhttpSettings']['mode'])
        if ident=='anytls':p['padding_scheme']=n.get('padding_scheme',[])
        p['client']={k:v for k,v in templates[ident].items() if k in CLIENT_BY_TYPE[ident]}
        state['protocols'][ident]=p
    validate_settings(state['protocols'])
    return state

def render(configs,state,desired):
    validate_settings(desired,complete=True)
    if set(desired)!=set(state['bindings']):raise ValueError('必须显式配置所有已登记协议')
    result=copy.deepcopy(configs);listeners=set()
    for ident,b in state['bindings'].items():
        p=desired[ident];kind=protocol_type(ident,p)
        found=[x for x in result[b['path']]['inbounds'] if x.get('tag')==b['tag']]
        if found:n=found[0]
        else:
            n=copy.deepcopy(b['inbound']);result[b['path']]['inbounds'].append(n)
        if not p['enabled']:
            result[b['path']]['inbounds'].remove(n);continue
        transport='udp' if kind in ('hy2','salamander') else 'tcp'
        socket=(transport,p['port'])
        if socket in listeners:raise ValueError('协议端口冲突')
        listeners.add(socket)
        same_certificate=True
        if p.get('certificate'):
            cert=state['certificates'][p['certificate']]
            tls=n.get('tls',n.get('streamSettings',{}).get('tlsSettings',{}))
            actual={'certificate_file':tls.get('certificate_path'),'key_file':tls.get('key_path')} if b['core']=='sing-box' else {'certificate_file':tls['certificates'][0]['certificateFile'],'key_file':tls['certificates'][0]['keyFile']}
            same_certificate=actual==cert
        # Client-only tuning must never normalize/rewrite a running native listener.
        native_settings=lambda value:{k:v for k,v in value.items() if k!='client'}
        if native_settings(p)==native_settings(state['protocols'][ident]) and same_certificate:continue
        n['listen']=p['listen'];n['listen_port' if b['core']=='sing-box' else 'port']=p['port']
        if 'certificate' in p:
            c=state['certificates'][p['certificate']]
            if b['core']=='sing-box':
                n['tls'].update(certificate_path=c['certificate_file'],key_path=c['key_file'])
                if p.get('alpn') or 'alpn' in n['tls']:n['tls']['alpn']=p.get('alpn',[])
            else:
                tls=n['streamSettings']['tlsSettings'];tls['certificates'][0].update(certificateFile=c['certificate_file'],keyFile=c['key_file'])
                tls['alpn']=p.get('alpn',[])
        if kind=='reality':
            r=n['streamSettings']['realitySettings'];r['serverNames']=[p['sni']];r['target']=p['cover_host']+':'+str(p['cover_port']);r.pop('dest',None)
        if kind=='shadowtls':n['handshake'].update(server=p['cover_host'],server_port=p['cover_port'])
        if kind=='cf':n['streamSettings']['wsSettings']['path']=p['ws_path']
        if kind=='xhttp':n['streamSettings']['xhttpSettings'].update(path=p['path'],mode=p['mode'])
        if kind=='anytls':n['padding_scheme']=p['padding_scheme']
    # Include auxiliary/unmanaged inbounds (for example ShadowTLS's inner SS)
    # when checking conflicts, rather than checking only published protocols.
    occupied=set()
    for config in result.values():
        for inbound in config['inbounds']:
            port=inbound.get('listen_port',inbound.get('port'))
            if not port:continue
            transport='udp' if inbound.get('type',inbound.get('protocol')) in ('hysteria','hysteria2','tuic') else 'tcp'
            key=(transport,port)
            if key in occupied:raise ValueError('与其他原生入站端口冲突')
            occupied.add(key)
    return result

def export(configs,state):
    result=[]
    for ident,template in state['templates'].items():
        p=state['protocols'][ident];kind=protocol_type(ident,p)
        if not p['enabled']:continue
        b=state['bindings'][ident];n=entry(configs[b['path']],b);node=copy.deepcopy(template)
        for key in CLIENT_FIELDS:node.pop(key,None)
        node.update(p.get('client',{}));node['port']=p['port']
        if kind=='reality':
            r=n['streamSettings']['realitySettings'];node.update(uuid=n['settings']['clients'][0]['id'],servername=r['serverNames'][0]);node['reality-opts']['short-id']=node['reality-opts']['short-id'] if str(node['reality-opts']['short-id']) in r['shortIds'] else r['shortIds'][0]
        elif kind=='hy2':node.update(password=n['settings']['clients'][0]['auth'],sni=p['sni'],alpn=p['alpn'])
        elif kind in ('anytls','salamander'):
            node.update(password=n['users'][0]['password'],sni=p['sni'])
            node.pop('alpn',None)
            if p.get('alpn'):node['alpn']=p['alpn']
            if kind=='salamander':node['obfs-password']=n['obfs']['password']
        elif kind=='shadowtls':
            inner=entry(configs[b['path']],{'tag':n['detour']});node.update(password=inner['password'],cipher=inner['method'])
            node['plugin-opts'].update(host=p['cover_host'],password=n['users'][0]['password'],version=n['version'])
        elif kind=='cf':
            node.update(port=443,server=p['sni'],servername=p['sni'],uuid=n['settings']['clients'][0]['id'])
            node['ws-opts'].update(path=p['ws_path']);node['ws-opts'].setdefault('headers',{})['Host']=p['sni']
        elif kind=='xhttp':
            node.update(port=443,server=p['sni'],servername=p['sni'],uuid=n['settings']['clients'][0]['id'])
            node['xhttp-opts'].update(path=p['path'],mode=p['mode'],host=p['sni'])
        from ech import client_options
        node.pop('ech-opts',None)
        node.update(client_options(state,ident,n))
        result.append(node)
    return {'proxies':result}
