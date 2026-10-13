"""Stable protocol identities and native configuration adapters; secrets stay on VPS."""
import copy
import ipaddress
import re

IDS=('reality','hy2','cf','anytls','shadowtls','salamander')
LABELS={'reality':'VLESS-REALITY-Vision','hy2':'Hysteria2','cf':'CF入口-VMess-WS-TLS','anytls':'AnyTLS','shadowtls':'SS2022-ShadowTLS-v3','salamander':'Hysteria2-Salamander'}
FIELDS={'enabled','port','sni','certificate','cover_host','cover_port','listen','padding_scheme','ws_path','alpn','client'}

def validate_settings(settings):
    if not isinstance(settings,dict) or set(settings)-set(IDS):raise ValueError('未知协议标识')
    for ident,p in settings.items():
        if not isinstance(p,dict) or set(p)-FIELDS:raise ValueError('未知协议参数: '+ident)
        for k in ('port','cover_port'):
            if k in p and (type(p[k]) is not int or not 1<=p[k]<=65535):raise ValueError('端口无效: '+ident)
        if 'enabled' in p and type(p['enabled']) is not bool:raise ValueError('enabled 必须为布尔值')
        for k in ('sni','cover_host'):
            if k in p and not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}',p[k]):raise ValueError('TLS 域名无效')
        if 'listen' in p:
            ipaddress.ip_address(p['listen'])
            if ident=='cf' and not ipaddress.ip_address(p['listen']).is_loopback:raise ValueError('CF 源站只允许监听回环地址')
        if 'ws_path' in p and (not isinstance(p['ws_path'],str) or not 1<=len(p['ws_path'])<=2048 or any(c.isspace() for c in p['ws_path'])):raise ValueError('WS 路径无效')
        if 'certificate' in p and not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}',p['certificate']):raise ValueError('证书引用无效')
        if 'padding_scheme' in p and (ident!='anytls' or not isinstance(p['padding_scheme'],list) or any(not isinstance(x,str) for x in p['padding_scheme'])):raise ValueError('padding_scheme 无效')
        if 'alpn' in p and (not isinstance(p['alpn'],list) or any(not isinstance(x,str) or not x for x in p['alpn'])):raise ValueError('ALPN 无效')
        if 'client' in p:
            allowed={'idle-session-check-interval','idle-session-timeout','fast-open','client-fingerprint','udp-over-tcp','udp-over-tcp-version'}
            if not isinstance(p['client'],dict) or set(p['client'])-allowed:raise ValueError('客户端参数无效')
            for key,value in p['client'].items():
                if key in ('fast-open','udp-over-tcp') and type(value) is not bool:raise ValueError('客户端开关必须为布尔值')
                if key in ('idle-session-check-interval','idle-session-timeout') and (type(value) is not int or not 0<=value<=86400):raise ValueError('连接复用周期无效')
                if key=='udp-over-tcp-version' and value not in (1,2):raise ValueError('UDP over TCP 版本无效')
                if key=='client-fingerprint' and (not isinstance(value,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,32}',value)):raise ValueError('客户端 TLS 指纹无效')

def classify(node):
    t=node.get('type')
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
        if ident=='anytls':p['padding_scheme']=n.get('padding_scheme',[])
        p['client']={k:v for k,v in templates[ident].items() if k in {'idle-session-check-interval','idle-session-timeout','fast-open','client-fingerprint','udp-over-tcp','udp-over-tcp-version'}}
        state['protocols'][ident]=p
    validate_settings(state['protocols'])
    return state

def render(configs,state,desired):
    validate_settings(desired)
    if set(desired)!=set(state['bindings']):raise ValueError('必须显式配置所有已登记协议')
    result=copy.deepcopy(configs);listeners=set()
    for ident,b in state['bindings'].items():
        p=desired[ident]
        found=[x for x in result[b['path']]['inbounds'] if x.get('tag')==b['tag']]
        if found:n=found[0]
        else:
            n=copy.deepcopy(b['inbound']);result[b['path']]['inbounds'].append(n)
        if not p['enabled']:
            result[b['path']]['inbounds'].remove(n);continue
        transport='udp' if ident in ('hy2','salamander') else 'tcp'
        socket=(transport,p['port'])
        if socket in listeners:raise ValueError('协议端口冲突')
        listeners.add(socket)
        same_certificate=True
        if p.get('certificate'):
            cert=state['certificates'][p['certificate']]
            tls=n.get('tls',n.get('streamSettings',{}).get('tlsSettings',{}))
            actual={'certificate_file':tls.get('certificate_path'),'key_file':tls.get('key_path')} if b['core']=='sing-box' else {'certificate_file':tls['certificates'][0]['certificateFile'],'key_file':tls['certificates'][0]['keyFile']}
            same_certificate=actual==cert
        if p==state['protocols'][ident] and same_certificate:continue
        n['listen']=p['listen'];n['listen_port' if b['core']=='sing-box' else 'port']=p['port']
        if 'certificate' in p:
            c=state['certificates'][p['certificate']]
            if b['core']=='sing-box':
                n['tls'].update(certificate_path=c['certificate_file'],key_path=c['key_file'])
                if p.get('alpn') or 'alpn' in n['tls']:n['tls']['alpn']=p.get('alpn',[])
            else:
                tls=n['streamSettings']['tlsSettings'];tls['certificates'][0].update(certificateFile=c['certificate_file'],keyFile=c['key_file'])
                tls['alpn']=p.get('alpn',[])
        if ident=='reality':
            r=n['streamSettings']['realitySettings'];r['serverNames']=[p['sni']];r['target']=p['cover_host']+':'+str(p['cover_port']);r.pop('dest',None)
        if ident=='shadowtls':n['handshake'].update(server=p['cover_host'],server_port=p['cover_port'])
        if ident=='cf':n['streamSettings']['wsSettings']['path']=p['ws_path']
        if ident=='anytls':n['padding_scheme']=p['padding_scheme']
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
        p=state['protocols'][ident]
        if not p['enabled']:continue
        b=state['bindings'][ident];n=entry(configs[b['path']],b);node=copy.deepcopy(template)
        node.update(p.get('client',{}));node['port']=p['port']
        if ident=='reality':
            r=n['streamSettings']['realitySettings'];node.update(uuid=n['settings']['clients'][0]['id'],servername=r['serverNames'][0]);node['reality-opts']['short-id']=node['reality-opts']['short-id'] if str(node['reality-opts']['short-id']) in r['shortIds'] else r['shortIds'][0]
        elif ident=='hy2':node.update(password=n['settings']['clients'][0]['auth'],sni=p['sni'],alpn=p['alpn'])
        elif ident in ('anytls','salamander'):
            node.update(password=n['users'][0]['password'],sni=p['sni'])
            if p.get('alpn'):node['alpn']=p['alpn']
            if ident=='salamander':node['obfs-password']=n['obfs']['password']
        elif ident=='shadowtls':
            inner=entry(configs[b['path']],{'tag':n['detour']});node.update(password=inner['password'],cipher=inner['method'])
            node['plugin-opts'].update(host=p['cover_host'],password=n['users'][0]['password'],version=n['version'])
        elif ident=='cf':
            node.update(port=443,server=p['sni'],servername=p['sni'],uuid=n['settings']['clients'][0]['id'])
            node['ws-opts'].update(path=p['ws_path']);node['ws-opts'].setdefault('headers',{})['Host']=p['sni']
        result.append(node)
    return {'proxies':result}
