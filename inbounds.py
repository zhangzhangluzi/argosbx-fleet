"""Create independent native inbound identities; credentials never enter inventory."""
import base64
import copy
import secrets
import subprocess
import uuid
from protocols import protocol_type,validate_settings,LABELS

CORES={'reality':'xray','hy2':'xray','cf':'xray','anytls':'sing-box','shadowtls':'sing-box','salamander':'sing-box'}

def x25519(binary='/root/agsbx/xray'):
    p=subprocess.run([binary,'x25519'],text=True,capture_output=True,check=True,timeout=10)
    values=dict(line.split(':',1) for line in p.stdout.splitlines() if ':' in line)
    private=(values.get('PrivateKey') or values.get('Private key') or '').strip()
    public=(values.get('Password (PublicKey)') or values.get('Password') or values.get('PublicKey') or values.get('Public key') or '').strip()
    if not private or not public:raise ValueError('Xray 未返回完整 X25519 密钥对')
    return private,public

def engines(state):
    result=copy.deepcopy(state.get('engines',{}))
    for binding in state['bindings'].values():
        result[binding['path']]={k:binding[k] for k in ('core','service')}
    return result

def create(ident,p,certificates,keygen=x25519):
    kind=protocol_type(ident,p);tag='fleet-'+ident
    password=secrets.token_urlsafe(32);uid=str(uuid.uuid4())
    node={'name':'fleet.'+ident,'server':'127.0.0.1','port':p['port'],'udp':True}
    native={'tag':tag,'listen':p['listen']};aux=[]
    if CORES[kind]=='xray':native['port']=p['port']
    else:native['listen_port']=p['port']
    pair=certificates.get(p.get('certificate'),{})
    tls={'enabled':True,'certificate_path':pair.get('certificate_file'),'key_path':pair.get('key_file'),'alpn':p.get('alpn',[])}
    if kind=='reality':
        private,public=keygen();short=secrets.token_hex(8)
        native.update(protocol='vless',settings={'clients':[{'id':uid,'flow':'xtls-rprx-vision'}],'decryption':'none'},streamSettings={'network':'raw','security':'reality','realitySettings':{'target':p['cover_host']+':'+str(p['cover_port']),'serverNames':[p['sni']],'privateKey':private,'shortIds':[short]}})
        node.update(type='vless',uuid=uid,flow='xtls-rprx-vision',tls=True,servername=p['sni'],**{'client-fingerprint':'chrome','reality-opts':{'public-key':public,'short-id':short}})
    elif kind=='hy2':
        native.update(protocol='hysteria',settings={'version':2,'clients':[{'auth':password}]},streamSettings={'network':'hysteria','security':'tls','tlsSettings':{'alpn':p['alpn'],'certificates':[{'certificateFile':pair['certificate_file'],'keyFile':pair['key_file']}]}})
        node.update(type='hysteria2',password=password,sni=p['sni'],alpn=p['alpn'],**{'skip-cert-verify':False})
    elif kind=='cf':
        native.update(protocol='vmess',settings={'clients':[{'id':uid}]},streamSettings={'network':'ws','security':'none','wsSettings':{'path':p['ws_path']}})
        node.update(type='vmess',uuid=uid,server=p['sni'],servername=p['sni'],port=443,tls=True,network='ws',alterId=0,cipher='auto',**{'ws-opts':{'path':p['ws_path'],'headers':{'Host':p['sni']}},'skip-cert-verify':False})
    elif kind=='anytls':
        native.update(type='anytls',users=[{'name':ident,'password':password}],padding_scheme=p['padding_scheme'],tls=tls)
        node.update(type='anytls',password=password,sni=p['sni'],**{'skip-cert-verify':False})
    elif kind=='salamander':
        obfs=secrets.token_urlsafe(32)
        native.update(type='hysteria2',users=[{'name':ident,'password':password}],obfs={'type':'salamander','password':obfs},tls=tls)
        node.update(type='hysteria2',password=password,obfs='salamander',sni=p['sni'],**{'obfs-password':obfs,'skip-cert-verify':False})
    else:
        ss=base64.b64encode(secrets.token_bytes(16)).decode();inner=tag+'-inner'
        native.update(type='shadowtls',version=3,users=[{'name':ident,'password':password}],handshake={'server':p['cover_host'],'server_port':p['cover_port']},strict_mode=True,detour=inner)
        # Detour-only inbound: no additional public or loopback listening port.
        aux=[{'type':'shadowsocks','tag':inner,'method':'2022-blake3-aes-128-gcm','password':ss,'network':'tcp'}]
        node.update(type='ss',cipher='2022-blake3-aes-128-gcm',password=ss,plugin='shadow-tls',**{'plugin-opts':{'host':p['cover_host'],'password':password,'version':3},'udp-over-tcp':True,'udp-over-tcp-version':2})
    return native,aux,node

def reconcile(configs,state,desired,keygen=x25519):
    """Build a candidate registry and configs; no disk writes or service actions."""
    validate_settings(desired,complete=True)
    if not desired or not any(p['enabled'] for p in desired.values()):raise ValueError('至少保留一个启用入站；整机退出请移除服务器')
    result=copy.deepcopy(configs);updated=copy.deepcopy(state)
    engine_map=engines(state)
    for ident,b in list(updated['bindings'].items()):
        if ident in desired:
            if protocol_type(ident,desired[ident])!=protocol_type(ident,state['protocols'][ident]):raise ValueError('入站 ID 不能变更协议类型，请使用新 ID')
            continue
        tags={b['tag'],*b.get('auxiliary_tags',[])}
        old=next((x for x in result[b['path']]['inbounds'] if x.get('tag')==b['tag']),b['inbound'])
        if protocol_type(ident,state['protocols'][ident])=='shadowtls':tags.add(old['detour'])
        result[b['path']]['inbounds']=[x for x in result[b['path']]['inbounds'] if x.get('tag') not in tags]
        for key in ('bindings','templates','protocols'):updated[key].pop(ident,None)
    added=[]
    for ident,p in desired.items():
        if ident in updated['bindings']:continue
        core=CORES[protocol_type(ident,p)]
        choices=[path for path,engine in engine_map.items() if engine['core']==core]
        if not choices:raise ValueError('尚未安装 '+core+' 引擎；先运行 server-install')
        path=sorted(choices,key=lambda x:(not x.endswith('/xr.json'),x))[0]
        n,aux,node=create(ident,p,updated['certificates'],keygen)
        existing={x.get('tag') for c in result.values() for x in c['inbounds']}
        if existing & {n['tag'],*(x['tag'] for x in aux)}:raise ValueError('新增入站 tag 与原配置冲突')
        result[path]['inbounds'] += [n]+aux
        updated['bindings'][ident]={'path':path,**engine_map[path],'tag':n['tag'],'inbound':copy.deepcopy(n),'auxiliary_tags':[x['tag'] for x in aux]}
        updated['templates'][ident]=node;updated['protocols'][ident]=copy.deepcopy(p);added.append(ident)
    if set(desired)!=set(state['protocols']):updated['engines']=engine_map
    return result,updated,{'added':added,'removed':sorted(set(state['protocols'])-set(desired))}
