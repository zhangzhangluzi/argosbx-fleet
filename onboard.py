#!/usr/bin/env python3
"""One controller command: blank host, Cloudflare, certificates, native source, publication."""
import argparse,base64,copy,hashlib,json,os,secrets,shlex,socket,subprocess,sys,tempfile,time
from pathlib import Path
from urllib.parse import urlsplit
import urllib.request
from fleet import read,servers,ssh_args,STATE,DEFAULT
from storage import save,lock
from domains import Cloudflare
import tunnels
ROOT=Path(__file__).resolve().parent

def command(config,ident,args,payload=None,timeout=600):
    proc=subprocess.run(ssh_args(ident,config)+[shlex.join(args)],input=payload,text=True,capture_output=True,timeout=timeout)
    if proc.returncode:raise RuntimeError(ident+'：远程初始化失败；'+proc.stderr[-450:])
    return proc.stdout

def defaults(ident,country,label,ip,ip6,zone,key,known_hosts):
    import ipaddress
    ipaddress.IPv4Address(ip)
    if ip6:ipaddress.IPv6Address(ip6)
    host=ident+'.'+zone
    cert={'certificate_file':'/etc/argosbx-fleet/tls/domain.crt','key_file':'/etc/argosbx-fleet/tls/domain.key'}
    protocols={}
    for kind,port in [('reality',443),('hy2',2446),('cf',18082),('anytls',2447),('shadowtls',2448),('salamander',8443)]:
        p={'enabled':True,'port':port,'listen':'127.0.0.1' if kind=='cf' else '::','client':{}}
        if kind=='reality':p.update(sni='www.microsoft.com',cover_host='www.microsoft.com',cover_port=443);p['client']['client-fingerprint']='chrome'
        elif kind=='shadowtls':p.update(cover_host='www.microsoft.com',cover_port=443);p['client'].update({'udp-over-tcp':True,'udp-over-tcp-version':2})
        elif kind=='cf':p.update(sni='edge-'+host,ws_path='/'+secrets.token_urlsafe(24))
        else:p.update(sni=host,certificate='domain',alpn=['h3'] if kind in ('hy2','salamander') else ['h2','http/1.1'])
        if kind=='anytls':p.update(padding_scheme=[]);p['client'].update({'idle-session-check-interval':30,'idle-session-timeout':30})
        protocols[kind]=p
    return {'id':ident,'name':country,'country':country,'country_name':label,'ipv4':ip,'ipv6':ip6,'domains':{'ipv4':ident+'4.'+zone,'ipv6':ident+'6.'+zone if ip6 else None,'cf':'edge-'+host},'ssh':{'host':ip,'port':22,'user':'root','known_hosts':str(Path(known_hosts).expanduser().resolve()),'identity_file':str(Path(key).expanduser().resolve())},'subscription':{'name':'argosbx-'+ident,'url':'https://'+host+':8443/source/'+secrets.token_urlsafe(32)},'salamander_ipv6':False,'certificates':{'domain':cert},'protocols':protocols,'onboarding':{'zone':zone,'certificate_host':host}}

def upload_tools(config,ident):
    import release
    with tempfile.TemporaryDirectory(prefix='fleet-package-') as d:
        archive=Path(release.package(d));body=base64.b64encode(archive.read_bytes()).decode();sha=hashlib.sha256(archive.read_bytes()).hexdigest()
        script='''import sys,json,base64,tempfile,tarfile,hashlib,subprocess,pathlib
p=json.load(sys.stdin)
with tempfile.TemporaryDirectory(prefix='fleet-bootstrap-') as d:
 a=pathlib.Path(d)/'release.tgz';a.write_bytes(base64.b64decode(p['body']))
 assert hashlib.sha256(a.read_bytes()).hexdigest()==p['sha']
 with tarfile.open(a) as t:source=t.extractfile('install.py').read()
 f=pathlib.Path(d)/'install.py';f.write_bytes(source)
 subprocess.run(['python3',str(f),str(a),'--sha256',p['sha']],check=True)
'''
        # apt is needed before importing the agent's existing PyYAML dependency.
        command(config,ident,['sh','-c','command -v python3 >/dev/null && python3 -c "import yaml" 2>/dev/null || (apt-get -o DPkg::Lock::Timeout=180 update && apt-get -o DPkg::Lock::Timeout=180 install -y python3 python3-yaml)'])
        command(config,ident,['python3','-c',script],json.dumps({'body':body,'sha':sha}))

def install(config,ident):
    server=servers(config)[ident]
    if 'onboarding' not in server:raise ValueError('已有服务器未标记为新机；不会覆盖原生服务')
    # Detect occupied/managed hosts before uploading code or creating CF resources.
    check='test "$(id -u)" = 0 && { test ! -e /root/agsbx || test -f /etc/argosbx-fleet/bootstrap.json; }'
    command(config,ident,['sh','-c',check])
    upload_tools(config,ident)
    prefix=['python3','-B','/opt/argosbx-fleet/current/bootstrap.py']
    check=json.loads(command(config,ident,prefix+['preflight'],json.dumps({'server':server})))
    cf=Cloudflare(config['cloudflare']['token_file'])
    journal=STATE/(ident+'-onboarding.json')
    connection=tunnels.provision(cf,server,server['onboarding']['zone'],journal)
    result=json.loads(command(config,ident,prefix+['install'],json.dumps({'server':server,'connector_token':connection['connector_token']}),timeout=900))
    # Successful systemd start does not prove the connector or source is usable.
    endpoint='/accounts/'+connection['account_id']+'/cfd_tunnel/'+connection['tunnel_id']
    for _ in range(12):
        if cf.call(endpoint)['result'].get('status')=='healthy':break
        time.sleep(5)
    else:raise RuntimeError('隧道尚未 healthy；未发布节点，修复后重试同一命令')
    import yaml
    try:
        # Use the verified inventory address while retaining hostname/SNI certificate validation.
        # A local VPN DNS cache must not turn newly issued hostnames into a false failure.
        import http.client,ssl
        url=urlsplit(server['subscription']['url']);conn=http.client.HTTPSConnection(url.hostname,url.port or 443,timeout=30)
        try:
            conn.sock=ssl.create_default_context().wrap_socket(socket.create_connection((server['ipv4'] or server['ipv6'],url.port or 443),30),server_hostname=url.hostname)
            conn.request('GET',url.path);response=conn.getresponse()
            if response.status!=200:raise ValueError('source HTTP status')
            source=yaml.safe_load(response.read())
        finally:conn.close()
    except Exception:raise RuntimeError('外部 HTTPS 源订阅验收失败；检查云防火墙 TCP 8443，未发布节点') from None
    if len(source.get('proxies',[]))!=sum(p['enabled'] for p in server['protocols'].values()):raise ValueError('源节点数量不一致')
    import servers as publisher
    from lease import coordinator
    with lock(STATE/'publisher.lock'),coordinator(config):
        publisher.prepare(config);published=publisher.publish(config)
    result.update(tunnel_healthy=True,https_source_verified=True,publication=published)
    return result

def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['zones','add','install']);p.add_argument('--config',default=str(DEFAULT));p.add_argument('--server');p.add_argument('--country');p.add_argument('--country-name');p.add_argument('--ipv4');p.add_argument('--ipv6');p.add_argument('--zone');p.add_argument('--ssh-key');p.add_argument('--known-hosts');a=p.parse_args()
    config=read(a.config);os.environ['ARGOSBX_SERVERS_FILE']=str(Path(a.config).resolve())
    if a.command=='zones':
        return {'zones':[{'name':z['name'],'account':z['account']['name'],'active':z['status']=='active'} for z in Cloudflare(config['cloudflare']['token_file']).zones()]}
    if not a.server:raise ValueError('需要 --server')
    if a.command=='install':return install(config,a.server)
    if any(not getattr(a,k) for k in ('country','country_name','ipv4','zone','ssh_key','known_hosts')):raise ValueError('add 需要国家、IP、域名、SSH 密钥和可信 known_hosts')
    if a.server in servers(config):raise ValueError('服务器 ID 已存在')
    tunnels.discover(Cloudflare(config['cloudflare']['token_file']),a.zone)
    added=defaults(a.server,a.country,a.country_name,a.ipv4,a.ipv6,a.zone,a.ssh_key,a.known_hosts)
    used={s['name'] for s in config['servers']};suffix=2
    while added['name'] in used:
        added['name']=a.country+str(suffix);suffix+=1
    config['servers'].append(added);config['schema']=3
    if a.country not in config['purpose_order']:config['purpose_order'].append(a.country)
    from fleet import validate
    validate(config);save(a.config,config)
    return {'added':a.server,'installed':False,'next':'python3 onboard.py install --config '+a.config+' --server '+a.server}

if __name__=='__main__':
    try:
        with lock(STATE/'fleet.lock'):print(json.dumps(main(),ensure_ascii=False))
    except Exception as e:
        print(str(e) if isinstance(e,(ValueError,RuntimeError)) else type(e).__name__,file=sys.stderr);sys.exit(1)
