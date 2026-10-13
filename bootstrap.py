#!/usr/bin/env python3
"""Blank Ubuntu/Debian host installation. Existing deployments are never adopted here."""
import argparse,hashlib,ipaddress,json,os,platform,re,shutil,socket,subprocess,sys,tarfile,tempfile,time,urllib.request,zipfile
from pathlib import Path
from urllib.parse import urlsplit
from storage import save,atomic,lock
from inbounds import reconcile
from protocols import render,export,protocol_type
import agent
ROOT=Path(__file__).resolve().parent
JOURNAL=Path('/etc/argosbx-fleet/bootstrap.json')
NATIVE=Path('/root/agsbx')

def run(args,timeout=180):
    p=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
    if p.returncode:raise RuntimeError('初始化命令失败：'+' '.join(args[:4])+'；详见服务器对应服务日志')
    return p.stdout.strip()

def ports(server):
    result={('tcp',80),('tcp',8443)}
    for i,p in server['protocols'].items():
        if p['enabled'] and protocol_type(i,p)!='cf':result.add(('udp' if protocol_type(i,p) in ('hy2','salamander') else 'tcp',p['port']))
    return sorted(result)

def preflight(server):
    from protocols import validate_settings
    validate_settings(server['protocols'],complete=True)
    if os.geteuid()!=0 or platform.system()!='Linux':raise ValueError('空白机初始化需要 Linux root')
    if shutil.which('systemctl') is None:raise ValueError('需要 systemd')
    if not JOURNAL.exists():
        if agent.STATE.exists() or NATIVE.exists() or Path('/etc/caddy-sub/Caddyfile').exists():raise ValueError('目标非空白服务器；请用 protocol-plan 管理已有安装')
        for transport,port in ports(server):
            with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM if transport=='udp' else socket.SOCK_STREAM) as s:
                try:s.bind(('::',port))
                except OSError:raise ValueError('初始化端口已被占用：'+str(port)+'/'+transport) from None
    return {'blank_or_resumable':True,'required_ingress':[str(p)+'/'+t for t,p in ports(server)]}

def binaries():
    arch={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine())
    if not arch:raise ValueError('仅支持 amd64 / arm64')
    manifest=json.loads((ROOT/'binaries.json').read_text())
    NATIVE.mkdir(parents=True,exist_ok=True,mode=0o700)
    for name,builds in manifest.items():
        item=builds[arch];target=NATIVE/name if name in ('xray','sing-box') else Path('/usr/local/bin')/name
        # A completed phase never downloads twice; retries reuse an existing verified digest.
        marker=target.with_suffix('.sha256')
        if target.exists() and marker.exists() and marker.read_text()==hashlib.sha256(target.read_bytes()).hexdigest():continue
        with tempfile.TemporaryDirectory(prefix='fleet-download-') as d:
            archive=Path(d)/'archive'
            urllib.request.urlretrieve(item['url'],archive)
            if hashlib.sha256(archive.read_bytes()).hexdigest()!=item['sha256']:raise ValueError('上游二进制校验和不符：'+name)
            if item['url'].endswith('.zip'):
                with zipfile.ZipFile(archive) as z:data=z.read(name)
            elif item['url'].endswith('.tar.gz'):
                with tarfile.open(archive) as t:
                    members=[m for m in t.getmembers() if m.isfile() and Path(m.name).name==name]
                    if len(members)!=1:raise ValueError('发布包缺少唯一二进制')
                    data=t.extractfile(members[0]).read()
            else:data=archive.read_bytes()
            atomic(target,data,0o755);atomic(marker,hashlib.sha256(data).hexdigest())

def unit(name,command,user='root',extra=''):
    body='[Unit]\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nUser='+user+'\nGroup='+user+'\nExecStart='+command+'\nRestart=on-failure\nRestartSec=3\nLimitNOFILE=65536\n'+extra+'\n[Install]\nWantedBy=multi-user.target\n'
    atomic('/etc/systemd/system/'+name+'.service',body,0o644)

def install(server,connector_token,test_certificate=False):
    preflight(server)
    if JOURNAL.exists():
        j=json.loads(JOURNAL.read_text())
        if j['server']!=server:raise ValueError('未完成安装属于另一配置，保留现场')
    else:j={'server':server,'phase':0};save(JOURNAL,j)
    def checkpoint(phase):j['phase']=phase;save(JOURNAL,j)
    if j['phase']<1:
        run(['apt-get','-o','DPkg::Lock::Timeout=180','update'],240)
        run(['apt-get','-o','DPkg::Lock::Timeout=180','install','-y','ca-certificates','openssl','python3-yaml'],300)
        binaries()
        if subprocess.run(['id','caddy-sub'],capture_output=True).returncode:run(['useradd','--system','--home-dir','/var/lib/caddy-sub','--create-home','--shell','/usr/sbin/nologin','caddy-sub'])
        for path,mode in [('/etc/caddy-sub',0o755),('/srv/argosbx',0o750),('/var/lib/caddy-sub',0o750)]:
            Path(path).mkdir(parents=True,exist_ok=True);os.chmod(path,mode);run(['chown','caddy-sub:caddy-sub',path])
        checkpoint(1)
    host=server['onboarding']['certificate_host'];source=urlsplit(server['subscription']['url'])
    if source.hostname!=host or source.port!=8443 or not re.fullmatch(r'/[a-zA-Z0-9_/-]{24,}',source.path) or source.query:raise ValueError('新机源订阅必须使用证书域名、8443 和至少 24 字符私密路径')
    if j['phase']<2:
        caddy='{\n admin off\n https_port 8443\n}\nhttps://'+host+':8443 {\n @source path '+source.path+'\n handle @source {\n root * /srv/argosbx\n rewrite * /clmi.yaml\n file_server\n }\n handle { respond "ArgoSBX" 200 }\n}\n'
        atomic('/etc/caddy-sub/Caddyfile',caddy,0o644)
        unit('caddy-sub','/usr/local/bin/caddy run --config /etc/caddy-sub/Caddyfile --adapter caddyfile','caddy-sub','Environment=HOME=/var/lib/caddy-sub\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nExecReload=/bin/kill -USR1 $MAINPID')
        run(['systemctl','daemon-reload']);run(['systemctl','enable','--now','caddy-sub'])
        if shutil.which('ufw') and 'Status: active' in run(['ufw','status']):
            for t,p in ports(server):run(['ufw','allow',str(p)+'/'+t])
        checkpoint(2)
    cert=server['certificates']['domain'];certfile=Path(cert['certificate_file']);keyfile=Path(cert['key_file'])
    if j['phase']<3:
        if test_certificate:
            certfile.parent.mkdir(parents=True,exist_ok=True)
            run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-keyout',str(keyfile),'-out',str(certfile),'-subj','/CN='+host,'-addext','subjectAltName=DNS:'+host])
        else:
            # Caddy owns issuance/renewal; stable symlinks are used by the native cores.
            for _ in range(120):
                matches=list(Path('/var/lib/caddy-sub/.local/share/caddy/certificates').glob('*/'+host+'/'+host+'.crt'))
                if matches and matches[0].with_suffix('.key').exists():break
                time.sleep(2)
            else:raise RuntimeError('证书尚未签发，检查 DNS 和云防火墙 TCP 80 后重试同一命令')
            for target,src in [(certfile,matches[0]),(keyfile,matches[0].with_suffix('.key'))]:
                target.parent.mkdir(parents=True,exist_ok=True,mode=0o700);target.unlink(missing_ok=True);target.symlink_to(src)
        checkpoint(3)
    if j['phase']<4:
        if 'candidate' not in j:
            paths={str(NATIVE/'xr.json'):{'core':'xray','service':'xr.service'},str(NATIVE/'sb.json'):{'core':'sing-box','service':'sb.service'}}
            config={p:({'log':{'loglevel':'warning'},'inbounds':[],'outbounds':[{'protocol':'freedom','tag':'direct'}]} if e['core']=='xray' else {'log':{'level':'warn'},'inbounds':[],'outbounds':[{'type':'direct','tag':'direct'}]}) for p,e in paths.items()}
            state={'schema':1,'server_id':server['id'],'bindings':{},'templates':{},'protocols':{},'certificates':server['certificates'],'engines':paths}
            config,state,_=reconcile(config,state,server['protocols']);config=render(config,state,server['protocols'])
            j['candidate']={'configs':config,'state':state};save(JOURNAL,j)
        config=j['candidate']['configs'];state=j['candidate']['state'];agent.validate_native(state,config)
        for p,c in config.items():save(p,c)
        state['native_sha256']={p:agent.sha(Path(p).read_text()) for p in config};save(agent.STATE,state)
        unit('xr',str(NATIVE/'xray')+' run -c '+str(NATIVE/'xr.json'))
        unit('sb',str(NATIVE/'sing-box')+' run -c '+str(NATIVE/'sb.json'))
        atomic('/etc/argosbx-fleet/connector.token',connector_token)
        unit('argo','/usr/local/bin/cloudflared tunnel --no-autoupdate run --token-file /etc/argosbx-fleet/connector.token')
        unit('argosbx-export','/usr/bin/python3 -B /opt/argosbx-fleet/current/agent.py export')
        atomic('/etc/systemd/system/argosbx-export.timer','[Unit]\nDescription=Refresh native source\n[Timer]\nOnBootSec=90\nOnUnitActiveSec=300\n[Install]\nWantedBy=timers.target\n',0o644)
        run(['systemctl','daemon-reload'])
        for service in ('xr','sb','argo','argosbx-export.timer'):run(['systemctl','enable','--now',service])
        agent.export_source();checkpoint(4)
    for service in ('xr','sb','argo','caddy-sub'):run(['systemctl','is-active','--quiet',service])
    health=agent.certificate_health(agent.load())
    if any(not v['usable'] for v in health.values()):raise ValueError('原生证书校验失败')
    return {'installed':True,'resumable':True,'protocols':list(server['protocols']),'certificate_health':health,'source_exported':agent.export_source(),'required_ingress':[str(p)+'/'+t for t,p in ports(server)]}

if __name__=='__main__':
    try:
        p=argparse.ArgumentParser();p.add_argument('command',choices=['preflight','install']);a=p.parse_args();payload=json.load(sys.stdin)
        with lock('/etc/argosbx-fleet/bootstrap.lock'):
            result=preflight(payload['server']) if a.command=='preflight' else install(payload['server'],payload['connector_token'])
        print(json.dumps(result,ensure_ascii=False))
    except Exception as e:
        print(str(e) if isinstance(e,(ValueError,RuntimeError)) else type(e).__name__,file=sys.stderr);sys.exit(1)
