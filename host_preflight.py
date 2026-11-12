"""Read-only blank-host checks, executable remotely with only Python's standard library."""
import ipaddress,json,os,platform,re,shutil,socket
from pathlib import Path

JOURNAL=Path('/etc/argosbx-fleet/bootstrap.json')
NATIVE=Path('/root/agsbx')
STATE=Path('/etc/argosbx-fleet/server.json')
CADDY=Path('/etc/caddy-sub/Caddyfile')
CURRENT=Path('/opt/argosbx-fleet/current')

def ports(server):
    result={('tcp',80),('tcp',8443)}
    for ident,p in server['protocols'].items():
        kind=p.get('type',ident)
        if p['enabled'] and kind not in ('cf','xhttp'):
            result.add(('udp' if kind in ('hy2','salamander') else 'tcp',p['port']))
    return sorted(result)

def check(server,release_version=None,journal=None,native=None,state=None,caddy=None,current=None):
    journal=JOURNAL if journal is None else Path(journal)
    native=NATIVE if native is None else Path(native)
    state=STATE if state is None else Path(state)
    caddy=CADDY if caddy is None else Path(caddy)
    current=CURRENT if current is None else Path(current)
    if os.geteuid()!=0 or platform.system()!='Linux':raise ValueError('空白机初始化需要 Linux root')
    if not shutil.which('systemctl'):raise ValueError('需要 systemd')
    if journal.is_symlink():raise ValueError('初始化日志不能是符号链接')
    if journal.exists():
        value=json.loads(journal.read_text())
        if value.get('server')!=server or type(value.get('phase')) is not int or value['phase'] not in range(5):
            raise ValueError('未完成安装属于另一配置，保留现场')
        resumable=True
    else:
        if any(p.exists() or p.is_symlink() for p in (state,native,caddy)):
            raise ValueError('目标非空白服务器；不会上传或覆盖已有安装')
        resumable=False
    if release_version and (current.exists() or current.is_symlink()):
        if not current.is_symlink() or not current.resolve().is_dir():raise ValueError('已有维护版本不可确认')
        if current.resolve().parent!=current.parent.resolve():raise ValueError('已有维护目录指向外部位置，不会覆盖')
        installed=current.resolve().name
        if not re.fullmatch(r'v\d+\.\d+\.\d+',installed):raise ValueError('已有维护版本不可确认')
        if (not resumable and installed!=release_version) or tuple(map(int,installed[1:].split('.')))>tuple(map(int,release_version[1:].split('.'))):
            raise ValueError('已有维护版本不同或更新；不会覆盖或降级')
    if not resumable:
        for transport,port in ports(server):
            for family,host in [(socket.AF_INET,'0.0.0.0')]+([(socket.AF_INET6,'::')] if server.get('ipv6') else []):
                bind(host,port,transport,family,ipv6_only=family==socket.AF_INET6)
        seen=[]
        for ident,p in server['protocols'].items():
            if not p['enabled']:continue
            kind=p.get('type',ident);transport='udp' if kind in ('hy2','salamander') else 'tcp'
            host=ipaddress.ip_address(p['listen']);port=p['port']
            if transport=='tcp' and port in (80,8443):raise ValueError('协议端口与 Caddy 冲突')
            for previous,n,t in seen:
                if n==port and t==transport and previous.version==host.version and (previous==host or previous.is_unspecified or host.is_unspecified):
                    raise ValueError('协议监听端口冲突：'+str(port)+'/'+transport)
            seen.append((host,port,transport))
            bind(str(host),port,transport,socket.AF_INET6 if host.version==6 else socket.AF_INET)
    return {'blank_or_resumable':True,'resumable':resumable,'required_ingress':[str(p)+'/'+t for t,p in ports(server)]}

def bind(host,port,transport,family,ipv6_only=False):
    try:
        with socket.socket(family,socket.SOCK_DGRAM if transport=='udp' else socket.SOCK_STREAM) as sock:
            if ipv6_only:sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            sock.bind((host,port))
    except OSError:raise ValueError('初始化地址不可绑定或端口已被占用：'+host+':'+str(port)+'/'+transport) from None
