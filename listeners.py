"""Check new sockets before writing files or restarting any native service."""
import ipaddress
import socket

def endpoints(configs):
    result=[]
    for path,c in configs.items():
        for n in c.get('inbounds',[]):
            port=n.get('listen_port',n.get('port'))
            if not port:continue
            kind=n.get('type',n.get('protocol'))
            transport='udp' if kind in ('hysteria','hysteria2','tuic') else 'tcp'
            result.append((path,n.get('listen','0.0.0.0'),port,transport))
    return result

def check(before,after):
    old=endpoints(before)
    for item in endpoints(after):
        if item in old:continue
        path,host,port,transport=item
        # A restart releases this engine's previous socket, but not another service's.
        if any(p==path and h==host and n==port and t==transport for p,h,n,t in old):continue
        ip=ipaddress.ip_address(host)
        family=socket.AF_INET6 if ip.version==6 else socket.AF_INET
        with socket.socket(family,socket.SOCK_DGRAM if transport=='udp' else socket.SOCK_STREAM) as sock:
            try:sock.bind((host,port))
            except OSError:raise ValueError(f'监听地址不可绑定或端口已被占用：{host}:{port}/{transport}；未修改服务') from None
