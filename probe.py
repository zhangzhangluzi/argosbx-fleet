"""Short-lived sing-box clients. No TUN, system DNS or production listener changes."""
import concurrent.futures,http.client,ipaddress,json,os,secrets,socket,ssl,struct,subprocess,tempfile,time
from pathlib import Path

def outbound(n):
    out={'type':n['type'],'tag':'proxy','server':n['server'],'server_port':n['port']}
    tls={'enabled':True,'server_name':n.get('sni',n.get('servername'))}
    if n.get('_certificate_path'):tls['certificate_path']=n['_certificate_path']
    extras=[]
    if n['type']=='vless':
        out.update(uuid=n['uuid'],flow=n['flow'],packet_encoding='xudp',tls={**tls,'utls':{'enabled':True,'fingerprint':'chrome'},'reality':{'enabled':True,'public_key':n['reality-opts']['public-key'],'short_id':str(n['reality-opts']['short-id'])}})
    elif n['type']=='vmess':
        out.update(uuid=n['uuid'],security='auto',packet_encoding='xudp',transport={'type':'ws','path':'/'+n['ws-opts']['path'].lstrip('/'),'headers':n['ws-opts'].get('headers',{})})
        if n.get('tls'):out['tls']=tls
    elif n['type'] in ('anytls','hysteria2'):
        out.update(password=n['password'],tls=tls)
        if n.get('alpn'):tls['alpn']=n['alpn']
        if n.get('obfs'):out['obfs']={'type':n['obfs'],'password':n['obfs-password']}
    elif n['type']=='ss':
        p=n['plugin-opts'];out.update(type='shadowsocks',method=n['cipher'],password=n['password'],detour='shadow',udp_over_tcp={'enabled':True,'version':2})
        extras=[{'type':'shadowtls','tag':'shadow','server':n['server'],'server_port':n['port'],'version':3,'password':p['password'],'tls':{'enabled':True,'server_name':p['host'],'utls':{'enabled':True,'fingerprint':'chrome'}}}]
        if n.get('_certificate_path'):extras[0]['tls']['certificate_path']=n['_certificate_path']
    else:raise ValueError('不支持的验收协议')
    return [out]+extras

def recv(sock,size):
    data=b''
    while len(data)<size:
        chunk=sock.recv(size-len(data))
        if not chunk:raise OSError('SOCKS connection closed')
        data+=chunk
    return data

def socks(port,host,target,udp=False):
    s=socket.create_connection(('127.0.0.1',port),12);s.settimeout(12)
    try:
        s.sendall(b'\x05\x01\x00')
        if recv(s,2)!=b'\x05\x00':raise OSError('SOCKS authentication failed')
        address=b'\x03'+bytes([len(host.encode())])+host.encode()
        s.sendall(b'\x05'+(b'\x03' if udp else b'\x01')+b'\x00'+address+struct.pack('!H',target))
        head=recv(s,4)
        if head[1]!=0:raise OSError('SOCKS connect failed')
        if head[3]==1:relay=socket.inet_ntop(socket.AF_INET,recv(s,4))
        elif head[3]==4:relay=socket.inet_ntop(socket.AF_INET6,recv(s,16))
        else:relay=recv(s,recv(s,1)[0]).decode()
        return s,(relay,struct.unpack('!H',recv(s,2))[0])
    except Exception:s.close();raise

def https(port):
    raw,_=socks(port,'www.cloudflare.com',443)
    with raw,ssl.create_default_context().wrap_socket(raw,server_hostname='www.cloudflare.com') as stream:
        stream.sendall(b'GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n')
        response=http.client.HTTPResponse(stream);response.begin()
        if response.status!=200:raise OSError('HTTPS status')
        data=dict(line.split('=',1) for line in response.read(32768).decode().splitlines() if '=' in line)
        return str(ipaddress.ip_address(data['ip']))

def udp_dns(port):
    stream,relay=socks(port,'0.0.0.0',0,True)
    with stream,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
        udp.settimeout(10);ident=secrets.randbelow(65536)
        query=struct.pack('!6H',ident,0x100,1,0,0,0)+b'\x07example\x03com\x00\x00\x01\x00\x01'
        # The native stub supports servers whose intentional DNS guard blocks public port 53.
        udp.sendto(b'\x00\x00\x00\x01'+socket.inet_aton('127.0.0.53')+struct.pack('!H',53)+query,relay)
        data,_=udp.recvfrom(4096)
        if data[:4]!=b'\x00\x00\x00\x01':raise OSError('UDP SOCKS reply')
        got,flags,_,answers,_,_=struct.unpack('!6H',data[10:22])
        if got!=ident or flags&15 or not answers:raise OSError('UDP DNS reply')
        return True

def check_case(case,binary='/root/agsbx/sing-box',https_check=https,udp_check=udp_dns):
    result={'name':case['name'],'https_ok':False,'exit_ok':False,'udp_ok':False}
    with tempfile.TemporaryDirectory(prefix='fleet-probe-') as temp:
        root=Path(temp)
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        config={'log':{'level':'error'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':port}], 'outbounds':outbound(case['node'])}
        # Hostname-based CF ingress must resolve without any local VPN or TUN dependency.
        config['dns']={'servers':[{'type':'local','tag':'local'}]}
        config['route']={'default_domain_resolver':'local'}
        path=root/'client.json';path.write_text(json.dumps(config));path.chmod(0o600)
        with (root/'log').open('w') as log:
            proc=subprocess.Popen([binary,'run','-c',str(path)],stdout=log,stderr=log)
            try:
                for _ in range(100):
                    if proc.poll() is not None:raise OSError('isolated client exited')
                    try:
                        with socket.create_connection(('127.0.0.1',port),.1):break
                    except OSError:time.sleep(.05)
                else:raise OSError('isolated client unavailable')
                for attempt in range(2):
                    try:
                        address=https_check(port)
                        result.update(https_ok=True,exit_ok=address in case['expected_ips'],udp_ok=udp_check(port))
                        if all(result[k] for k in ('https_ok','exit_ok','udp_ok')):break
                    except Exception:pass
                return result
            finally:
                if proc.poll() is None:proc.terminate()
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)

def verify(cases):
    if not cases:raise ValueError('没有可验收节点')
    def check(case):
        try:return check_case(case)
        except Exception:return {'name':case['name'],'https_ok':False,'exit_ok':False,'udp_ok':False}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:results=list(pool.map(check,cases))
    return {'passed':all(all(r[k] for k in ('https_ok','exit_ok','udp_ok')) for r in results),'results':results}

if __name__=='__main__':
    import sys
    print(json.dumps(verify(json.load(sys.stdin)['cases'])))
