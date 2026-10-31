"""Short-lived sing-box clients. No TUN, system DNS or production listener changes."""
import concurrent.futures,contextlib,http.client,ipaddress,json,os,secrets,socket,ssl,struct,subprocess,tempfile,time,threading
from pathlib import Path

def outbound(n):
    out={'type':n['type'],'tag':'proxy','server':n['server'],'server_port':n['port']}
    tls={'enabled':True,'server_name':n.get('sni',n.get('servername'))}
    if n.get('_certificate_path'):tls['certificate_path']=n['_certificate_path']
    extras=[]
    if n['type']=='vless':
        out.update(uuid=n['uuid'],flow=n['flow'],packet_encoding='xudp',tls={**tls,'utls':{'enabled':True,'fingerprint':'chrome'},'reality':{'enabled':True,'public_key':n['reality-opts']['public-key'],'short_id':str(n['reality-opts']['short-id'])}})
    elif n['type']=='vmess':
        out.update(uuid=n['uuid'],security=n.get('cipher','auto'),packet_encoding='xudp',transport={'type':'ws','path':'/'+n['ws-opts']['path'].lstrip('/'),'headers':n['ws-opts'].get('headers',{})})
        if n.get('tls'):out['tls']=tls
    elif n['type'] in ('anytls','hysteria2'):
        out.update(password=n['password'],tls=tls)
        if n['type']=='anytls':
            for key in ('idle-session-check-interval','idle-session-timeout','min-idle-session'):
                if key in n:out[key.replace('-','_')]=str(n[key])+'s' if key!='min-idle-session' else n[key]
        if n.get('alpn'):tls['alpn']=n['alpn']
        if n.get('obfs'):out['obfs']={'type':n['obfs'],'password':n['obfs-password']}
    elif n['type']=='ss':
        p=n['plugin-opts'];out.update(type='shadowsocks',method=n['cipher'],password=n['password'],detour='shadow',udp_over_tcp={'enabled':True,'version':2})
        extras=[{'type':'shadowtls','tag':'shadow','server':n['server'],'server_port':n['port'],'version':3,'password':p['password'],'tls':{'enabled':True,'server_name':p['host'],'utls':{'enabled':True,'fingerprint':'chrome'}}}]
        if n.get('_certificate_path'):extras[0]['tls']['certificate_path']=n['_certificate_path']
    else:raise ValueError('不支持的验收协议')
    ech=n.get('ech-opts',{})
    if ech.get('enable'):
        from ech import pem_config
        tls['ech']={'enabled':True}
        if ech.get('config'):tls['ech']['config']=[pem_config(ech['config'])]
        if ech.get('query-server-name'):tls['ech']['query_server_name']=ech['query-server-name']
        if n['type'] in ('vmess','anytls'):tls['utls']={'enabled':True,'fingerprint':n.get('client-fingerprint','chrome')}
    return [out]+extras

def xhttp_client(n,port):
    tls={'serverName':n['servername'],'fingerprint':n.get('client-fingerprint','chrome'),'alpn':['h2']}
    if n.get('_certificate_path'):tls['certificates']=[{'certificateFile':n['_certificate_path'],'usage':'verify'}]
    ech=n.get('ech-opts',{})
    if ech.get('enable'):tls['echConfigList']=ech.get('config') or ech.get('query-server-name','cloudflare-ech.com')+'+https://dns.alidns.com/dns-query'
    opts=n['xhttp-opts']
    from protocols import xhttp_xmux
    settings={'path':opts['path'],'host':opts.get('host'),'mode':opts['mode']}
    if opts.get('reuse-settings'):settings['extra']={'xmux':xhttp_xmux(opts['reuse-settings'])}
    stream={'network':'xhttp','security':'tls' if n.get('tls') else 'none','xhttpSettings':settings}
    if n.get('tls'):stream['tlsSettings']=tls
    return {'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'udp':True}}],
            'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':n['server'],'port':n['port'],'users':[{'id':n['uuid'],'encryption':n['encryption']}]}]},'streamSettings':stream}]}

def certificate_client(n,port):
    """Pin the whole leaf on an isolated HY2 client, including same-key renewals."""
    fingerprint=n['_certificate_sha256']
    if len(fingerprint)!=64 or any(c not in '0123456789abcdef' for c in fingerprint):
        raise ValueError('证书 SHA256 无效')
    tls={'serverName':n.get('sni',n.get('servername')),'pinnedPeerCertSha256':fingerprint,'alpn':n.get('alpn',['h3'])}
    if n.get('ech-opts',{}).get('enable'):
        tls['echConfigList']=n['ech-opts']['config']
    stream={'network':'hysteria','security':'tls','tlsSettings':tls,
            'hysteriaSettings':{'version':2,'auth':n['password']}}
    if n.get('obfs'):
        if n['obfs']!='salamander':raise ValueError('不支持的证书验收混淆')
        stream['finalmask']={'udp':[{'type':'salamander','settings':{'password':n['obfs-password']}}]}
    return {'log':{'loglevel':'error'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'udp':True}}],
            'outbounds':[{'protocol':'hysteria','settings':{'version':2,'address':n['server'],'port':n['port']},'streamSettings':stream}]}

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

_PORT_LOCK = threading.Lock()
_PORTS = set()

@contextlib.contextmanager
def reserved_port():
    """Reserve both protocols until launch; exclude concurrent probes until cleanup."""
    for _ in range(64):
        tcp=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        try:
            tcp.bind(('127.0.0.1',0));port=tcp.getsockname()[1]
            udp.bind(('127.0.0.1',port))
            with _PORT_LOCK:
                if port in _PORTS:raise OSError('probe port already reserved')
                _PORTS.add(port)
            break
        except OSError:
            tcp.close();udp.close()
    else:raise OSError('no free TCP/UDP probe port')
    def release():
        tcp.close();udp.close()
    try:yield port,release
    finally:
        release()
        with _PORT_LOCK:_PORTS.discard(port)

@contextlib.contextmanager
def client_session(case,binary='/root/agsbx/sing-box'):
    """One isolated core for all attempts and optional idle/stream acceptance."""
    with tempfile.TemporaryDirectory(prefix='fleet-probe-') as temp,reserved_port() as (port,release):
        root=Path(temp)
        is_xhttp=case['node'].get('network')=='xhttp'
        cert_probe=case['node'].get('_certificate_sha256') and case['node']['type']=='hysteria2'
        config=certificate_client(case['node'],port) if cert_probe else xhttp_client(case['node'],port) if is_xhttp else {'log':{'level':'error'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':port}], 'outbounds':outbound(case['node'])}
        # Hostname-based CF ingress must resolve without any local VPN or TUN dependency.
        if is_xhttp or cert_probe:binary=str(Path(binary).with_name('xray'))
        else:
            config['dns']={'servers':[{'type':'https','tag':'local','server':'223.5.5.5','path':'/dns-query'},
                {'type':'https','tag':'ech','server':'dns.alidns.com','path':'/dns-query','domain_resolver':'local'}],
                'rules':[{'domain':['cloudflare-ech.com'],'server':'ech'}],'final':'local'}
            config['route']={'default_domain_resolver':'local'}
        path=root/'client.json';path.write_text(json.dumps(config));path.chmod(0o600)
        with (root/'log').open('w') as log:
            # Native cores cannot inherit these listeners. Keep the reservation
            # registry until exit and release sockets immediately before launch.
            release()
            proc=subprocess.Popen([binary,'run','-c',str(path)],stdout=log,stderr=log)
            try:
                for _ in range(100):
                    if proc.poll() is not None:raise OSError('isolated client exited')
                    try:
                        with socket.create_connection(('127.0.0.1',port),.1):break
                    except OSError:time.sleep(.05)
                else:raise OSError('isolated client unavailable')
                yield port
            finally:
                if proc.poll() is None:proc.terminate()
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)

def error_info(error):
    # Exception text can contain URLs, credentials or native configuration.
    info={'type':type(error).__name__}
    if isinstance(getattr(error,'errno',None),int):info['errno']=error.errno
    return info

def elapsed(start):return round((time.monotonic()-start)*1000,2)

def run_attempts(port,case,https_check=https,udp_check=udp_dns):
    result={'name':case['name'],'attempts':[]}
    start=time.monotonic()
    for number in range(1,3):
        attempt={'number':number,'https_ok':False,'exit_ok':False,'udp_ok':False,'errors':{}}
        tick=time.monotonic()
        try:
            address=https_check(port)
            attempt.update(https_ok=True,exit_ok=address in case['expected_ips'])
            if not attempt['exit_ok']:attempt['errors']['exit']={'type':'UnexpectedExit'}
        except Exception as error:attempt['errors']['https']=error_info(error)
        attempt['https_ms']=elapsed(tick)
        # Check UDP independently, so HTTPS failure cannot hide its actual state.
        tick=time.monotonic()
        try:
            attempt['udp_ok']=udp_check(port) is True
            if not attempt['udp_ok']:attempt['errors']['udp']={'type':'NegativeResult'}
        except Exception as error:attempt['errors']['udp']=error_info(error)
        attempt['udp_ms']=elapsed(tick)
        attempt['passed']=all(attempt[k] for k in ('https_ok','exit_ok','udp_ok'))
        result['attempts'].append(attempt)
        if attempt['passed']:break
    # Never combine a success from one attempt with another attempt's failure.
    result.update({k:attempt[k] for k in ('https_ok','exit_ok','udp_ok')})
    result.update(passed=attempt['passed'],first_attempt_ok=result['attempts'][0]['passed'],
                  retry_recovered=attempt['passed'] and number>1,attempt_count=number,duration_ms=elapsed(start))
    result['status']='passed' if result['first_attempt_ok'] else 'passed_after_retry' if result['passed'] else 'failed'
    return result

def check_case(case,binary='/root/agsbx/sing-box',https_check=https,udp_check=udp_dns):
    start=time.monotonic()
    try:
        with client_session(case,binary) as port:
            result=run_attempts(port,case,https_check,udp_check)
        result['total_ms']=elapsed(start)
        return result
    except Exception as error:
        return {'name':case['name'],'passed':False,'https_ok':False,'exit_ok':False,'udp_ok':False,
                'first_attempt_ok':False,'retry_recovered':False,'attempt_count':0,'attempts':[],
                'status':'setup_failed','setup_error':error_info(error),'total_ms':elapsed(start)}

def verify(cases):
    if not cases:raise ValueError('没有可验收节点')
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:results=list(pool.map(check_case,cases))
    first=sum(r['first_attempt_ok'] for r in results)
    return {'passed':all(r['passed'] for r in results),'first_attempt_passed':first==len(results),
            'first_attempt_successes':first,'retry_recovered':sum(r['retry_recovered'] for r in results),
            'failed':sum(not r['passed'] for r in results),'results':results}

if __name__=='__main__':
    import sys
    print(json.dumps(verify(json.load(sys.stdin)['cases'])))
