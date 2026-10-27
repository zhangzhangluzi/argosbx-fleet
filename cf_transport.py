"""CF-only HTTPS over an owned, short-lived OpenSSH local forward."""
import atexit
import http.client
import ipaddress
import json
import shlex
import socket
import ssl
import subprocess
import time

HOST='api.cloudflare.com'
LIMIT=4*1024*1024


class ForwardHTTPS(http.client.HTTPSConnection):
    def __init__(self,port,timeout=30,context=None):
        super().__init__(HOST,443,timeout=timeout,context=context or ssl.create_default_context())
        self.forward_port=port
    def connect(self):
        raw=socket.create_connection(('127.0.0.1',self.forward_port),self.timeout)
        try:self.sock=self._context.wrap_socket(raw,server_hostname=HOST)
        except Exception:raw.close();raise


class SSHTransport:
    def __init__(self,config,server_id):
        from fleet import servers,ssh_args
        server=servers(config).get(server_id)
        if not server or server.get('status','active')!='active' or not server.get('ipv4'):
            raise ValueError('CF 管理出口必须是已启用且有 IPv4 的服务器')
        self.server_id=server_id;self.expected_ip=str(ipaddress.IPv4Address(server['ipv4']))
        self.args=ssh_args(server_id,config)
        # A shared master would retain forwarding after this client exits.
        self.args[self.args.index('-S')+1]='none'
        self.proc=None;self.port=None;self.observed_ip=None;self.closed=False
        atexit.register(self.close)

    def resolve(self):
        script="import json,socket;print(json.dumps(sorted({r[4][0] for r in socket.getaddrinfo('api.cloudflare.com',443,socket.AF_INET,socket.SOCK_STREAM)})))"
        command=self.args+[shlex.join(['python3','-B','-c',script])]
        try:
            result=subprocess.run(command,capture_output=True,text=True,timeout=20,check=True)
            addresses=json.loads(result.stdout)
            if not isinstance(addresses,list) or not 1<=len(addresses)<=16:raise ValueError()
            if any(not isinstance(a,str) or not ipaddress.IPv4Address(a).is_global for a in addresses):raise ValueError()
            return addresses
        except (OSError,ValueError,subprocess.SubprocessError):
            raise RuntimeError('CF 管理出口 DNS/SSH 验证失败；未回退本机出口') from None

    def _stop(self):
        proc=self.proc;self.proc=None;self.port=None;self.observed_ip=None
        if proc:
            if proc.poll() is None:proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)

    def close(self):
        self._stop();self.closed=True

    def _request(self,path,method='GET',body=None,headers=None):
        if not self.proc or self.proc.poll() is not None:raise RuntimeError('CF 管理 SSH 通道已断开；未回退本机出口')
        conn=ForwardHTTPS(self.port)
        try:
            conn.request(method,path,body=body,headers=headers or {})
            response=conn.getresponse();data=response.read(LIMIT+1)
            if len(data)>LIMIT:raise ValueError('CF API 响应超过大小限制')
            return response.status,data
        finally:conn.close()

    def ensure(self):
        if self.closed:raise RuntimeError('CF 管理通道已关闭；未回退本机出口')
        if self.observed_ip:
            if self.proc and self.proc.poll() is None:return
            raise RuntimeError('CF 管理 SSH 通道已断开；未回退本机出口')
        addresses=self.resolve()
        for address in addresses:
            try:
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as reservation:
                    reservation.bind(('127.0.0.1',0));port=reservation.getsockname()[1]
                forward='127.0.0.1:'+str(port)+':'+address+':443'
                args=self.args[:-1]+['-N','-T','-o','ControlMaster=no','-o','ControlPersist=no',
                      '-o','ExitOnForwardFailure=yes','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=2',
                      '-L',forward,self.args[-1]]
                self.port=port
                self.proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                for _ in range(200):
                    if self.proc.poll() is not None:raise OSError('SSH forward unavailable')
                    try:
                        with socket.create_connection(('127.0.0.1',port),.1):break
                    except OSError:time.sleep(.05)
                else:raise OSError('SSH forward timeout')
                # This request has no Authorization header. Check before sending a token.
                status,body=self._request('/cdn-cgi/trace')
                trace=dict(line.split('=',1) for line in body.decode().splitlines() if '=' in line)
                observed=str(ipaddress.IPv4Address(trace.get('ip','')))
                if status!=200:raise OSError('CF source trace unavailable')
                if observed!=self.expected_ip:
                    self._stop();self.closed=True
                    raise RuntimeError('CF 管理出口与登记的 IPv4 不符；未发送管理令牌')
                self.observed_ip=observed
                return
            except RuntimeError:raise
            except (OSError,ValueError,UnicodeError,http.client.HTTPException):
                self._stop()
        raise RuntimeError('CF 管理 SSH/TLS 通道无法建立；未回退本机出口')

    def request(self,path,method='GET',body=None,headers=None):
        if not path.startswith('/client/v4/'):raise ValueError('CF 管理通道仅允许 Cloudflare API 路径')
        self.ensure()
        return self._request(path,method,body,headers)

    def info(self):
        return {'mode':'ssh_forward','server':self.server_id,'expected_ipv4':self.expected_ip,
                'observed_ipv4':self.observed_ip,'verified':self.observed_ip==self.expected_ip,
                'tls_server_name':HOST,'direct_fallback':False,'token_stored_on_relay':False}
