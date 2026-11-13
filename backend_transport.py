"""Optional authenticated SSH forwarding for private Sub-Store management.

Public subscription checks continue to use the published HTTPS URLs.
"""
import contextlib
import contextvars
import http.client
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import time
import urllib.error
from urllib.parse import urlsplit

from lease import ensure_owned,ssh_candidates

_active=contextvars.ContextVar('argosbx_backend_relay',default=None)
MAX_BODY=8*1024*1024

class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self,path,timeout=20):
        super().__init__('localhost',timeout=timeout)
        self.socket_path=str(path)
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)

def identity(config):
    subscription=config['subscription']
    relay=subscription.get('backend_relay') or {}
    return (config['coordinator'],subscription['backend_url'],relay.get('port'),relay.get('jump_server'))

def active(config):
    value=_active.get()
    if value is None:return False
    if value['identity']!=identity(config):raise ValueError('订阅管理中继与当前资料不匹配')
    if value['process'].poll() is not None:raise RuntimeError('订阅管理 SSH 中继已断开')
    return True

@contextlib.contextmanager
def connection(config):
    settings=config.get('subscription',{}).get('backend_relay')
    if settings is None:
        yield
        return
    if _active.get() is not None:raise ValueError('订阅管理中继不能嵌套')
    if (not isinstance(settings,dict) or not {'port'}<=set(settings) or set(settings)-{'port','jump_server'}
            or type(settings['port']) is not int or not 1<=settings['port']<=65535):
        raise ValueError('订阅管理中继端口无效')
    parsed=urlsplit(config['subscription']['backend_url'])
    if parsed.scheme!='https' or not parsed.hostname or parsed.query or parsed.fragment:
        raise ValueError('订阅管理地址不适合 SSH 中继')
    ensure_owned()
    with tempfile.TemporaryDirectory(prefix='argosbx-relay-',dir='/tmp') as directory:
        path=Path(directory)/'backend.sock'
        process=None
        current=None
        token=None
        try:
            for candidate in ssh_candidates(config,config['coordinator']):
                args=candidate.copy();args[2]='none' # A stale multiplexed master cannot redirect a new forward.
                args=args[:-1]+['-N','-T','-C','-o','ExitOnForwardFailure=yes','-o','StreamLocalBindMask=0177',
                                '-L',str(path)+':127.0.0.1:'+str(settings['port']),args[-1]]
                current=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                until=time.monotonic()+18
                while current.poll() is None and time.monotonic()<until:
                    try:
                        if stat.S_ISSOCK(path.stat().st_mode):process=current;break
                    except FileNotFoundError:pass
                    time.sleep(.1)
                if process is not None:break
                if current.poll() is None:current.terminate()
                try:current.wait(timeout=5)
                except subprocess.TimeoutExpired:current.kill();current.wait(timeout=5)
                path.unlink(missing_ok=True)
            if process is None:raise RuntimeError('无法建立订阅管理 SSH 中继')
            ensure_owned()
            token=_active.set({'identity':identity(config),'process':process,'socket':path,'prefix':parsed.path.rstrip('/')})
            yield
            ensure_owned()
            if process.poll() is not None:raise RuntimeError('订阅管理 SSH 中继已断开')
        finally:
            if token is not None:_active.reset(token)
            if current is not None and current is not process and current.poll() is None:
                current.terminate()
                try:current.wait(timeout=5)
                except subprocess.TimeoutExpired:current.kill();current.wait(timeout=5)
            if process is not None:
                if process.poll() is None:process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)

def request(config,path,value=None,method=None,raw=False,user_agent='FlClash/0.8.99'):
    if not active(config):raise ValueError('订阅管理 SSH 中继未启用')
    if not isinstance(path,str) or not path.startswith('/') or any(c in path for c in '\r\n'):
        raise ValueError('订阅管理路径无效')
    ensure_owned();relay=_active.get()
    body=None if value is None else json.dumps(value).encode()
    verb=method or ('POST' if body is not None else 'GET')
    for attempt in range(2 if verb=='GET' and body is None else 1):
        connection=UnixHTTPConnection(relay['socket'])
        try:
            connection.request(verb,relay['prefix']+path,body,
                               {'Content-Type':'application/json','User-Agent':user_agent})
            response=connection.getresponse();content=response.read(MAX_BODY+1)
            if len(content)>MAX_BODY:raise ValueError('订阅管理响应过大')
            if response.status>=400:raise urllib.error.HTTPError('backend-relay',response.status,'backend error',None,None)
            break
        except urllib.error.HTTPError:raise
        except (OSError,http.client.HTTPException):
            ensure_owned()
            if not active(config) or attempt or verb!='GET' or body is not None:raise
            time.sleep(.25)
        finally:connection.close()
    ensure_owned()
    if relay['process'].poll() is not None:raise RuntimeError('订阅管理 SSH 中继已断开')
    text=content.decode()
    if raw:return text
    result=json.loads(text)
    if result.get('status')!='success':raise ValueError('Sub-Store 操作未成功')
    return result.get('data')
