"""Cross-workstation publisher exclusion using the coordinator's native flock."""
import contextlib,contextvars,select,subprocess
from fleet import ssh_args

_active=contextvars.ContextVar('argosbx_publisher_lease',default=None)

def ensure_owned():
    proc=_active.get()
    if proc is not None and proc.poll() is not None:
        raise RuntimeError('发布协调锁连接已中断；停止写入，保留事务日志以待恢复')

@contextlib.contextmanager
def coordinator(config):
    ident=config.get('coordinator')
    if not ident:raise ValueError('必须配置 coordinator，防止跨机器并发发布')
    args=ssh_args(ident,config)
    args=args[:-1]+['-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2',args[-1]]
    proc=subprocess.Popen(args+["flock -n /run/argosbx-publisher.lock sh -c 'printf READY; cat >/dev/null'"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    token=None
    try:
        ready,_,_=select.select([proc.stdout],[],[],15)
        if not ready or proc.stdout.read(5)!=b'READY':raise RuntimeError('发布协调锁不可用：已有发布或 SSH 不通')
        token=_active.set(proc)
        ensure_owned()
        yield
        ensure_owned()
    finally:
        if token is not None:_active.reset(token)
        try:proc.stdin.close()
        except BrokenPipeError:pass
        try:proc.wait(timeout=10)
        except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=5)
