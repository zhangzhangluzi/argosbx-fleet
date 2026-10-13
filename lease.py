"""Cross-workstation publisher exclusion using the coordinator's native flock."""
import contextlib,select,subprocess
from fleet import ssh_args

@contextlib.contextmanager
def coordinator(config):
    ident=config.get('coordinator')
    if not ident:raise ValueError('必须配置 coordinator，防止跨机器并发发布')
    proc=subprocess.Popen(ssh_args(ident,config)+["flock -n /run/argosbx-publisher.lock sh -c 'printf READY; cat >/dev/null'"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    try:
        ready,_,_=select.select([proc.stdout],[],[],15)
        if not ready or proc.stdout.read(5)!=b'READY':raise RuntimeError('发布协调锁不可用：已有发布或 SSH 不通')
        yield
    finally:
        proc.stdin.close()
        try:proc.wait(timeout=10)
        except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=5)
