"""Cross-workstation publisher exclusion using the coordinator's native flock."""
import contextlib,contextvars,re,select,shlex,subprocess
from fleet import ssh_args

_active=contextvars.ContextVar('argosbx_publisher_lease',default=None)

def marker_check(path,onboarding_id=None):
    if onboarding_id is not None and not re.fullmatch(r'[a-f0-9]{32}',onboarding_id):raise ValueError('接入事务标识无效')
    path=shlex.quote(str(path))
    absent='test ! -e '+path+' && test ! -L '+path
    if onboarding_id is None:return absent
    return '{ '+absent+'; } || { test ! -L '+path+' && test -f '+path+' && test "$(cat '+path+')" = '+onboarding_id+'; }'

def ensure_owned():
    proc=_active.get()
    if proc is not None and proc.poll() is not None:
        raise RuntimeError('发布协调锁连接已中断；停止写入，保留事务日志以待恢复')

def ssh_candidates(config,ident):
    """Prefer direct SSH; an optional jump still verifies both host identities."""
    direct=ssh_args(ident,config)
    yield direct
    jump=(config.get('subscription',{}).get('backend_relay') or {}).get('jump_server')
    if jump and ident==config.get('coordinator') and jump!=ident:
        via=ssh_args(jump,config);via[2]='none'
        target=direct.copy();target[2]='none'
        proxy=shlex.join(via[:-1]+['-W','%h:%p',via[-1]])
        yield target[:-1]+['-o','ProxyCommand='+proxy,target[-1]]

def reachable_ssh_args(config,ident):
    """Choose a reachable path before a write; never replay the write itself."""
    candidates=list(ssh_candidates(config,ident))
    if len(candidates)==1:return candidates[0]
    for candidate in candidates:
        try:
            probe=subprocess.run(candidate+['true'],capture_output=True,timeout=15)
            if probe.returncode==0:return candidate
        except (OSError,subprocess.SubprocessError):
            pass
    raise RuntimeError('协调服务器 SSH 直连与跳板均不可用')

def close_process(proc):
    try:proc.stdin.close()
    except (BrokenPipeError,AttributeError):pass
    try:proc.wait(timeout=10)
    except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=5)

@contextlib.contextmanager
def coordinator(config,onboarding_id=None):
    ident=config.get('coordinator')
    if not ident:raise ValueError('必须配置 coordinator，防止跨机器并发发布')
    check=marker_check('/etc/argosbx-fleet/onboarding-publication.id',onboarding_id)
    script='test ! -e /etc/argosbx-fleet/ad-delivery-journal.json || exit 73; '+check+' || exit 74; printf READY; cat >/dev/null'
    proc=None
    for candidate in ssh_candidates(config,ident):
        args=candidate[:-1]+['-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2',candidate[-1]]
        current=subprocess.Popen(args+['flock -n /run/argosbx-publisher.lock sh -c '+shlex.quote(script)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        try:ready,_,_=select.select([current.stdout],[],[],15)
        except BaseException:
            close_process(current)
            raise
        if ready and current.stdout.read(5)==b'READY':
            proc=current;break
        close_process(current)
    if proc is None:raise RuntimeError('发布协调锁不可用：已有发布、待恢复事务或 SSH 不通')
    token=None
    try:
        token=_active.set(proc)
        ensure_owned()
        yield
        ensure_owned()
    finally:
        if token is not None:_active.reset(token)
        close_process(proc)
