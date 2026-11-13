"""Durable, private state and a process lock; no background daemon."""
import contextlib
import fcntl
import json
import math
import os
from pathlib import Path
import tempfile
import time

def atomic(path,body,mode=0o600):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,tmp=tempfile.mkstemp(prefix='.'+path.name+'.',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            os.fchmod(f.fileno(),mode);f.write(body if isinstance(body,bytes) else body.encode());f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
        d=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(d)
        finally:os.close(d)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def save(path,value):atomic(path,json.dumps(value,ensure_ascii=False,indent=2)+'\n')

@contextlib.contextmanager
def lock(path,timeout=0):
    if isinstance(timeout,bool) or not isinstance(timeout,(int,float)) or not math.isfinite(timeout) or timeout<0:
        raise ValueError('锁等待时间无效')
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd=os.open(path,os.O_RDWR|os.O_CREAT,0o600)
    with os.fdopen(fd,'w') as f:
        deadline=time.monotonic()+timeout
        while True:
            try:
                fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
                break
            except BlockingIOError:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise RuntimeError('另一个维护事务正在运行') from None
                time.sleep(min(.25,remaining))
        yield
