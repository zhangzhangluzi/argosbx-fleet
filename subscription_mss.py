#!/usr/bin/env python3
"""Stage or recover a narrowly scoped, non-disruptive subscription MSS clamp."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from storage import lock,save

ROOT=Path(__file__).resolve().parent
HOME=Path('/etc/argosbx-fleet')
RULE=HOME/'argosbx-sub-mss.nft'
UNIT=Path('/etc/systemd/system/argosbx-sub-mss.service')
JOURNAL=HOME/'subscription-mss-journal.json'
LOCK=Path('/run/argosbx-sub-mss.lock')
RULE_SOURCE=ROOT/'templates/argosbx-sub-mss.nft'
UNIT_SOURCE=ROOT/'systemd/argosbx-sub-mss.service'
SERVICE='argosbx-sub-mss.service'
TIMER='argosbx-sub-mss-rollback.timer'
PROTECTED=('xr','sb','argo','argosbx-xhttp','caddy-sub','sub-store')

def run(args,body=None,check=True):
    p=subprocess.run(args,input=body,text=True,capture_output=True,timeout=30)
    if check and p.returncode:raise RuntimeError('命令执行失败：'+args[0]+' '+args[1])
    return p

def digest(data):return hashlib.sha256(data).hexdigest()

def protected():
    props=['MainPID','NRestarts','ActiveState','ExecMainStartTimestampMonotonic']
    result={}
    for unit in PROTECTED:
        p=run(['systemctl','show',unit]+sum((['-p',k] for k in props),[]))
        result[unit]=dict(x.split('=',1) for x in p.stdout.splitlines() if '=' in x)
    return result

def table():
    p=run(['nft','-j','list','table','ip','argosbx_sub_mss'],check=False)
    return None if p.returncode else json.loads(p.stdout)

def valid_table(value):
    if not isinstance(value,dict):return False
    objects=value.get('nftables',[])
    rules=[x['rule'] for x in objects if 'rule' in x]
    chains=[x['chain'] for x in objects if 'chain' in x]
    if len(rules)!=1 or len(chains)!=1:return False
    r=rules[0];c=chains[0];expr=r.get('expr',[])
    if (r.get('family')!='ip' or r.get('table')!='argosbx_sub_mss' or r.get('chain')!='preroute'
            or c.get('hook')!='prerouting' or c.get('type')!='filter' or c.get('policy')!='accept'
            or c.get('prio')!=-150 or len(expr)!=6):return False
    try:
        src,port,flags,mss=tuple(x['match'] for x in expr[:4])
        net=src['right'];net=(net['prefix']['addr']+'/'+str(net['prefix']['len'])) if isinstance(net,dict) else net
        tcpopt={'tcp option':{'name':'maxseg','field':'size'}}
        return (src=={'op':'!=','left':{'payload':{'protocol':'ip','field':'saddr'}},'right':src['right']}
                and net=='127.0.0.0/8'
                and port=={'op':'==','left':{'payload':{'protocol':'tcp','field':'dport'}},'right':8443}
                and flags=={'op':'==','left':{'&':[{'payload':{'protocol':'tcp','field':'flags'}},['syn','rst']]},'right':'syn'}
                and mss=={'op':'>','left':tcpopt,'right':1200}
                and set(expr[4])=={'counter'} and expr[5]=={'mangle':{'key':tcpopt,'value':1200}})
    except (KeyError,TypeError,ValueError):return False

def state():
    present=table()
    return {'table_present':present is not None,'table_valid':valid_table(present),
            'service_active':run(['systemctl','is-active','--quiet',SERVICE],check=False).returncode==0,
            'service_enabled':run(['systemctl','is-enabled','--quiet',SERVICE],check=False).returncode==0,
            'rule_file_matches':RULE.is_file() and RULE.read_bytes()==RULE_SOURCE.read_bytes(),
            'unit_file_matches':UNIT.is_file() and UNIT.read_bytes()==UNIT_SOURCE.read_bytes()}

def verify():
    s=state();s['verified']=all(s.values());return s

def create(path,data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o644)
    with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())

def owned_files():
    for path,source in ((RULE,RULE_SOURCE),(UNIT,UNIT_SOURCE)):
        if path.is_symlink() or (path.exists() and (not path.is_file() or path.read_bytes()!=source.read_bytes())):
            raise ValueError('已有规则文件被更改，保留现场')

def recover():
    if not JOURNAL.exists():return {'recovered':False}
    owned_files();present=table()
    if present is not None and not valid_table(present):raise ValueError('现有规则与本事务不一致，保留现场')
    loaded=run(['systemctl','show','-p','LoadState','--value',SERVICE],check=False).stdout.strip()
    if loaded not in ('','not-found'):
        stopped=run(['systemctl','disable','--now',SERVICE],check=False)
        if stopped.returncode and run(['systemctl','is-active','--quiet',SERVICE],check=False).returncode==0:
            raise RuntimeError('无法停止订阅规则服务，保留现场')
    if table() is not None:
        run(['nft','delete','table','ip','argosbx_sub_mss'])
    for path in (UNIT,RULE):
        if path.exists():path.unlink()
    run(['systemctl','daemon-reload'])
    run(['systemctl','stop',TIMER],check=False)
    JOURNAL.unlink()
    return {'recovered':True}

def stage():
    if os.geteuid()!=0:raise ValueError('需要 root 执行')
    if JOURNAL.exists():raise ValueError('已有未完成的订阅网络规则事务')
    current=verify()
    if current['verified']:return {'already_enabled':True}
    if RULE.exists() or UNIT.exists() or current['table_present'] or current['service_active'] or current['service_enabled']:
        raise ValueError('已有同名规则或服务，拒绝覆盖')
    listeners=run(['ss','-Hltnp','sport',':8443']).stdout.splitlines()
    if not listeners or not all('caddy' in x.lower() for x in listeners):raise ValueError('8443 并非仅由 Caddy 监听')
    run(['nft','-c','-f','-'],RULE_SOURCE.read_text())
    baseline=protected()
    save(JOURNAL,{'rule_sha256':digest(RULE_SOURCE.read_bytes()),'unit_sha256':digest(UNIT_SOURCE.read_bytes()),'protected':baseline})
    try:
        run(['systemd-run','--quiet','--unit=argosbx-sub-mss-rollback','--on-active=240s','--collect',
             '--property=Restart=on-failure','--property=RestartSec=10s',
             '/usr/bin/python3','-B',str(Path(__file__).resolve()),'recover'])
        if run(['systemctl','is-active','--quiet',TIMER],check=False).returncode:raise RuntimeError('自动回滚定时器未启动')
        create(RULE,RULE_SOURCE.read_bytes());create(UNIT,UNIT_SOURCE.read_bytes())
        run(['systemd-analyze','verify',str(UNIT)])
        run(['systemctl','daemon-reload']);run(['systemctl','enable','--now',SERVICE])
        if not verify()['verified'] or protected()!=baseline:raise RuntimeError('规则或原服务回读失败')
        return {'staged':True,'rollback_seconds':240,'existing_services_restarted':False}
    except BaseException:
        recover();raise

def commit():
    if not JOURNAL.exists():raise ValueError('不存在待验收事务')
    j=json.loads(JOURNAL.read_text());owned_files()
    if (j['rule_sha256']!=digest(RULE_SOURCE.read_bytes()) or j['unit_sha256']!=digest(UNIT_SOURCE.read_bytes())
            or not verify()['verified'] or protected()!=j['protected']):raise ValueError('验收状态发生变化，保留回滚')
    if run(['systemctl','is-active','--quiet',TIMER],check=False).returncode:raise ValueError('自动回滚定时器已停止')
    run(['systemctl','stop',TIMER]);JOURNAL.unlink()
    return {'committed':True,'verified':True,'existing_services_restarted':False}

def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=('stage','commit','recover','verify'));a=p.parse_args()
    with lock(LOCK,timeout=30 if a.action=='recover' else 0):print(json.dumps(globals()[a.action](),ensure_ascii=False))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print('操作停止：'+(str(error) if isinstance(error,(ValueError,RuntimeError)) else type(error).__name__),file=sys.stderr)
        raise SystemExit(1)
