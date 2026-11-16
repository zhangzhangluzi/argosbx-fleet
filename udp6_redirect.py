#!/usr/bin/env python3
"""Transactional IPv6 UDP ingress redirect to an existing HY2 listener."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from storage import lock,save

ROOT=Path(__file__).resolve().parent
HOME=Path('/etc/argosbx-fleet')
CONFIG=HOME/'udp6-hy2-redirect.json'
RULE=HOME/'udp6-hy2-redirect.nft'
UNIT=Path('/etc/systemd/system/argosbx-udp6-hy2-redirect.service')
UNIT_SOURCE=ROOT/'systemd/argosbx-udp6-hy2-redirect.service'
JOURNAL=HOME/'udp6-hy2-redirect-journal.json'
LOCK=Path('/run/argosbx-udp6-hy2-redirect.lock')
SERVICE='argosbx-udp6-hy2-redirect.service'
TIMER='argosbx-udp6-hy2-redirect-rollback.timer'
TABLE='argosbx_hy2_redirect'

def run(args,body=None,check=True):
    p=subprocess.run(args,input=body,text=True,capture_output=True,timeout=30)
    if check and p.returncode:raise RuntimeError('命令执行失败：'+args[0]+' '+args[1])
    return p
def digest(data):return hashlib.sha256(data).hexdigest()
def validate(config):
    if not isinstance(config,dict) or set(config)!={'address','port','target_port'}:raise ValueError('IPv6 入口配置无效')
    ip=ipaddress.IPv6Address(config['address'])
    if not ip.is_global or str(ip)!=config['address']:raise ValueError('IPv6 地址必须是规范化公网地址')
    if any(type(config[k]) is not int or not 1<=config[k]<=65535 for k in ('port','target_port')) or config['port']==config['target_port']:
        raise ValueError('UDP 端口无效')
    return config
def render(config):
    validate(config)
    return ('table ip6 '+TABLE+' {\n chain preroute {\n  type nat hook prerouting priority dstnat; policy accept;\n'
            '  ip6 daddr '+config['address']+' udp dport '+str(config['port'])+' counter redirect to :'+str(config['target_port'])+'\n }\n}\n').encode()
def table():
    p=run(['nft','-j','list','table','ip6',TABLE],check=False)
    return None if p.returncode else json.loads(p.stdout)
def valid_table(value,config):
    if not isinstance(value,dict):return False
    try:
        validate(config);items=value['nftables'];rules=[x['rule'] for x in items if 'rule' in x];chains=[x['chain'] for x in items if 'chain' in x]
        if len(rules)!=1 or len(chains)!=1:return False
        r=rules[0];c=chains[0];expr=r['expr']
        return (r.get('family')=='ip6' and r.get('table')==TABLE and r.get('chain')=='preroute'
                and c.get('hook')=='prerouting' and c.get('type')=='nat' and c.get('policy')=='accept' and c.get('prio')==-100
                and len(expr)==4
                and expr[0]=={'match':{'op':'==','left':{'payload':{'protocol':'ip6','field':'daddr'}},'right':config['address']}}
                and expr[1]=={'match':{'op':'==','left':{'payload':{'protocol':'udp','field':'dport'}},'right':config['port']}}
                and set(expr[2])=={'counter'} and expr[3]=={'redirect':{'port':config['target_port']}})
    except (KeyError,TypeError,ValueError):return False
def target_ready(config):
    try:
        state=json.loads((HOME/'server.json').read_text());p=state['protocols']['hy2'];binding=state['bindings']['hy2']
        if p.get('enabled') is not True or p.get('port')!=config['target_port'] or binding.get('core')!='xray':return False
        if run(['systemctl','is-active','--quiet',binding['service']],check=False).returncode:return False
        rows=run(['ss','-6','-Hlunp','sport',':'+str(config['target_port'])]).stdout.splitlines()
        return bool(rows) and any('xray' in row.lower() for row in rows)
    except (OSError,ValueError,KeyError,IndexError,TypeError):return False
def ingress_ready(config):
    try:
        addresses=json.loads(run(['ip','-j','-6','addr']).stdout)
        if not any(ipaddress.ip_address(x['local'])==ipaddress.ip_address(config['address'])
                   for row in addresses for x in row.get('addr_info',[]) if x.get('local')):return False
        rows=run(['ss','-6','-Hlun','sport',':'+str(config['port'])]).stdout.splitlines()
        if rows:return False
        status=run(['ufw','status']).stdout
        return all(re.search(r'(?m)^'+str(port)+r'/udp\s+\(v6\)\s+ALLOW\b',status) for port in (config['port'],config['target_port']))
    except (OSError,ValueError,IndexError,TypeError):return False
def protected():
    state=json.loads((HOME/'server.json').read_text());units={b['service'] for k,b in state['bindings'].items() if state['protocols'][k]['enabled']}|{'caddy-sub'}
    fields=['MainPID','NRestarts','ActiveState','ExecMainStartTimestampMonotonic'];out={}
    for unit in sorted(units):
        p=run(['systemctl','show',unit]+sum((['-p',f] for f in fields),[]));out[unit]=dict(x.split('=',1) for x in p.stdout.splitlines() if '=' in x)
    return out
def verify():
    try:
        config=validate(json.loads(CONFIG.read_text()));present=table()
        flags={'table_valid':valid_table(present,config),'rule_file_matches':RULE.is_file() and RULE.read_bytes()==render(config),
               'unit_file_matches':UNIT.is_file() and UNIT.read_bytes()==UNIT_SOURCE.read_bytes(),
               'service_active':run(['systemctl','is-active','--quiet',SERVICE],check=False).returncode==0,
               'service_enabled':run(['systemctl','is-enabled','--quiet',SERVICE],check=False).returncode==0,
               'target_ready':target_ready(config),'ingress_ready':ingress_ready(config)}
        return {**config,**flags,'verified':all(flags.values())}
    except (OSError,ValueError,KeyError,TypeError):return {'verified':False}
def create(path,data,mode=0o644):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),mode)
    with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
def owned(config):
    for path,body in ((CONFIG,(json.dumps(config,sort_keys=True)+'\n').encode()),(RULE,render(config)),(UNIT,UNIT_SOURCE.read_bytes())):
        if path.is_symlink() or (path.exists() and (not path.is_file() or path.read_bytes()!=body)):raise ValueError('转发文件被外部更改，保留现场')
def recover():
    if not JOURNAL.exists():return {'recovered':False}
    j=json.loads(JOURNAL.read_text());config=validate(j['config']);owned(config);present=table()
    if present is not None and not valid_table(present,config):raise ValueError('转发规则被外部更改，保留现场')
    if run(['systemctl','show','-p','LoadState','--value',SERVICE],check=False).stdout.strip() not in ('','not-found'):
        stopped=run(['systemctl','disable','--now',SERVICE],check=False)
        if stopped.returncode and run(['systemctl','is-active','--quiet',SERVICE],check=False).returncode==0:raise RuntimeError('无法停止转发服务')
    if table() is not None:run(['nft','delete','table','ip6',TABLE])
    for path in (UNIT,RULE,CONFIG):path.unlink(missing_ok=True)
    run(['systemctl','daemon-reload']);run(['systemctl','stop',TIMER],check=False);JOURNAL.unlink()
    return {'recovered':True}
def stage(config):
    validate(config)
    if os.geteuid()!=0 or JOURNAL.exists() or any(p.exists() or p.is_symlink() for p in (CONFIG,RULE,UNIT)) or table() is not None:raise ValueError('已有转发规则或事务')
    if not target_ready(config) or not ingress_ready(config):raise ValueError('HY2、IPv6 监听或主机防火墙未就绪')
    run(['nft','-c','-f','-'],render(config).decode());baseline=protected()
    save(JOURNAL,{'config':config,'protected':baseline,'unit_sha256':digest(UNIT_SOURCE.read_bytes())})
    try:
        run(['systemd-run','--quiet','--unit='+TIMER.removesuffix('.timer'),'--on-active=900s','--collect',
             '--property=Restart=on-failure','--property=RestartSec=10s','/usr/bin/python3','-B',str(Path(__file__).resolve()),'recover'])
        if run(['systemctl','is-active','--quiet',TIMER],check=False).returncode:raise RuntimeError('自动回滚定时器未启动')
        create(CONFIG,(json.dumps(config,sort_keys=True)+'\n').encode(),0o600);create(RULE,render(config));create(UNIT,UNIT_SOURCE.read_bytes())
        run(['systemd-analyze','verify',str(UNIT)]);run(['systemctl','daemon-reload']);run(['systemctl','enable','--now',SERVICE])
        if not verify()['verified'] or protected()!=baseline:raise RuntimeError('转发规则或原服务回读失败')
        return {'staged':True,'rollback_seconds':900,'existing_services_restarted':False}
    except BaseException:recover();raise
def commit():
    if not JOURNAL.exists():raise ValueError('不存在待验收事务')
    j=json.loads(JOURNAL.read_text());owned(j['config'])
    if digest(UNIT_SOURCE.read_bytes())!=j['unit_sha256'] or not verify()['verified'] or protected()!=j['protected']:raise ValueError('验收状态变化，保留回滚')
    if run(['systemctl','is-active','--quiet',TIMER],check=False).returncode:raise ValueError('自动回滚定时器已停止')
    run(['systemctl','stop',TIMER]);JOURNAL.unlink();return {'committed':True,'existing_services_restarted':False}
def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=('stage','verify','commit','recover'));p.add_argument('--address');p.add_argument('--port',type=int,default=443);p.add_argument('--target-port',type=int,default=2446);a=p.parse_args()
    with lock(LOCK,timeout=30 if a.action=='recover' else 0):
        result=stage({'address':str(ipaddress.IPv6Address(a.address)),'port':a.port,'target_port':a.target_port}) if a.action=='stage' else globals()[a.action]()
        print(json.dumps(result,ensure_ascii=False))
if __name__=='__main__':
    try:main()
    except Exception as error:print('操作停止：'+(str(error) if isinstance(error,(ValueError,RuntimeError)) else type(error).__name__),file=sys.stderr);raise SystemExit(1)
