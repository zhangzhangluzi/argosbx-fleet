#!/usr/bin/env python3
"""Local VPS adapter. No listener restarts without --allow-restart."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import grp
import yaml
from protocols import adopt,export,render, classify
from storage import save,atomic,lock
from inbounds import reconcile,engines

HOME=Path(os.environ.get('ARGOSBX_AGENT_HOME','/etc/argosbx-fleet'))
STATE=HOME/'server.json'
JOURNAL=HOME/'apply-journal.json'
PLAN=HOME/'plan.json'
TARGET=Path(os.environ.get('ARGOSBX_EXPORT','/srv/argosbx/clmi.yaml'))
BIN={'xray':'/root/agsbx/xray','sing-box':'/root/agsbx/sing-box'}

def sha(s):return hashlib.sha256(s.encode()).hexdigest()
def load():return json.loads(STATE.read_text())
def configs(state):return {p:json.loads(Path(p).read_text()) for p in engines(state)}
def cmd(args):return subprocess.run(args,capture_output=True,text=True,check=True,timeout=45).stdout

def certificate_health(state):
    import ssl,time
    result={}
    for ref in sorted({p['certificate'] for p in state['protocols'].values() if p['enabled'] and p.get('certificate')}):
        pair=state['certificates'][ref]
        hosts=sorted({p['sni'] for p in state['protocols'].values() if p['enabled'] and p.get('certificate')==ref})
        try:
            dates=dict(line.split('=',1) for line in cmd(['openssl','x509','-in',pair['certificate_file'],'-noout','-dates']).splitlines())
            now=time.time();days=int((ssl.cert_time_to_seconds(dates['notAfter'])-now)//86400)
            started=ssl.cert_time_to_seconds(dates['notBefore'])<=now
            matches=all('does match certificate' in cmd(['openssl','x509','-in',pair['certificate_file'],'-noout','-checkhost',host]) for host in hosts)
            public=cmd(['openssl','x509','-in',pair['certificate_file'],'-pubkey','-noout']).strip()
            key=cmd(['openssl','pkey','-in',pair['key_file'],'-pubout']).strip()
            result[ref]={'usable':started and days>=1 and matches and public==key,'days_remaining':days,'renewal_due':days<14,'identities_match':matches,'key_matches':public==key,'validity_started':started}
        except (OSError,ValueError,KeyError,IndexError,subprocess.SubprocessError):
            result[ref]={'usable':False,'error':'证书或私钥不可读取、解析或校验'}
    return result

def validate_native(state,values):
    for path,c in values.items():
        core=engines(state)[path]['core']
        with tempfile.TemporaryDirectory(prefix='argosbx-check-') as d:
            f=Path(d)/'config.json';save(f,c)
            cmd([BIN[core]]+(['run','-test'] if core=='xray' else ['check'])+['-c',str(f)])

def plan(desired):
    if JOURNAL.exists():raise ValueError('有未完成事务，请先 recover；未覆盖原计划')
    state=load();before=configs(state)
    for path,wanted in state['native_sha256'].items():
        if sha(Path(path).read_text())!=wanted:raise ValueError('服务配置已被外部修改，需要重新核对并 adopt')
    updated=copy.deepcopy(state)
    if 'certificates' in desired:updated['certificates']=desired['certificates']
    candidate,updated,changes=reconcile(before,updated,desired['protocols'])
    after=render(candidate,updated,desired['protocols']);validate_native(updated,after)
    updated['protocols']=desired['protocols']
    if any(not v['usable'] for v in certificate_health(updated).values()):raise ValueError('证书过期、SNI 不匹配或私钥不匹配，未创建计划')
    files=[{'path':p,'before':Path(p).read_text(),'after':json.dumps(c,ensure_ascii=False,indent=2)+'\n'} for p,c in after.items() if c!=before[p]]
    services=sorted({v['service'] for path,v in engines(updated).items() if path in {f['path'] for f in files}})
    save(PLAN,{'state_before':state,'state_after':updated,'files':files,'services':services})
    return {'changed_files':len(files),'restart_required':services,'subscription_only':not files and updated!=state,**changes}

def restore(allow_restart=False):
    if not JOURNAL.exists():return {'recovery':'nothing'}
    j=json.loads(JOURNAL.read_text());fail=[]
    if j.get('restarts_attempted') and not allow_restart:
        raise ValueError('恢复需要重启协议服务；保护现有连接，请在维护窗口指定 --allow-restart')
    # Check every resource before restoring any, so a conflict cannot leave a
    # partially reverted configuration beside still-running newer processes.
    for item in reversed(j['files']):
        p=Path(item['path']);current=p.read_text()
        if current not in (item['before'],item['after']):fail.append(item['path'])
    if STATE.exists() and load() not in (j['state_before'],j.get('state_after',j['state_before'])):fail.append('server.json')
    source=j.get('source')
    if source and TARGET.exists() and TARGET.read_text() not in (source['before'],source['after']):fail.append('subscription source')
    if fail:raise RuntimeError('检测到第三方修改，保留恢复日志：'+','.join(fail))
    for item in reversed(j['files']):
        if Path(item['path']).read_text()==item['after']:atomic(item['path'],item['before'])
    save(STATE,j['state_before'])
    for service in j.get('restarts_attempted',[]):cmd(['systemctl','restart',service])
    if source:
        if source['before'] is None:TARGET.unlink(missing_ok=True)
        else:write_source(source['before'],source['uid'],source['gid'],source['mode'])
    else:
        # Journals from v1.0.2 did not include the source snapshot.
        export_source(_applying=True)
    PLAN.unlink(missing_ok=True);JOURNAL.unlink();return {'recovery':'restored'}

def apply(allow_restart=False):
    if JOURNAL.exists():raise ValueError('有未完成事务，请先 recover')
    p=json.loads(PLAN.read_text());state=load()
    if state!=p['state_before']:raise ValueError('计划已过期')
    if p['services'] and not allow_restart:raise ValueError('本次需重启 '+','.join(p['services'])+'；保护现有连接，未修改任何配置')
    if any(not v['usable'] for v in certificate_health(p['state_after']).values()):raise ValueError('证书在 plan 后已失效；未修改配置')
    for path,h in state['native_sha256'].items():
        if sha(Path(path).read_text())!=h:raise ValueError('原生配置在 plan 后发生变化')
    for f in p['files']:
        if Path(f['path']).read_text()!=f['before']:raise ValueError('服务配置已改变')
    updated=p['state_after']
    # Persist the complete post-apply identity before changing files. Recovery
    # must recognize a crash after saving STATE but before writing the source.
    updated['native_sha256']={path:sha(next((f['after'] for f in p['files'] if f['path']==path),Path(path).read_text())) for path in state['native_sha256']}
    source_stat=TARGET.stat() if TARGET.exists() else None
    expected=configs(state)
    for f in p['files']:expected[f['path']]=json.loads(f['after'])
    p['source']={'before':TARGET.read_text() if source_stat else None,'after':yaml.safe_dump(export(expected,updated),allow_unicode=True,sort_keys=False),
                 'uid':source_stat.st_uid if source_stat else 0,'gid':source_stat.st_gid if source_stat else 0,'mode':source_stat.st_mode&0o777 if source_stat else 0o640}
    p['restarts_attempted']=[];save(JOURNAL,p)
    try:
        for f in p['files']:atomic(f['path'],f['after'])
        for service in p['services']:
            p['restarts_attempted'].append(service);save(JOURNAL,p)
            cmd(['systemctl','restart',service]);cmd(['systemctl','is-active','--quiet',service])
        save(STATE,updated);export_source(_applying=True)
    except Exception:
        restore(allow_restart=allow_restart);raise
    JOURNAL.unlink();PLAN.unlink();return {'applied':True,'restarted':p['services']}

def export_source(_applying=False):
    if JOURNAL.exists() and not _applying:raise ValueError('未完成事务，保留上一份订阅；请先 recover')
    state=load();current=configs(state)
    for path,h in state['native_sha256'].items():
        if sha(Path(path).read_text())!=h:raise ValueError('原生配置漂移，保留上一份可用订阅')
    for s in {b['service'] for ident,b in state['bindings'].items() if state['protocols'][ident]['enabled']}:
        cmd(['systemctl','is-active','--quiet',s])
    value=export(current,state);body=yaml.safe_dump(value,allow_unicode=True,sort_keys=False)
    if TARGET.exists() and yaml.safe_load(TARGET.read_text())==value:return {'nodes':len(value['proxies']),'changed':False}
    group=cmd(['systemctl','show','caddy-sub','-p','Group','--value']).strip() or 'caddy-sub'
    write_source(body,0,grp.getgrnam(group).gr_gid,0o640)
    return {'nodes':len(value['proxies']),'changed':True}

def write_source(body,uid,gid,mode):
    # Target remains readable by Caddy across an atomic replacement.
    with tempfile.NamedTemporaryFile(dir=TARGET.parent,prefix='.source-',delete=False) as f:
        temp=Path(f.name)
        try:
            f.write(body.encode());os.fchmod(f.fileno(),mode);os.fchown(f.fileno(),uid,gid);f.flush();os.fsync(f.fileno())
            os.replace(temp,TARGET)
            d=os.open(TARGET.parent,os.O_RDONLY)
            try:os.fsync(d)
            finally:os.close(d)
        finally:temp.unlink(missing_ok=True)

def initialize(payload):
    if STATE.exists():raise ValueError('已有登记，不能覆盖')
    current={p:json.loads(Path(p).read_text()) for p in payload['services']}
    clients=yaml.safe_load(TARGET.read_text())['proxies']
    state=adopt(current,clients,payload['services']);state['native_sha256']={p:sha(Path(p).read_text()) for p in current}
    state['server_id']=payload['server_id'];validate_native(state,current)
    visible={'proxies':[n for n in clients if not (n.get('type')=='vmess' and n.get('network')=='ws' and not n.get('tls'))]}
    if export(current,state)!=visible:raise ValueError('接管前后导出不一致')
    save(STATE,state);return {'adopted':True,'protocols':list(state['protocols'])}

def certificate(host):
    import re,signal,time
    if not re.fullmatch(r'(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}',host):raise ValueError('证书域名无效')
    base=Path('/var/lib/caddy-sub/.local/share/caddy/certificates')
    def find():
        for cert in base.glob('*/'+host+'/'+host+'.crt'):
            key=cert.with_suffix('.key')
            check=cmd(['openssl','x509','-in',str(cert),'-noout','-checkhost',host])
            if key.exists() and 'does match certificate' in check:
                cmd(['openssl','x509','-in',str(cert),'-noout','-checkend','86400'])
                return {'certificate_file':str(cert),'key_file':str(key)}
        return None
    found=find()
    if found:return {'ready':True,'certificate':found,'caddy_changed':False}
    path=Path('/etc/caddy-sub/Caddyfile');old=path.read_text();stat=path.stat()
    marker='# ArgoSBX managed certificate '+host
    new=old if marker in old else old+'\n'+marker+'\nhttps://'+host+':8443 {\n respond "ArgoSBX certificate endpoint" 200\n}\n'
    with tempfile.NamedTemporaryFile(mode='w',suffix='.caddy') as f:
        f.write(new);f.flush();cmd(['/usr/local/bin/caddy','validate','--config',f.name,'--adapter','caddyfile'])
    pid=int(cmd(['systemctl','show','caddy-sub','-p','MainPID','--value']).strip())
    journal=HOME/'certificate-journal.json'
    if journal.exists():raise ValueError('有未完成证书事务，请执行 certificate-recover')
    save(journal,{'before':old,'after':new,'uid':stat.st_uid,'gid':stat.st_gid,'mode':stat.st_mode&0o777})
    try:
        atomic(path,new,stat.st_mode&0o777);os.chown(path,stat.st_uid,stat.st_gid);os.kill(pid,signal.SIGUSR1)
        for _ in range(60):
            found=find()
            if found:break
            time.sleep(2)
        if not found:raise RuntimeError('签发未就绪，保留旧配置与订阅')
        if int(cmd(['systemctl','show','caddy-sub','-p','MainPID','--value']))!=pid:raise ValueError('Caddy 进程发生变化')
    except Exception:
        certificate_recover();raise
    journal.unlink();return {'ready':True,'certificate':found,'caddy_changed':True,'pid_preserved':True}

def certificate_recover():
    import signal
    journal=HOME/'certificate-journal.json'
    if not journal.exists():return {'recovered':False}
    j=json.loads(journal.read_text());path=Path('/etc/caddy-sub/Caddyfile')
    if path.read_text()==j['after']:
        atomic(path,j['before'],j['mode']);os.chown(path,j['uid'],j['gid'])
        os.kill(int(cmd(['systemctl','show','caddy-sub','-p','MainPID','--value'])),signal.SIGUSR1)
    elif path.read_text()!=j['before']:raise ValueError('Caddy 已被其他操作修改，保留恢复日志')
    journal.unlink();return {'recovered':True}

def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['adopt','inspect','plan','apply','recover','export','certificate','certificate-recover']);p.add_argument('--allow-restart',action='store_true');a=p.parse_args()
    with lock(HOME/'agent.lock'):
        if a.command=='adopt':r=initialize(json.load(sys.stdin))
        elif a.command=='inspect':
            s=load();r={k:s[k] for k in ['server_id','protocols','certificates','native_sha256']}
            r['native_configuration_matches']=all(sha(Path(p).read_text())==h for p,h in s['native_sha256'].items())
            r['services_active']=all(subprocess.run(['systemctl','is-active','--quiet',u]).returncode==0 for u in {b['service'] for ident,b in s['bindings'].items() if s['protocols'][ident]['enabled']})
            r['unfinished_transactions']=[p.name for p in HOME.glob('*journal.json')]
            r['source_matches']=TARGET.exists() and yaml.safe_load(TARGET.read_text())==export(configs(s),s) if r['native_configuration_matches'] else False
            r['certificate_health']=certificate_health(s)
        elif a.command=='plan':r=plan(json.load(sys.stdin))
        elif a.command=='apply':r=apply(a.allow_restart)
        elif a.command=='recover':r=restore(a.allow_restart)
        elif a.command=='certificate':r=certificate(json.load(sys.stdin)['hostname'])
        elif a.command=='certificate-recover':r=certificate_recover()
        else:r=export_source()
    print(json.dumps(r,ensure_ascii=False))

if __name__=='__main__':
    try:main()
    except Exception as e:
        print(str(e) if isinstance(e,(ValueError,RuntimeError)) else type(e).__name__,file=sys.stderr);sys.exit(1)
