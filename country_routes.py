"""Upgrade only the authenticated country handlers; keep public URLs and tokens."""
import json,re,signal,os,subprocess,tempfile
from pathlib import Path
from storage import atomic,save

def render(text):
    start=text.index('# BEGIN TI UNIFIED SUBSCRIPTION');end=text.index('# END TI UNIFIED SUBSCRIPTION',start)
    old=text[start:end]
    if '@fleet_country expression' in old:return text
    matches=re.findall(r'(?m)^\s*rewrite \* (/[A-Za-z0-9_-]+/download/collection/all)\?target=URI$',old)
    if not matches or len(set(matches))!=1:raise ValueError('无法确认原统一订阅后端路径，未修改 Caddy')
    backend=matches[0].removesuffix('/download/collection/all')
    new=re.sub(r'(?m)^\s*@ti_phone_[a-z]{2}_format query format=shadowrocket-[a-z]{2}\n','\n',old)
    new,count=re.subn(r'(?m)^  handle @ti_phone_[a-z]{2}_format \{\n(?:[^{}]*\n)*?  \}\n','',new)
    if not count:raise ValueError('原国家订阅区块无法识别')
    marker='  respond @ti_bad_format "Unsupported format" 400'
    if new.count(marker)!=1:raise ValueError('原订阅格式路由无法识别')
    handler=('  @fleet_country expression `{query.format}.matches("^shadowrocket-[a-z]{2}$")`\n'
             '  handle @fleet_country {\n'
             '   header Content-Type "text/plain; charset=utf-8"\n'
             '   rewrite * '+backend+'/download/collection/{query.format}?target=URI\n'
             '   reverse_proxy 127.0.0.1:3001\n'
             '  }\n')
    new=new.replace(marker,handler+marker)
    return text[:start]+new+text[end:]

def upgrade():
    path=Path('/etc/caddy-sub/Caddyfile');journal=Path('/etc/argosbx-fleet/country-routes-journal.json')
    if journal.exists():raise ValueError('国家路由有未完成事务，请先恢复')
    old=path.read_text();new=render(old)
    if new==old:return {'changed':False}
    with tempfile.NamedTemporaryFile(mode='w',suffix='.caddy') as f:
        f.write(new);f.flush()
        subprocess.run(['/usr/local/bin/caddy','validate','--config',f.name,'--adapter','caddyfile'],check=True,capture_output=True)
    pid=int(subprocess.check_output(['systemctl','show','caddy-sub','-p','MainPID','--value']))
    st=path.stat();save(journal,{'before':old,'after':new,'uid':st.st_uid,'gid':st.st_gid,'mode':st.st_mode&0o777})
    atomic(path,new,st.st_mode&0o777);os.chown(path,st.st_uid,st.st_gid);os.kill(pid,signal.SIGUSR1)
    return {'changed':True,'caddy_pid':pid,'pending_readback':True}

def finish(restore=False):
    path=Path('/etc/caddy-sub/Caddyfile');journal=Path('/etc/argosbx-fleet/country-routes-journal.json')
    if not journal.exists():return {'pending':False}
    j=json.loads(journal.read_text())
    if path.read_text() not in (j['before'],j['after']):raise ValueError('Caddy 存在第三方修改，保留日志')
    if restore:
        atomic(path,j['before'],j['mode']);os.chown(path,j['uid'],j['gid'])
        os.kill(int(subprocess.check_output(['systemctl','show','caddy-sub','-p','MainPID','--value'])),signal.SIGUSR1)
    journal.unlink();return {'restored':restore,'committed':not restore}

if __name__=='__main__':
    import sys
    from storage import lock
    with lock('/etc/argosbx-fleet/agent.lock'):
        command=sys.argv[1];print(json.dumps(upgrade() if command=='upgrade' else finish(command=='recover')))
