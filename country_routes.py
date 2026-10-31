"""Upgrade only the authenticated country handlers; keep public URLs and tokens."""
import hashlib,json,re,signal,os,subprocess,tempfile
from pathlib import Path
from storage import atomic,save

COMPRESSION_JOURNAL=Path('/etc/argosbx-fleet/share-compression-journal.json')

def compression_render(text):
    start_marker='# BEGIN EXTERNAL SEVEN SHARES';end_marker='# END EXTERNAL SEVEN SHARES'
    if text.count(start_marker)!=1 or text.count(end_marker)!=1:raise ValueError('外部分享区块缺失或重复，未修改压缩配置')
    start=text.index(start_marker);end=text.index(end_marker,start);block=text[start:end]
    matcher=re.findall(r'(?m)^\s*@external_seven_share path ([^\n]+)$',block)
    allowed={'/share/col/external-seven','/share/file/external-seven-shadowrocket-config','/share/file/external-seven-shadowrocket-ads'}
    if len(matcher)!=1 or set(matcher[0].split())!=allowed or block.count('handle @external_seven_share {')!=1:
        raise ValueError('无法确认外部分享压缩作用域')
    if 'reverse_proxy 127.0.0.1:3001' not in block or 'private, no-store' not in block:raise ValueError('外部分享后端或私有响应策略不匹配')
    encodings=re.findall(r'(?m)^\s*encode\s+([^\n]+)$',block)
    if encodings:
        if encodings!=['gzip']:raise ValueError('已有非默认压缩配置，保留原配置')
        return text
    block=block.replace('handle @external_seven_share {\n','handle @external_seven_share {\n encode gzip\n',1)
    return text[:start]+block+text[end:]

def compression_upgrade(path=Path('/etc/caddy-sub/argosbx.caddy'),main=Path('/etc/caddy-sub/Caddyfile'),journal=COMPRESSION_JOURNAL):
    if journal.exists():raise ValueError('分享压缩有未完成事务，先恢复或验收')
    before=path.read_text();after=compression_render(before)
    if before==after:return {'changed':False,'existing_services_restarted':False}
    original_main=main.read_text();marker='import '+str(path)
    if original_main.count(marker)!=1:raise ValueError('Caddy 分享配置导入不唯一')
    with tempfile.TemporaryDirectory(prefix='argosbx-share-compression-') as directory:
        candidate=Path(directory)/'shares.caddy';candidate.write_text(after);candidate.chmod(0o600)
        validation=Path(directory)/'Caddyfile';validation.write_text(original_main.replace(marker,'import '+str(candidate)));validation.chmod(0o600)
        subprocess.run(['/usr/local/bin/caddy','validate','--config',str(validation),'--adapter','caddyfile'],check=True,capture_output=True)
    pid=int(subprocess.check_output(['systemctl','show','caddy-sub','-p','MainPID','--value']))
    if pid<=1:raise ValueError('Caddy 运行进程不可确认')
    stat=path.stat();main_hash=hashlib.sha256(original_main.encode()).hexdigest()
    save(journal,{'path':str(path),'main':str(main),'main_sha256':main_hash,'before':before,'after':after,'uid':stat.st_uid,'gid':stat.st_gid,'mode':stat.st_mode&0o777,'pid':pid})
    if path.read_text()!=before or main.read_text()!=original_main:raise ValueError('压缩计划后配置变化，保留日志')
    atomic(path,after,stat.st_mode&0o777);os.chown(path,stat.st_uid,stat.st_gid);os.kill(pid,signal.SIGUSR1)
    return {'changed':True,'caddy_pid':pid,'pending_readback':True,'existing_services_restarted':False}

def compression_finish(restore=False,journal=COMPRESSION_JOURNAL):
    if not journal.exists():return {'pending':False}
    saved=json.loads(journal.read_text());path=Path(saved['path']);main=Path(saved['main'])
    current=path.read_text()
    if current not in (saved['before'],saved['after']) or hashlib.sha256(main.read_bytes()).hexdigest()!=saved['main_sha256']:
        raise ValueError('分享或主配置存在第三方修改，保留恢复日志')
    pid=int(subprocess.check_output(['systemctl','show','caddy-sub','-p','MainPID','--value']))
    if pid!=saved['pid']:raise ValueError('Caddy 进程发生变化，保留日志以待核对')
    if restore and current!=saved['before']:
        atomic(path,saved['before'],saved['mode']);os.chown(path,saved['uid'],saved['gid']);os.kill(pid,signal.SIGUSR1)
    elif not restore and current!=saved['after']:raise ValueError('压缩尚未应用，不能完成验收')
    journal.unlink();return {'restored':restore,'committed':not restore,'caddy_pid':pid}

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
    import argparse
    from storage import lock
    parser=argparse.ArgumentParser();parser.add_argument('command',choices=['upgrade','finish','recover','compress','compression-finish','compression-recover']);command=parser.parse_args().command
    with lock('/etc/argosbx-fleet/agent.lock'):
        if command=='compress':result=compression_upgrade()
        elif command.startswith('compression-'):result=compression_finish(command=='compression-recover')
        else:result=upgrade() if command=='upgrade' else finish(command=='recover')
        print(json.dumps(result))
