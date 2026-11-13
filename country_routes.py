"""Upgrade only the authenticated country handlers; keep public URLs and tokens."""
import hashlib,json,re,signal,os,subprocess,tempfile
from pathlib import Path
from storage import atomic,save

COMPRESSION_JOURNAL=Path('/etc/argosbx-fleet/share-compression-journal.json')
RAW_COMPRESSION_JOURNAL=Path('/etc/argosbx-fleet/raw-compression-journal.json')
RAW_COMPRESSION_TIMER='argosbx-raw-compression-rollback.timer'
AD_JOURNAL = Path('/etc/argosbx-fleet/ad-route-journal.json')
RETIRED_JOURNAL = Path('/etc/argosbx-fleet/retired-country-journal.json')
AD_ROOT = Path('/srv/argosbx/ad-rules')
AD_ROUTES = '''# BEGIN FLEET AD RULES
handle /rules/ad/ads-*.mrs {
 uri strip_prefix /rules/ad
 root * /srv/argosbx/ad-rules
 header Content-Type application/octet-stream
 header Cache-Control "public, max-age=31536000, immutable"
 file_server
}
# END FLEET AD RULES
'''

def compression_render(text):
    start_marker='# BEGIN EXTERNAL SEVEN SHARES';end_marker='# END EXTERNAL SEVEN SHARES'
    if text.count(start_marker)!=1 or text.count(end_marker)!=1:raise ValueError('外部分享区块缺失或重复，未修改压缩配置')
    start=text.index(start_marker);end=text.index(end_marker,start);block=text[start:end]
    matcher=re.findall(r'(?m)^\s*@external_seven_share path ([^\n]+)$',block)
    required={'/share/col/external-seven','/share/file/external-seven-shadowrocket-config','/share/file/external-seven-shadowrocket-ads'}
    allowed=required|{'/share/file/external-seven-de-mia-ingress'}
    paths=matcher[0].split() if len(matcher)==1 else []
    if not required<=set(paths)<=allowed or len(paths)!=len(set(paths)) or block.count('handle @external_seven_share {')!=1:
        raise ValueError('无法确认外部分享压缩作用域')
    if 'reverse_proxy 127.0.0.1:3001' not in block or 'private, no-store' not in block:raise ValueError('外部分享后端或私有响应策略不匹配')
    encodings=re.findall(r'(?m)^\s*encode\s+([^\n]+)$',block)
    if encodings:
        if encodings!=['gzip']:raise ValueError('已有非默认压缩配置，保留原配置')
        return text
    block=block.replace('handle @external_seven_share {\n','handle @external_seven_share {\n encode gzip\n',1)
    return text[:start]+block+text[end:]

def stage_import(render, path, main, journal):
    if journal.exists():raise ValueError('路由有未完成事务，先恢复或验收')
    before=path.read_text();after=render(before)
    if before==after:return {'changed':False,'existing_services_restarted':False}
    original_main=main.read_text();marker='import '+str(path)
    if original_main.count(marker)!=1:raise ValueError('Caddy 分享配置导入不唯一')
    with tempfile.TemporaryDirectory(prefix='argosbx-caddy-import-') as directory:
        candidate=Path(directory)/'shares.caddy';candidate.write_text(after);candidate.chmod(0o600)
        validation=Path(directory)/'Caddyfile';validation.write_text(original_main.replace(marker,'import '+str(candidate)));validation.chmod(0o600)
        subprocess.run(['/usr/local/bin/caddy','validate','--config',str(validation),'--adapter','caddyfile'],check=True,capture_output=True)
    pid=int(subprocess.check_output(['systemctl','show','caddy-sub','-p','MainPID','--value']))
    if pid<=1:raise ValueError('Caddy 运行进程不可确认')
    stat=path.stat();main_hash=hashlib.sha256(original_main.encode()).hexdigest()
    save(journal,{'path':str(path),'main':str(main),'main_sha256':main_hash,'before':before,'after':after,'uid':stat.st_uid,'gid':stat.st_gid,'mode':stat.st_mode&0o777,'pid':pid})
    if path.read_text()!=before or main.read_text()!=original_main:raise ValueError('路由计划后配置变化，保留日志')
    atomic(path,after,stat.st_mode&0o777);os.chown(path,stat.st_uid,stat.st_gid);os.kill(pid,signal.SIGUSR1)
    return {'changed':True,'caddy_pid':pid,'pending_readback':True,'existing_services_restarted':False}


def compression_upgrade(path=Path('/etc/caddy-sub/argosbx.caddy'),main=Path('/etc/caddy-sub/Caddyfile'),journal=COMPRESSION_JOURNAL):
    return stage_import(compression_render, path, main, journal)

def raw_compression_render(text):
    matches=re.findall(r'(?m)^[ \t]*@substore_admin path ([^\n]+)$',text)
    paths=matches[0].split() if len(matches)==1 else []
    private=[x[:-2] for x in paths if re.fullmatch(r'/[A-Za-z0-9_-]{20,}/\*',x)]
    if len(private)!=1:raise ValueError('无法唯一确认原订阅后台路径')
    pattern=re.compile(r'(?m)^([ \t]*)handle @substore_admin \{\n((?:[^\r\n{}]*\n)*)\1\}')
    blocks=list(pattern.finditer(text))
    if len(blocks)!=1:raise ValueError('无法唯一确认原订阅后台路由')
    match=blocks[0];body=match.group(2);indent=match.group(1)+' '
    definition=indent+'@substore_raw_download path '+private[0]+'/download/collection/all\n'
    encoding=indent+'encode @substore_raw_download gzip\n'
    if text.count('@substore_raw_download'):
        if text.count('@substore_raw_download')==2 and body.count(definition)==1 and body.count(encoding)==1:return text
        raise ValueError('原订阅压缩作用域存在冲突')
    if body.count('reverse_proxy 127.0.0.1:3001')!=1 or 'Cache-Control "no-store"' not in body:
        raise ValueError('原订阅后端或缓存策略不匹配')
    if re.search(r'(?m)^\s*encode\s+',body):raise ValueError('原订阅已有压缩规则，保留原配置')
    return text[:match.start(2)]+definition+encoding+text[match.start(2):]

def raw_compression_finish(restore=False,journal=RAW_COMPRESSION_JOURNAL):
    result=compression_finish(restore=restore,journal=journal)
    subprocess.run(['systemctl','stop',RAW_COMPRESSION_TIMER],capture_output=True,timeout=15)
    return result

def raw_compression_upgrade(path=Path('/etc/caddy-sub/argosbx.caddy'),main=Path('/etc/caddy-sub/Caddyfile'),journal=RAW_COMPRESSION_JOURNAL):
    if journal.exists():raise ValueError('原订阅压缩有未完成事务')
    if any(p!=journal for p in journal.parent.glob('*journal.json')):
        raise ValueError('存在其他未完成的维护事务')
    # Schedule recovery before the first write; a disconnect cannot strand a staged edit.
    subprocess.run(['systemd-run','--quiet','--unit=argosbx-raw-compression-rollback','--on-active=240s','--collect',
                    '--property=Restart=on-failure','--property=RestartSec=10s',
                    '/usr/bin/python3','-B',str(Path(__file__).resolve()),'raw-compression-recover'],
                   check=True,capture_output=True,timeout=20)
    try:
        active=subprocess.run(['systemctl','is-active','--quiet',RAW_COMPRESSION_TIMER],capture_output=True,timeout=15)
        if active.returncode:raise ValueError('自动回滚定时器未启动')
        result=stage_import(raw_compression_render,path,main,journal)
        if not result['changed']:subprocess.run(['systemctl','stop',RAW_COMPRESSION_TIMER],capture_output=True,timeout=15)
        return {**result,'rollback_seconds':240 if result['changed'] else 0}
    except BaseException:
        if not journal.exists():subprocess.run(['systemctl','stop',RAW_COMPRESSION_TIMER],capture_output=True,timeout=15)
        raise


def ad_render(text):
    if text.count(AD_ROUTES) == 1 and text.count('/rules/ad/') == 1:
        return text
    if '/rules/ad/' in text or 'FLEET AD RULES' in text or text.count('# END EXTERNAL SEVEN SHARES') != 1:
        raise ValueError('无法确认广告规则发布路由的作用域')
    return text + '\n' + AD_ROUTES


def store_ad_asset(snapshot):
    import base64
    from ad_rules import asset_name, validate
    validate(snapshot)
    name = asset_name(snapshot)
    body = base64.b64decode(snapshot['mrs'], validate=True)
    AD_ROOT.mkdir(mode=0o755, exist_ok=True)
    path = AD_ROOT / name
    if path.exists() and path.read_bytes() != body:
        raise ValueError('同一版本的广告规则文件内容发生冲突')
    if not path.exists():
        atomic(path, body, 0o644)
    return name


def stage_ads(snapshot):
    if AD_JOURNAL.exists():
        raise ValueError('广告路由有未完成事务')
    name = store_ad_asset(snapshot)
    result = stage_import(ad_render, Path('/etc/caddy-sub/argosbx.caddy'), Path('/etc/caddy-sub/Caddyfile'), AD_JOURNAL)
    return {**result, 'asset': name, 'sha256': snapshot['mrs_sha256']}


def ad_render_main(text):
    if text.count(AD_ROUTES) == 1 and text.count('/rules/ad/') == 1:
        return text
    marker = '# BEGIN TI UNIFIED SUBSCRIPTION'
    if '/rules/ad/' in text or 'FLEET AD RULES' in text or text.count(marker) != 1:
        raise ValueError('无法确认原统一订阅的广告路由作用域')
    return text.replace(marker, AD_ROUTES + marker, 1)


def stage_ads_main(snapshot, path=Path('/etc/caddy-sub/Caddyfile'), journal=AD_JOURNAL, owner=None):
    if journal.exists():
        raise ValueError('广告路由有未完成事务')
    name = store_ad_asset(snapshot)
    before = path.read_text()
    after = ad_render_main(before)
    if before == after:
        return {'changed': False, 'asset': name}
    with tempfile.NamedTemporaryFile(mode='w', suffix='.caddy') as candidate:
        candidate.write(after)
        candidate.flush()
        subprocess.run(['/usr/local/bin/caddy', 'validate', '--config', candidate.name,
                        '--adapter', 'caddyfile'], check=True, capture_output=True)
    pid = int(subprocess.check_output(['systemctl', 'show', 'caddy-sub', '-p', 'MainPID', '--value']))
    if pid <= 1:
        raise ValueError('Caddy 运行进程不可确认')
    st = path.stat()
    save(journal, {'before': before, 'after': after, 'uid': st.st_uid,
                   'gid': st.st_gid, 'mode': st.st_mode & 0o777, 'pid': pid, 'owner': owner,
                   'asset_sha256': snapshot['mrs_sha256']})
    if path.read_text() != before:
        raise ValueError('广告路由计划后配置变化，保留日志')
    atomic(path, after, st.st_mode & 0o777)
    os.chown(path, st.st_uid, st.st_gid)
    os.kill(pid, signal.SIGUSR1)
    return {'changed': True, 'asset': name, 'caddy_pid': pid, 'pending_readback': True}


def ad_finish(restore=False, journal=AD_JOURNAL):
    if not journal.exists():
        return {'pending': False}
    saved = json.loads(journal.read_text())
    if 'main_sha256' in saved:
        return compression_finish(restore=restore, journal=journal)
    return retired_finish(restore=restore, journal=journal)

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


def retired_render(text,countries):
    if not isinstance(countries,list) or any(not isinstance(c,str) or not re.fullmatch('[A-Z]{2}',c) for c in countries):
        raise ValueError('退役国家代码无效')
    start='# BEGIN RETIRED COUNTRIES';end='# END RETIRED COUNTRIES'
    if text.count(start)!=text.count(end) or text.count(start)>1:raise ValueError('退役路由标记异常')
    if start in text:
        a=text.index(start);b=text.index(end,a)+len(end)
        a=text.rfind('\n',0,a)+1
        if b<len(text) and text[b]=='\n':b+=1
        text=text[:a]+text[b:]
    begin=text.find('# BEGIN TI UNIFIED SUBSCRIPTION');finish=text.find('# END TI UNIFIED SUBSCRIPTION',begin)
    if begin<0 or finish<0:raise ValueError('未找到原统一订阅路由')
    block=text[begin:finish];marker='  @fleet_country expression'
    if block.count(marker)!=1:raise ValueError('未找到唯一国家订阅路由')
    values=sorted({c.lower() for c in countries})
    if not values:return text
    pattern='|'.join(values)
    route=('  '+start+'\n'
           '  @fleet_retired expression `{query.format}.matches("^shadowrocket-('+pattern+')$")`\n'
           '  handle @fleet_retired {\n'
           '   respond "Subscription retired" 410\n'
           '  }\n'
           '  '+end+'\n')
    block=block.replace(marker,route+marker,1)
    return text[:begin]+block+text[finish:]


def retired_stage(countries,path=Path('/etc/caddy-sub/Caddyfile'),journal=RETIRED_JOURNAL):
    if journal.exists():raise ValueError('退役国家路由有待恢复事务')
    before=path.read_text();after=retired_render(before,countries)
    if before==after:return {'changed':False}
    with tempfile.NamedTemporaryFile(mode='w',suffix='.caddy') as f:
        f.write(after);f.flush()
        subprocess.run(['/usr/local/bin/caddy','validate','--config',f.name,'--adapter','caddyfile'],check=True,capture_output=True)
    pid=int(subprocess.check_output(['systemctl','show','caddy-sub','-p','MainPID','--value']))
    if pid<=1:raise ValueError('Caddy 进程不可确认')
    st=path.stat();save(journal,{'before':before,'after':after,'uid':st.st_uid,'gid':st.st_gid,'mode':st.st_mode&0o777,'pid':pid})
    if path.read_text()!=before:raise ValueError('Caddy 配置发生并发变化，保留事务')
    atomic(path,after,st.st_mode&0o777);os.chown(path,st.st_uid,st.st_gid);os.kill(pid,signal.SIGUSR1)
    return {'changed':True,'pending_readback':True}


def retired_finish(restore=False,path=Path('/etc/caddy-sub/Caddyfile'),journal=RETIRED_JOURNAL):
    if not journal.exists():return {'pending':False}
    j=json.loads(journal.read_text());current=path.read_text()
    if current not in (j['before'],j['after']):raise ValueError('Caddy 存在第三方修改，保留事务')
    pid=int(subprocess.check_output(['systemctl','show','caddy-sub','-p','MainPID','--value']))
    if pid!=j['pid']:raise ValueError('Caddy 进程已变化，保留事务')
    if restore and current!=j['before']:
        atomic(path,j['before'],j['mode']);os.chown(path,j['uid'],j['gid']);os.kill(pid,signal.SIGUSR1)
    elif not restore and current!=j['after']:raise ValueError('退役路由尚未应用')
    journal.unlink();return {'restored':restore,'committed':not restore}

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
    import sys
    from storage import lock
    parser=argparse.ArgumentParser();parser.add_argument('command',choices=['upgrade','finish','recover','compress','compression-finish','compression-recover','raw-compress','raw-compression-finish','raw-compression-recover','ads-stage','ads-finish','ads-recover','retired-stage','retired-finish','retired-recover']);command=parser.parse_args().command
    with lock('/etc/argosbx-fleet/agent.lock',timeout=30 if command=='raw-compression-recover' else 0):
        if command=='retired-stage':result=retired_stage(json.load(sys.stdin)['countries'])
        elif command.startswith('retired-'):result=retired_finish(command=='retired-recover')
        elif command=='raw-compress':result=raw_compression_upgrade()
        elif command.startswith('raw-compression-'):result=raw_compression_finish(command=='raw-compression-recover')
        elif command=='compress':result=compression_upgrade()
        elif command.startswith('compression-'):result=compression_finish(command=='compression-recover')
        elif command=='ads-stage':result=stage_ads(json.load(sys.stdin))
        elif command.startswith('ads-'):result=ad_finish(command=='ads-recover')
        else:result=upgrade() if command=='upgrade' else finish(command=='recover')
        print(json.dumps(result))
