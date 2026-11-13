#!/usr/bin/env python3
"""One controller command: blank host, Cloudflare, certificates, native source, publication."""
import argparse,base64,copy,hashlib,json,os,secrets,shlex,socket,subprocess,sys,tempfile,time
from pathlib import Path
from urllib.parse import urlsplit
import urllib.request
from fleet import read,servers,ssh_args,STATE,DEFAULT
from storage import save,lock
from domains import Cloudflare
import tunnels
ROOT=Path(__file__).resolve().parent
PUBLICATION=STATE/'onboarding-publication.json'

def command(config,ident,args,payload=None,timeout=600):
    proc=subprocess.run(ssh_args(ident,config)+[shlex.join(args)],input=payload,text=True,capture_output=True,timeout=timeout)
    if proc.returncode:raise RuntimeError(ident+'：远程初始化失败；'+proc.stderr[-450:])
    return proc.stdout

def defaults(ident,country,label,ip,ip6,zone,key,known_hosts):
    import ipaddress
    ipaddress.IPv4Address(ip)
    if ip6:ipaddress.IPv6Address(ip6)
    host=ident+'.'+zone
    cert={'certificate_file':'/etc/argosbx-fleet/tls/domain.crt','key_file':'/etc/argosbx-fleet/tls/domain.key'}
    protocols={}
    for kind,port in [('reality',443),('hy2',2446),('cf',18082),('xhttp',18083),('anytls',2447),('shadowtls',2448),('salamander',8443)]:
        p={'enabled':True,'port':port,'listen':'127.0.0.1' if kind in ('cf','xhttp') else ('::' if ip6 else '0.0.0.0'),'client':{}}
        if kind=='reality':p.update(sni='www.microsoft.com',cover_host='www.microsoft.com',cover_port=443);p['client']['client-fingerprint']='chrome'
        elif kind=='shadowtls':p.update(cover_host='www.microsoft.com',cover_port=443);p['client'].update({'udp-over-tcp':True,'udp-over-tcp-version':2})
        elif kind=='cf':p.update(sni='edge-'+host,ws_path='/'+secrets.token_urlsafe(24))
        elif kind=='xhttp':p.update(sni='edge-'+host,path='/'+secrets.token_urlsafe(24),mode='packet-up')
        else:p.update(sni=host,certificate='domain',alpn=['h3'] if kind in ('hy2','salamander') else ['h2','http/1.1'])
        if kind=='anytls':p.update(padding_scheme=[]);p['client'].update({'idle-session-check-interval':30,'idle-session-timeout':30})
        protocols[kind]=p
    return {'id':ident,'status':'pending','name':country,'country':country,'country_name':label,'ipv4':ip,'ipv6':ip6,'domains':{'ipv4':ident+'4.'+zone,'ipv6':ident+'6.'+zone if ip6 else None,'cf':'edge-'+host},'ssh':{'host':ip,'port':22,'user':'root','known_hosts':str(Path(known_hosts).expanduser().resolve()),'identity_file':str(Path(key).expanduser().resolve())},'subscription':{'name':'argosbx-'+ident,'url':'https://'+host+':8443/source/'+secrets.token_urlsafe(32)},'salamander_ipv6':False,'certificates':{'domain':cert},'protocols':protocols,'onboarding':{'zone':zone,'certificate_host':host}}

def upload_tools(config,ident):
    import release
    with tempfile.TemporaryDirectory(prefix='fleet-package-') as d:
        archive=Path(release.package(d));body=base64.b64encode(archive.read_bytes()).decode();sha=hashlib.sha256(archive.read_bytes()).hexdigest()
        script='''import sys,json,base64,tempfile,tarfile,hashlib,subprocess,pathlib
p=json.load(sys.stdin)
with tempfile.TemporaryDirectory(prefix='fleet-bootstrap-') as d:
 a=pathlib.Path(d)/'release.tgz';a.write_bytes(base64.b64decode(p['body']))
 assert hashlib.sha256(a.read_bytes()).hexdigest()==p['sha']
 with tarfile.open(a) as t:source=t.extractfile('install.py').read()
 f=pathlib.Path(d)/'install.py';f.write_bytes(source)
 subprocess.run(['python3',str(f),str(a),'--sha256',p['sha']],check=True)
'''
        # apt is needed before importing the agent's existing PyYAML dependency.
        command(config,ident,['sh','-c','command -v python3 >/dev/null && python3 -c "import yaml" 2>/dev/null || (apt-get -o DPkg::Lock::Timeout=180 update && apt-get -o DPkg::Lock::Timeout=180 install -y python3 python3-yaml)'])
        command(config,ident,['python3','-c',script],json.dumps({'body':body,'sha':sha}))

def preflight_host(config,server):
    """Check the target before uploading packages or changing any files."""
    from protocols import validate_settings
    validate_settings(server['protocols'],complete=True)
    command(config,server['id'],['sh','-c','test "$(id -u)" = 0 && command -v python3 >/dev/null && command -v systemctl >/dev/null || { echo "需要 root、Python 3 和 systemd；未修改目标" >&2; exit 1; }'])
    code=(ROOT/'host_preflight.py').read_text()
    version=json.loads((ROOT/'versions.json').read_text())['version']
    wrapper="import json,sys;p=json.load(sys.stdin);n={'__name__':'host_preflight_remote'};exec(compile(p['code'],'host-preflight','exec'),n);print(json.dumps(n['check'](p['server'],p['version'])))"
    return json.loads(command(config,server['id'],['python3','-B','-c',wrapper],json.dumps({'code':code,'server':server,'version':version})))

def marker(config,transaction,remove=False):
    """Persistent coordinator fence, separate from the short-lived flock lease."""
    script='''import json,os,sys,tempfile
from pathlib import Path
p=json.load(sys.stdin);f=Path('/etc/argosbx-fleet/onboarding-publication.id')
if f.is_symlink():raise ValueError('接入标记不能是符号链接')
if p['remove']:
 if f.exists():
  if f.read_text()!=p['id']:raise ValueError('接入标记属于另一事务')
  f.unlink()
else:
 fd,tmp=tempfile.mkstemp(prefix='.onboarding-id-',dir=f.parent)
 try:
  with os.fdopen(fd,'w') as out:out.write(p['id']);out.flush();os.fsync(out.fileno())
  try:os.link(tmp,f)
  except FileExistsError:
   if f.is_symlink() or f.read_text()!=p['id']:raise ValueError('接入标记属于另一事务')
 finally:
  if os.path.exists(tmp):os.unlink(tmp)
fd=os.open(f.parent,os.O_RDONLY)
try:os.fsync(fd)
finally:os.close(fd)
print('{}')
'''
    command(config,config['coordinator'],['python3','-B','-c',script],json.dumps({'id':transaction,'remove':remove}))

def inventory_file():
    return Path(os.environ.get('ARGOSBX_SERVERS_FILE',DEFAULT)).expanduser().resolve()

def finish_publication(config,journal):
    import servers as publisher
    from lease import coordinator
    if publisher.JOURNAL.exists():raise ValueError('接入发布尚未提交，先恢复')
    if publisher.digest(config)!=journal['after_sha256']:raise ValueError('服务器资料已变化，保留接入事务')
    if journal['phase']!='done':
        rules=publisher.sync_standard_rules(config)
        countries=publisher.sync_retired_countries(config)
        if rules['status']=='failed' or countries['status'].startswith('failed'):
            raise RuntimeError('新机已发布，但独立规则或国家路由验收失败；保留事务，重试原接入命令')
        with lock(STATE/'publisher.lock'),coordinator(config,journal['id']):
            marker(config,journal['id'])
            publisher.verify_committed_plan(config)
            journal['phase']='done';save(PUBLICATION,journal)
            marker(config,journal['id'],remove=True)
            publisher.PLAN.unlink(missing_ok=True);PUBLICATION.unlink()
        return {'recovered':True,'published':True,'standard_rules':rules,'countries':countries}
    with lock(STATE/'publisher.lock'),coordinator(config,journal['id']):
        marker(config,journal['id'])
        if publisher.PLAN.exists():publisher.verify_committed_plan(config)
        marker(config,journal['id'],remove=True)
        publisher.PLAN.unlink(missing_ok=True);PUBLICATION.unlink()
    return {'recovered':True,'published':True}

def resume_publication(config,ident):
    """Resolve an interrupted transaction before any new onboarding writes."""
    import servers as publisher
    import publication
    from lease import coordinator
    journal=json.loads(PUBLICATION.read_text())
    if journal.get('server')!=ident or journal.get('config_file')!=str(inventory_file()):
        raise ValueError('另一台服务器或资料文件有未完成接入事务')
    if publisher.digest(config) not in (journal['before_sha256'],journal['after_sha256']):
        raise ValueError('服务器资料已被其他操作修改，保留接入事务')
    if journal['phase'] in ('committing','done') and not publisher.JOURNAL.exists():
        return finish_publication(config,journal)
    if journal['phase'] not in ('prepared','staging','publishing','published','committing','rollback'):
        raise ValueError('接入事务阶段无效，保留现场')
    with lock(STATE/'publisher.lock'),coordinator(config,journal['id']):
        marker(config,journal['id'])
        phase=journal['phase']
        other=(phase=='prepared' and (publisher.JOURNAL.exists() or publisher.STAGING.exists())) or (phase=='staging' and publisher.JOURNAL.exists())
        if other:
            if publisher.digest(config)!=journal['before_sha256']:raise ValueError('服务器资料已变化，保留接入事务')
            if phase=='staging':publication.recover(publisher.STAGING,config,publisher.get,publisher.request,publisher.digest,owner=journal['id'])
            marker(config,journal['id'],remove=True);PUBLICATION.unlink()
            raise ValueError('检测到其他发布事务，已退出本次接入；请先运行 servers.py recover')
        journal['phase']='rollback';save(PUBLICATION,journal)
        for path in (publisher.JOURNAL,publisher.STAGING):
            publication.recover(path,config,publisher.get,publisher.request,publisher.digest,owner=journal['id'])
        if publisher.digest(config)==journal['after_sha256']:
            save(inventory_file(),journal['before'])
        if publisher.PLAN.exists():
            plan=json.loads(publisher.PLAN.read_text())
            if plan.get('inventory_sha256')==journal['after_sha256']:publisher.PLAN.unlink()
        marker(config,journal['id'],remove=True)
        PUBLICATION.unlink()
    return {'recovered':True,'published':False}

def publish_server(config,ident):
    """Keep the subscription rollback journal until inventory is durable."""
    import servers as publisher
    from lease import coordinator
    candidate=copy.deepcopy(config);servers(candidate)[ident]['status']='active'
    path=inventory_file()
    journal={'id':secrets.token_hex(16),'server':ident,'config_file':str(path),'phase':'prepared',
             'before':copy.deepcopy(config),'before_sha256':publisher.digest(config),'after_sha256':publisher.digest(candidate)}
    if PUBLICATION.exists() or publisher.JOURNAL.exists() or publisher.STAGING.exists():raise ValueError('已有未完成发布或新机接入事务')
    save(PUBLICATION,journal)
    with lock(STATE/'publisher.lock'),coordinator(config,journal['id']):
        marker(config,journal['id'])
        if publisher.JOURNAL.exists() or publisher.STAGING.exists():raise ValueError('已有未完成发布事务，保留接入现场')
        journal['phase']='staging';save(PUBLICATION,journal)
        publisher.prepare(candidate,owner=journal['id'])
        journal['phase']='publishing';save(PUBLICATION,journal)
        published=publisher.publish(candidate,defer_commit=True,owner=journal['id'])
        journal['phase']='published';save(PUBLICATION,journal)
        if publisher.digest(read(path))!=journal['before_sha256']:raise ValueError('服务器资料被并发修改，保留事务')
        save(path,candidate)
        journal['phase']='committing';save(PUBLICATION,journal)
        publisher.commit_deferred(read(path),journal['id'])
    synced=finish_publication(read(path),journal)
    published['待接入提交']=False
    return {'publication':published,'post_publish':synced}

def install(config,ident):
    if PUBLICATION.exists():
        resumed=resume_publication(config,ident)
        if resumed['published']:return resumed
        config=read(inventory_file())
    server=servers(config)[ident]
    if 'onboarding' not in server:raise ValueError('已有服务器未标记为新机；不会覆盖原生服务')
    if server.get('status','active')!='pending':raise ValueError('服务器已启用，请使用协议管理命令')
    # All host, journal and listener checks precede package upload or CF writes.
    preflight_host(config,server)
    upload_tools(config,ident)
    prefix=['python3','-B','/opt/argosbx-fleet/current/bootstrap.py']
    check=json.loads(command(config,ident,prefix+['preflight'],json.dumps({'server':server})))
    cf=Cloudflare.from_config(config)
    journal=STATE/(ident+'-onboarding.json')
    connection=tunnels.provision(cf,server,server['onboarding']['zone'],journal)
    result=json.loads(command(config,ident,prefix+['install'],json.dumps({'server':server,'connector_token':connection['connector_token']}),timeout=900))
    # Successful systemd start does not prove the connector or source is usable.
    endpoint='/accounts/'+connection['account_id']+'/cfd_tunnel/'+connection['tunnel_id']
    for _ in range(12):
        if cf.call(endpoint)['result'].get('status')=='healthy':break
        time.sleep(5)
    else:raise RuntimeError('隧道尚未 healthy；未发布节点，修复后重试同一命令')
    import yaml
    try:
        # Use the verified inventory address while retaining hostname/SNI certificate validation.
        # A local VPN DNS cache must not turn newly issued hostnames into a false failure.
        import http.client,ssl
        url=urlsplit(server['subscription']['url']);conn=http.client.HTTPSConnection(url.hostname,url.port or 443,timeout=30)
        try:
            conn.sock=ssl.create_default_context().wrap_socket(socket.create_connection((server['ipv4'] or server['ipv6'],url.port or 443),30),server_hostname=url.hostname)
            conn.request('GET',url.path);response=conn.getresponse()
            if response.status!=200:raise ValueError('source HTTP status')
            source=yaml.safe_load(response.read())
        finally:conn.close()
    except Exception:raise RuntimeError('外部 HTTPS 源订阅验收失败；检查云防火墙 TCP 8443，未发布节点') from None
    if len(source.get('proxies',[]))!=sum(p['enabled'] for p in server['protocols'].values()):raise ValueError('源节点数量不一致')
    from acceptance import verify_new_server
    result['protocol_acceptance']=verify_new_server(config,server,source['proxies'])
    result.update(tunnel_healthy=True,https_source_verified=True,**publish_server(config,ident))
    return result

def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['zones','add','install','add-install']);p.add_argument('--config',default=str(DEFAULT));p.add_argument('--server');p.add_argument('--country');p.add_argument('--country-name');p.add_argument('--ipv4');p.add_argument('--ipv6');p.add_argument('--zone');p.add_argument('--ssh-key');p.add_argument('--known-hosts');a=p.parse_args()
    config=read(a.config);os.environ['ARGOSBX_SERVERS_FILE']=str(Path(a.config).resolve())
    if a.command=='zones':
        return {'zones':[{'name':z['name'],'account':z['account']['name'],'active':z['status']=='active'} for z in Cloudflare.from_config(config).zones()]}
    if not a.server:raise ValueError('需要 --server')
    if a.command=='install':return install(config,a.server)
    if any(not getattr(a,k) for k in ('country','country_name','ipv4','zone','ssh_key','known_hosts')):raise ValueError('add 需要国家、IP、域名、SSH 密钥和可信 known_hosts')
    if a.server in servers(config):
        if a.command!='add-install':raise ValueError('服务器 ID 已存在')
        existing=servers(config)[a.server]
        expected=(a.country,a.country_name,a.ipv4,a.ipv6,a.zone,
                  str(Path(a.ssh_key).expanduser().resolve()),str(Path(a.known_hosts).expanduser().resolve()))
        actual=(existing.get('country'),existing.get('country_name'),existing.get('ipv4'),existing.get('ipv6'),
                existing.get('onboarding',{}).get('zone'),existing['ssh'].get('identity_file'),existing['ssh'].get('known_hosts'))
        if actual!=expected:raise ValueError('已有服务器资料与本次输入不一致')
        if existing.get('status','active')=='active' and not PUBLICATION.exists():return {'server':a.server,'already_active':True}
        return {'server':a.server,'resumed':True,'result':install(config,a.server)}
    tunnels.discover(Cloudflare.from_config(config),a.zone)
    added=defaults(a.server,a.country,a.country_name,a.ipv4,a.ipv6,a.zone,a.ssh_key,a.known_hosts)
    used={s['name'] for s in config['servers']};suffix=2
    while added['name'] in used:
        added['name']=a.country+str(suffix);suffix+=1
    config['servers'].append(added);config['schema']=3
    if a.country not in config['purpose_order']:config['purpose_order'].append(a.country)
    from fleet import validate
    validate(config);save(a.config,config)
    if a.command=='add-install':
        return {'server':a.server,'resumed':False,'result':install(config,a.server)}
    return {'added':a.server,'installed':False,'next':'python3 onboard.py install --config '+a.config+' --server '+a.server}

if __name__=='__main__':
    try:
        with lock(STATE/'fleet.lock'):print(json.dumps(main(),ensure_ascii=False))
    except Exception as e:
        print(str(e) if isinstance(e,(ValueError,RuntimeError)) else type(e).__name__,file=sys.stderr);sys.exit(1)
