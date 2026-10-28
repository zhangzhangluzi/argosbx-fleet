"""Renewal acceptance: compare certificate files with existing live listeners."""
import concurrent.futures
import copy
import hashlib
import json
import re
import socket
import ssl
import subprocess
from pathlib import Path

from diagnostics import error_info


def leaf(path):
    text=Path(path).read_text()
    found=re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',text,re.S)
    if not found:raise ValueError('无法读取证书叶子')
    return found[0],hashlib.sha256(ssl.PEM_cert_to_DER_cert(found[0])).hexdigest()


def snapshot(state,health,storage=Path('/var/lib/caddy-sub/.local/share/caddy/certificates'),http_hosts=()):
    result={}
    for ref,value in health.items():
        pair=state['certificates'][ref];hosts=sorted({p['sni'] for p in state['protocols'].values() if p['enabled'] and p.get('certificate')==ref})
        row={**value,'hosts':hosts,'renewal_event_performed':False}
        try:
            cert=Path(pair['certificate_file']);key=Path(pair['key_file'])
            pem,fingerprint=leaf(cert)
            candidates=[]
            for host in hosts:
                for path in storage.glob('*/'+host+'/'+host+'.crt'):
                    try:candidates.append({'sha256':leaf(path)[1],'mtime':path.stat().st_mtime})
                    except (OSError,ValueError,UnicodeError):continue
            row.update(sha256=fingerprint,certificate_pem=pem,
                       certificate_symlink=cert.is_symlink(),key_symlink=key.is_symlink(),
                       key_world_readable=bool(key.stat().st_mode&0o004),
                       managed_storage_found=bool(candidates),
                       storage_matches=any(c['sha256']==fingerprint for c in candidates) if candidates else None,
                       renewal_reference='symlink' if cert.is_symlink() and key.is_symlink() else 'copy_requires_sync')
            if candidates and max(candidates,key=lambda c:c['mtime'])['sha256']!=fingerprint:
                row['renewal_warning']='newer_managed_certificate_differs'
        except (OSError,ValueError,UnicodeError) as error:
            row.update(usable=False,error=error_info(error))
        result[ref]=row
    http_certificates=[]
    for host in http_hosts:
        if not isinstance(host,str) or not re.fullmatch(r'[a-zA-Z0-9.-]+',host) or '/' in host or '..' in host:raise ValueError('无效订阅证书域名')
        paths=sorted(storage.glob('*/'+host+'/'+host+'.crt'),key=lambda p:p.stat().st_mtime,reverse=True)
        if not paths:http_certificates.append({'host':host,'status':'managed_certificate_not_found'});continue
        try:
            pem,fingerprint=leaf(paths[0]);http_certificates.append({'host':host,'status':'found','sha256':fingerprint,'certificate_pem':pem})
        except (OSError,ValueError,UnicodeError) as error:http_certificates.append({'host':host,'status':'unreadable','error':error_info(error)})
    proc=subprocess.run(['systemctl','is-active','--quiet','caddy-sub'],capture_output=True,timeout=5)
    return {'certificates':result,'caddy_active':proc.returncode==0,'read_only':True,
            'http_certificates':http_certificates,'forced_renewal':False,'services_reloaded':False}


def tcp_certificate(case):
    node=case['node']
    try:
        context=ssl.create_default_context()
        context.load_verify_locations(cadata=case['certificate_pem'])
        with socket.create_connection((node['server'],node['port']),timeout=5) as raw:
            with context.wrap_socket(raw,server_hostname=node.get('sni',node.get('servername'))) as stream:
                got=hashlib.sha256(stream.getpeercert(binary_form=True)).hexdigest()
        return {'name':case['name'],'expected_sha256':case['sha256'],'observed_sha256':got,
                'passed':got==case['sha256'],'status':'matched' if got==case['sha256'] else 'served_certificate_differs'}
    except (OSError,ValueError) as error:
        return {'name':case['name'],'passed':False,'status':'handshake_not_verified','error':error_info(error)}


def verify(cases,https_check=None):
    import probe
    def check(case):
        if case['node']['type']!='hysteria2':return tcp_certificate(case)
        node=copy.deepcopy(case['node']);node['_certificate_sha256']=case['sha256']
        attempts=[]
        for _ in range(2):
            try:
                with probe.client_session({'node':node}) as port:
                    exit_ip=(https_check or probe.https)(port)
                attempts.append({'certificate_matched':True,'exit_ok':exit_ip in case['expected_ips']})
                break
            except Exception as error:attempts.append({'certificate_matched':False,'error':error_info(error)})
        passed=attempts[-1].get('certificate_matched') is True and attempts[-1].get('exit_ok') is True
        return {'name':case['name'],'expected_sha256':case['sha256'],'passed':passed,
                'status':'matched' if passed else 'expected_certificate_not_verified',
                'first_attempt_passed':passed and len(attempts)==1,'attempts':attempts}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:return list(pool.map(check,cases))


def run(config,server,remote,observer=None,http_hosts=()):
    import acceptance,shlex
    from fleet import servers,ssh_args
    from urllib.parse import urlsplit
    source=urlsplit(server['subscription']['url']);payload={'http_hosts':list(dict.fromkeys([source.hostname,*http_hosts]))}
    bundle=remote(config,server['id'],'diagnostic-source',payload)
    checks=acceptance.cases(server,bundle['nodes'])
    metadata=bundle['certificates'];selected=[]
    for case in checks:
        ident=case['name'].split('/')[0];p=server['protocols'][ident]
        if not p.get('certificate'):continue
        value=metadata['certificates'][p['certificate']]
        selected.append({**case,'sha256':value.get('sha256'),'certificate_pem':value.get('certificate_pem')})
    if any(not metadata['certificates'][p['certificate']].get('usable') for p in server['protocols'].values() if p['enabled'] and p.get('certificate')):
        return {'server':server['id'],'passed':False,'disk':redact(metadata),'runtime':[],'reason':'disk_certificate_invalid'}
    for value in metadata['http_certificates']:
        if value.get('status')!='found':return {'server':server['id'],'passed':False,'disk':redact(metadata),'runtime':[],'reason':'subscription_certificate_not_found'}
        for family in ('ipv4','ipv6'):
            if server.get(family):selected.append({'name':('subscription' if value['host']==source.hostname else 'https/'+value['host'])+'/'+family,'node':{'type':'tls','server':server[family],'port':source.port or 443,'sni':value['host']},
                                                  'sha256':value['sha256'],'certificate_pem':value['certificate_pem']})
    if not selected:raise ValueError('没有可验收的入站或订阅证书')
    if observer:
        peer=servers(config).get(observer)
        if not peer or peer['id']==server['id'] or peer.get('status','active')!='active':raise ValueError('验收端必须是另一台已启用服务器')
        if any(c['name'].endswith('/ipv6') for c in selected) and not peer.get('ipv6'):raise ValueError('所选验收端缺少 IPv6')
        groups={observer:selected}
    else:groups=acceptance.observers(config,server,selected)
    wrapper="import sys,json;sys.path.insert(0,'/opt/argosbx-fleet/current');import certificates;print(json.dumps(certificates.verify(json.load(sys.stdin))))"
    runtime=[]
    for peer,values in groups.items():
        proc=subprocess.run(ssh_args(peer,config)+[shlex.join(['python3','-B','-c',wrapper])],input=json.dumps(values),capture_output=True,text=True,timeout=max(120,len(values)*45))
        if proc.returncode:raise RuntimeError('远端证书验收未完成；未重载或重启服务')
        rows=json.loads(proc.stdout)
        if sorted(r['name'] for r in rows)!=sorted(c['name'] for c in values):raise ValueError('证书验收结果集合不符')
        runtime.extend({**r,'observer':peer} for r in rows)
    after=remote(config,server['id'],'certificate-snapshot',payload)
    unchanged=redact(metadata)==redact(after)
    renewal_ready=after['caddy_active'] and all(c.get('usable') and c.get('storage_matches') and c.get('renewal_reference')=='symlink' and not c.get('key_world_readable') and not c.get('renewal_warning') for c in after['certificates'].values())
    return {'server':server['id'],'read_only':True,'disk':redact(after),'runtime':runtime,'renewal_reference_verified':renewal_ready,
            'certificate_files_preserved':unchanged,'forced_renewal':False,'services_reloaded':False,
            'passed':unchanged and renewal_ready and all(r['passed'] for r in runtime)}


def redact(value):
    value=copy.deepcopy(value)
    for row in value['certificates'].values():row.pop('certificate_pem',None)
    for row in value.get('http_certificates',[]):row.pop('certificate_pem',None)
    return value
