"""Read-only renewal/control-plane dependency checks and opt-in owned write evidence."""
import concurrent.futures
import copy
import hashlib
import http.client
import ipaddress
import json
import re
import shlex
import subprocess
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from diagnostics import error_info


def _run(args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, timeout=15, check=True, **kwargs).stdout


def _processes(state):
    from protocols import protocol_type
    units={b['service'] for i,b in state['bindings'].items() if state['protocols'][i]['enabled']}
    units.add('caddy-sub.service')
    if any(p['enabled'] and protocol_type(i,p) in ('cf','xhttp') for i,p in state['protocols'].items()):units.add('argo.service')
    return {u:dict(line.split('=',1) for line in _run(['systemctl','show',u,'-p','MainPID','-p','NRestarts','-p','ActiveState','-p','User']).splitlines() if '=' in line) for u in sorted(units)}


def _environment(pid, root):
    return dict(v.split('=',1) for v in (root/str(pid)/'environ').read_bytes().decode().split('\0') if '=' in v)


def caddy_model(config):
    """Keep only public dependency facts; adapted DNS provider credentials never escape."""
    hosts=set();servers=config.get('apps',{}).get('http',{}).get('servers',{})
    def walk(value):
        if isinstance(value,dict):
            matches=value.get('match',[])
            if isinstance(matches,list):
                for match in matches:
                    if isinstance(match,dict):hosts.update(match.get('host',[]))
            for child in value.values():walk(child)
        elif isinstance(value,list):
            for child in value:walk(child)
    walk(servers)
    policies=config.get('apps',{}).get('tls',{}).get('automation',{}).get('policies',[])
    rows=[]
    for policy in policies:
        subjects=policy.get('subjects') or sorted(hosts)
        hosts.update(subjects);issuers=[]
        for issuer in policy.get('issuers') or [{'module':'acme'}]:
            challenges=issuer.get('challenges',{});dns=challenges.get('dns',{})
            issuers.append({'module':issuer.get('module'),'ca_host':urlsplit(issuer.get('ca','https://acme-v02.api.letsencrypt.org/directory')).hostname,
                           'http01_enabled':not dns and not challenges.get('http',{}).get('disabled',False),
                           'tls_alpn_enabled':not dns and not challenges.get('tls-alpn',{}).get('disabled',False),
                           'dns01_enabled':bool(dns),'dns_provider':dns.get('provider',{}).get('name')})
        rows.append({'subjects':subjects,'issuers':issuers})
    if not policies and hosts:rows=[{'subjects':sorted(hosts),'issuers':[{'module':'acme','ca_host':'acme-v02.api.letsencrypt.org','http01_enabled':True,'tls_alpn_enabled':True,'dns01_enabled':False,'dns_provider':None}]}]
    disabled=any(s.get('automatic_https',{}).get('disable') for s in servers.values())
    manual=config.get('apps',{}).get('tls',{}).get('certificates',{})
    return {'hosts':sorted(hosts),'policies':rows,'automatic_https_disabled':disabled,
            'manual_certificate_loaders':list(manual),'http_port':config.get('apps',{}).get('http',{}).get('http_port',80)}


def _acme_directory(url):
    try:
        u=urlsplit(url)
        if u.scheme!='https' or not u.hostname or u.username or u.password or u.query or u.fragment:raise ValueError()
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url,timeout=8) as response:
            raw=response.read(1048577)
            if len(raw)>1048576:raise ValueError()
            value=json.loads(raw)
            return {'host':u.hostname,'passed':response.status==200 and all(k in value for k in ('newNonce','newAccount','newOrder'))}
    except Exception as error:return {'passed':False,'error':error_info(error)}


def connector_identity(pid, management_sha256, root=Path('/proc')):
    """Compare locally; never return a connector credential or its hash."""
    args=(root/str(pid)/'cmdline').read_bytes().decode().split('\0');token=None;source='not_found';private=None
    if '--token-file' in args:
        path=Path(args[args.index('--token-file')+1]);token=path.read_text().strip();source='token_file';private=not bool(path.stat().st_mode&0o077)
    elif '--token' in args:token=args[args.index('--token')+1];source='process_argument'
    else:token=_environment(pid,root).get('TUNNEL_TOKEN');source='environment' if token else 'not_found'
    return {'source':source,'credential_found':bool(token),'token_file_private':private,
            'distinct_from_management':bool(token) and hashlib.sha256(token.encode()).hexdigest()!=management_sha256}


def snapshot(state, management_sha256, probe_acme=True, root=Path('/proc')):
    if not isinstance(management_sha256,str) or not re.fullmatch('[a-f0-9]{64}',management_sha256):raise ValueError('需要管理令牌的 SHA256，仅比较指纹，不接收令牌值')
    if type(probe_acme) is not bool:raise ValueError('probe_acme 必须为布尔值')
    protected={'processes':_processes(state),'native_sha256':{p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in state['native_sha256']}}
    result={'server':state['server_id'],'read_only':True,'forced_renewal':False,'services_reloaded':False,'protected':protected,
            'native_matches':protected['native_sha256']==state['native_sha256']}
    caddy=protected['processes']['caddy-sub.service'];pid=int(caddy['MainPID'])
    try:
        args=(root/str(pid)/'cmdline').read_bytes().decode().split('\0')
        path=Path(args[args.index('--config')+1]);command=[str((root/str(pid)/'exe').resolve()),'adapt','--config',str(path)]
        if '--adapter' in args:command+=['--adapter',args[args.index('--adapter')+1]]
        env=_environment(pid,root)
        raw=json.loads(_run(command,env=env));model=caddy_model(raw)
        protected['caddy_config_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        protected['caddy_effective_config_sha256']=hashlib.sha256(json.dumps(raw,sort_keys=True).encode()).hexdigest()
        storage=raw.get('storage',{});base=Path(storage.get('root') or (Path(env['XDG_DATA_HOME'])/'caddy' if env.get('XDG_DATA_HOME') else Path(env.get('HOME','/var/lib/caddy-sub'))/'.local/share/caddy'))
        writable=subprocess.run(['runuser','-u',caddy.get('User') or 'root','--','test','-w',str(base/'certificates')],capture_output=True,timeout=5).returncode==0
        providers=[i for p in raw.get('apps',{}).get('tls',{}).get('automation',{}).get('policies',[]) for i in p.get('issuers',[]) if i.get('challenges',{}).get('dns')]
        tokens=[i.get('challenges',{}).get('dns',{}).get('provider',{}).get('api_token') for i in providers]
        model.update(storage_writable=writable,storage_supported=not storage or storage.get('module')=='file_system',
                     dns_uses_management_token=any(isinstance(t,str) and hashlib.sha256(t.encode()).hexdigest()==management_sha256 for t in tokens),
                     cf_credential_env_present=bool(set(env)&{'CF_Token','CF_API_TOKEN','CLOUDFLARE_API_TOKEN','CF_Key'}))
        if probe_acme:
            policies=raw.get('apps',{}).get('tls',{}).get('automation',{}).get('policies') or [{}]
            urls={i.get('ca','https://acme-v02.api.letsencrypt.org/directory') for p in policies for i in p.get('issuers') or [{'module':'acme'}] if i.get('module')=='acme'}
            model['ca_directories']=[_acme_directory(u) for u in sorted(urls)]
        result['caddy']=model
    except Exception as error:result['caddy']={'error':error_info(error)}
    try:result['connector']=connector_identity(int(protected['processes'].get('argo.service',{}).get('MainPID',0)),management_sha256,root)
    except Exception as error:result['connector']={'credential_found':False,'error':error_info(error)}
    reloads=[]
    for path,engine in state['engines'].items():
        for inbound in json.loads(Path(path).read_text()).get('inbounds',[]):
            if engine['core']=='xray':
                for cert in inbound.get('streamSettings',{}).get('tlsSettings',{}).get('certificates',[]):
                    reloads.append({'engine':'xray','file_reference':bool(cert.get('certificateFile') and cert.get('keyFile')),'hot_reload':not cert.get('oneTimeLoading',False)})
            elif inbound.get('tls',{}).get('certificate_path') or inbound.get('tls',{}).get('certificate'):
                file_reference=bool(inbound['tls'].get('certificate_path') and inbound['tls'].get('key_path'))
                reloads.append({'engine':'sing-box','file_reference':file_reference,'hot_reload':file_reference})
    result['certificate_reload']=reloads
    timer=subprocess.run(['systemctl','is-active','--quiet','certbot.timer'],capture_output=True,timeout=5).returncode==0
    cron_files=[Path('/etc/crontab')]+list(Path('/etc/cron.d').glob('*'))+list(Path('/var/spool/cron/crontabs').glob('*'))
    acme_cron=False
    for p in cron_files:
        if p.is_file():acme_cron|=any(not line.lstrip().startswith('#') and '.acme.sh' in line and '--cron' in line for line in p.read_text(errors='replace').splitlines())
    result['other_renewal_jobs']={'active_certbot_with_configs':timer and bool(list(Path('/etc/letsencrypt/renewal').glob('*.conf'))),'active_acme_sh_cron':acme_cron}
    return result


def local_checks(value):
    issues=[];caddy=value.get('caddy',{});connector=value.get('connector',{})
    if not value.get('native_matches'):issues.append('native_configuration_drift')
    if value.get('source_matches') is not True:issues.append('native_source_not_verified')
    if any(v.get('ActiveState')!='active' or v.get('MainPID','0')=='0' for v in value['protected']['processes'].values()):issues.append('service_not_running')
    if not caddy.get('hosts') or not caddy.get('policies'):issues.append('caddy_automation_not_verified')
    if caddy.get('automatic_https_disabled') or caddy.get('manual_certificate_loaders'):issues.append('manual_or_disabled_certificate_management')
    if not caddy.get('storage_writable') or not caddy.get('storage_supported'):issues.append('caddy_storage_not_verified')
    if not caddy.get('ca_directories') or not all(r['passed'] for r in caddy.get('ca_directories',[])):issues.append('acme_ca_unreachable_or_unknown')
    if any(i.get('dns01_enabled') for p in caddy.get('policies',[]) for i in p['issuers']):issues.append('dns01_api_egress_requires_verification')
    if any(not i.get('http01_enabled') for p in caddy.get('policies',[]) for i in p['issuers']):issues.append('http01_not_available')
    if any(not r['file_reference'] or not r['hot_reload'] for r in value.get('certificate_reload',[])):issues.append('certificate_hot_reload_disabled')
    if not connector.get('distinct_from_management') or connector.get('token_file_private') is False:issues.append('connector_credential_independence_not_verified')
    if any(value.get('other_renewal_jobs',{}).values()):issues.append('other_renewal_job_requires_review')
    return {'passed':not issues,'issues':issues,'renewal_requires_management_relay':False if not issues else None}


def http_checks(cases):
    def check(case):
        try:
            ipaddress.ip_address(case['ip'])
            if not re.fullmatch(r'[a-zA-Z0-9.-]+',case['host']):raise ValueError()
            conn=http.client.HTTPConnection(case['ip'],80,timeout=5)
            try:
                conn.request('GET','/.well-known/acme-challenge/fleet-nonexistent-preflight',headers={'Host':case['host']})
                response=conn.getresponse();response.read(1024)
                return {'name':case['name'],'passed':response.getheader('Server')=='Caddy','status':response.status,'real_acme_validation':False}
            finally:conn.close()
        except Exception as error:return {'name':case['name'],'passed':False,'error':error_info(error),'real_acme_validation':False}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:return list(pool.map(check,cases))


def http_ingress(config,server,hosts):
    from acceptance import observers
    from fleet import ssh_args
    cases=[{'name':host+'/'+f,'ip':server[f],'host':host} for host in hosts for f in ('ipv4','ipv6') if server.get(f)]
    groups=observers(config,server,cases);rows=[]
    wrapper="import sys,json;sys.path.insert(0,'/opt/argosbx-fleet/current');import dependency_audit;print(json.dumps(dependency_audit.http_checks(json.load(sys.stdin))))"
    for peer,checks in groups.items():
        proc=subprocess.run(ssh_args(peer,config)+[shlex.join(['python3','-B','-c',wrapper])],input=json.dumps(checks),capture_output=True,text=True,timeout=max(30,len(checks)*6))
        if proc.returncode:raise RuntimeError('HTTP-01 独立入口核验未完成')
        got=json.loads(proc.stdout)
        if sorted(r['name'] for r in got)!=sorted(r['name'] for r in checks):raise ValueError('HTTP-01 结果集合不符')
        rows.extend({**r,'observer':peer} for r in got)
    return {'passed':bool(rows) and all(r['passed'] for r in rows),'results':rows,'real_acme_validation':False}


def references(cf,server,hosts):
    from domains import build
    from tunnels import routes
    from protocols import protocol_type
    zones=cf.zones();records={};matched={}
    for host in set(hosts)|{h for h in server['domains'].values() if h}:
        zone=max((z for z in zones if host==z['name'] or host.endswith('.'+z['name'])),key=lambda z:len(z['name']))
        records[host]=cf.call('/zones/'+zone['id']+'/dns_records?'+urlencode({'name':host,'per_page':100}))['result'];matched[host]=zone
    issues=[]
    for family,kind in [('ipv4','A'),('ipv6','AAAA')]:
        host=server['domains'][family]
        if host and not any(r['type']==kind and r['content']==server[family] and not r.get('proxied') for r in records[host]):issues.append('direct_dns_mismatch:'+family)
    for host in hosts:
        origins=[r for r in records[host] if r['type'] in ('A','AAAA')]
        if not origins or any(r['content'] not in (server.get('ipv4'),server.get('ipv6')) for r in origins):issues.append('certificate_dns_origin_not_verified:'+host)
    cf_hosts={p['sni'] for i,p in server['protocols'].items() if p['enabled'] and protocol_type(i,p) in ('cf','xhttp')}
    checked=[]
    for host in cf_hosts:
        if host not in records:
            z=max((z for z in zones if host.endswith('.'+z['name'])),key=lambda z:len(z['name']));matched[host]=z
            records[host]=cf.call('/zones/'+z['id']+'/dns_records?'+urlencode({'name':host}))['result']
        rows=[r for r in records[host] if r['type']=='CNAME' and r['content'].endswith('.cfargotunnel.com') and r.get('proxied')]
        if len(rows)!=1:issues.append('tunnel_dns_mismatch');continue
        z=matched[host];tid=rows[0]['content'].removesuffix('.cfargotunnel.com');base='/accounts/'+z['account']['id']+'/cfd_tunnel/'+tid
        detail=cf.call(base)['result'];plan=build(cf,z['name'],server,server['domains'],tid)
        wanted=[r for r in routes(server)[:-1] if r['hostname']==host]
        okay=not plan['records'] and plan['before']==plan['after'] and all(any(all(row.get(k)==v for k,v in w.items()) for row in plan['before']['ingress']) for w in wanted)
        if not okay:issues.append('domain_or_tunnel_route_drift')
        if detail.get('status')!='healthy':issues.append('tunnel_not_healthy')
        checked.append({'host':host,'healthy':detail.get('status')=='healthy','routes_match':okay,'configuration_sha256':hashlib.sha256(json.dumps(plan['before'],sort_keys=True).encode()).hexdigest()})
    return {'passed':not issues,'issues':issues,'tunnels':checked,'domain_plan_read_only':True}


def negative_source(config):
    from domains import Cloudflare,CloudflareAPIError
    from cf_transport import SSHTransport
    from fleet import resolve_path
    relay=config['cloudflare']['management_server'];peers=[s for s in config['servers'] if s['id']!=relay and s.get('status','active')=='active' and s.get('ipv4')]
    rows=[]
    for peer in peers:
        cf=Cloudflare(resolve_path(config['cloudflare']['token_file']),SSHTransport(config,peer['id']))
        try:
            try:cf.zones()
            except CloudflareAPIError as error:
                info=cf.transport_info();rows.append({'server':peer['id'],'passed':error.status==403 and info.get('verified') is True,'http_status':error.status,'source':info})
            else:rows.append({'server':peer['id'],'passed':False,'status':'non_management_source_allowed','source':cf.transport_info()})
        finally:cf.close()
    return {'passed':bool(rows) and all(r['passed'] for r in rows),'results':rows,'exhaustive_token_policy_read':False}


def observer_config(config,server):
    peers=[p for p in config['servers'] if p['id']!=server['id'] and p.get('status','active')=='active' and all(not server.get(f) or p.get(f) for f in ('ipv4','ipv6'))]
    selected=copy.copy(config)
    if peers:selected['coordinator']=peers[0]['id']
    return selected,peers[0]['id'] if peers else None


def _checked(action):
    try:return action()
    except Exception as error:
        from acceptance import AcceptanceError
        result={'passed':False,'error':error_info(error)}
        if isinstance(error,AcceptanceError):result['evidence']=error.evidence
        return result


def read_remote(remote,config,server,command,payload=None):
    if command not in ('dependency-snapshot','certificate-snapshot','diagnostic-source'):raise ValueError('依赖验收只允许远端只读命令')
    for attempt in range(3):
        try:return remote(config,server,command,payload)
        except RuntimeError as error:
            if '另一个维护事务正在运行' not in str(error) or attempt==2:raise
            time.sleep(.2*(attempt+1))


def run(config,targets,remote,verify_writes=False):
    import acceptance,certificates,cf_audit,cf_probe
    from domains import Cloudflare
    from fleet import resolve_path,STATE
    from protocols import classify,protocol_type
    original_remote=remote
    remote=lambda c,s,command,payload=None:read_remote(original_remote,c,s,command,payload)
    result={'read_only':not verify_writes,'writes_requested':verify_writes,'writes_tested':False,'forced_renewal':False,'services_reloaded':False,'servers':[],
            'policy_evidence_scope':'functional source allow/deny, not exhaustive token policy enumeration',
            'dependencies':{'renewal':'per-host certificate manager','cf_management':'configured SSH egress; no direct fallback','tunnel_runtime':'per-tunnel connector credential'},
            'management_relay_outage':'CF API maintenance stops; HTTP-01 renewal and separate connector credentials are independent only when their checks pass'}
    if not config.get('cloudflare',{}).get('management_server'):raise ValueError('依赖验收需要先配置 cloudflare.management_server；不会使用本机出口')
    cf=Cloudflare.from_config(config);digest=hashlib.sha256(cf.token.encode()).hexdigest();write_scopes={};write_owners={}
    try:
        positive=_checked(lambda:{'passed':bool(cf.zones()),'transport':cf.transport_info()})
        info=positive.get('transport',{});positive['passed']=positive.get('passed') and info.get('verified') is True and info.get('direct_fallback') is False
        result['management_access']=positive
        result['source_restriction']=_checked(lambda:negative_source(config)) if positive['passed'] else {'passed':False,'status':'positive_source_not_verified'}
        for server in targets:
            sid=server['id'];row={'server':sid};payload={'management_sha256':digest};probe_config,observer=observer_config(config,server)
            before=_checked(lambda:remote(config,sid,'dependency-snapshot',payload));row['snapshot']=before
            row['local_dependencies']=_checked(lambda:local_checks(before))
            hosts=before.get('caddy',{}).get('hosts',[])
            row['certificates']=_checked(lambda:certificates.run(config,server,remote,observer=observer,http_hosts=hosts))
            row['http01_ingress']=_checked(lambda:http_ingress(probe_config,server,hosts))
            row['cloudflare_policy']=_checked(lambda:cf_audit.audit(cf,server,resolve_path(config['cloudflare']['policy_snapshot']) if config['cloudflare'].get('policy_snapshot') else None)) if positive['passed'] else {'read_access_passed':False}
            row['references']=_checked(lambda:references(cf,server,hosts)) if positive['passed'] else {'passed':False}
            def traffic():
                scoped=copy.deepcopy(server);scoped['protocols']={i:p for i,p in server['protocols'].items() if p['enabled'] and protocol_type(i,p) in ('cf','xhttp')}
                if not scoped['protocols']:return {'passed':True,'status':'not_required','results':[]}
                bundle=remote(config,sid,'diagnostic-source');nodes=[n for n in bundle['nodes'] if classify(n) in ('cf','xhttp')]
                return acceptance.verify_new_server(probe_config,scoped,nodes)
            row['cf_traffic']=_checked(traffic)
            if verify_writes and positive['passed'] and result['source_restriction']['passed']:
                def writes():
                    zones=cf_probe.zones_for(cf,server);scope=tuple(sorted((z['id'],z['account']['id']) for z in zones))
                    if scope not in write_scopes:
                        result['writes_tested']=True
                        write_owners[scope]=sid
                        write_scopes[scope]=_checked(lambda:cf_probe.verify(cf,server,STATE/(sid+'-cf-permission-check.json')))
                    row['write_recovery_command']='fleetctl.py cf-audit --server '+write_owners[scope]+' --recover-writes'
                    return write_scopes[scope]
                row['write_access']=_checked(writes)
                row.setdefault('write_recovery_command','fleetctl.py cf-audit --server '+sid+' --recover-writes')
            else:row['write_access']={'passed':None if not verify_writes else False,'status':'not_tested' if not verify_writes else 'source_preflight_failed'}
            after=_checked(lambda:remote(config,sid,'dependency-snapshot',{**payload,'probe_acme':False}))
            row['protected_state_preserved']=bool(before.get('protected')) and before.get('protected')==after.get('protected')
            required=('local_dependencies','certificates','http01_ingress','references','cf_traffic')+(('write_access',) if verify_writes else ())
            row['passed']=all(row[k].get('passed') is True for k in required) and row['cloudflare_policy'].get('read_access_passed') is True and row['protected_state_preserved']
            result['servers'].append(row)
        result['passed']=positive['passed'] is True and result['source_restriction']['passed'] is True and bool(result['servers']) and all(r['passed'] for r in result['servers'])
        result['status']='passed' if result['passed'] else 'needs_attention'
        return result
    finally:cf.close()
