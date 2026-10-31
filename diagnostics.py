"""Read-only transport evidence. Never infer censorship from one timeout."""
import concurrent.futures
import json
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

from protocols import protocol_type


def _metric_total(text, name):
    """Read numeric counters only; never expose metric labels or raw response text."""
    import math
    values=[]
    for line in text.splitlines():
        match=re.fullmatch(re.escape(name)+r'(?:\{[^{}\n]*\})?\s+([^\s]+)(?:\s+\d+)?',line)
        if not match:continue
        try:value=float(match[1])
        except ValueError:return None
        if not math.isfinite(value) or value<0 or not value.is_integer():return None
        values.append(int(value))
    return sum(values) if values else None


def connector_health(state, command=None, root=Path('/proc')):
    """Bounded local readiness/HA evidence; no provider API or service mutation."""
    if not any(p['enabled'] and protocol_type(i,p) in ('cf','xhttp') for i,p in state.get('protocols',{}).items()):
        return {'required':False}
    import http.client
    command=command or (lambda args:subprocess.check_output(args,text=True,timeout=5))
    result={'required':True,'service_active':False,'ready':None,'ha_connections':None,
            'redundancy':'unknown','metrics_status':'not_observed'}
    try:
        command(['systemctl','is-active','--quiet','argo'])
        pid=int(command(['systemctl','show','argo','-p','MainPID','--value']).strip())
        if pid<=0:raise ValueError('No connector process')
        proc=root/str(pid)
        if 'cloudflared' not in (proc/'exe').resolve().name:raise ValueError('Unexpected process')
        result.update(service_active=True,pid=pid)
        args=(proc/'cmdline').read_bytes().decode().split('\0')
        def option(name,default=None):
            for index,arg in enumerate(args):
                if arg==name:return args[index+1]
                if arg.startswith(name+'='):return arg.split('=',1)[1]
            return default
        try:environment=dict(v.split('=',1) for v in (proc/'environ').read_bytes().decode().split('\0') if '=' in v)
        except (OSError,UnicodeError):environment={}
        protocol=option('--protocol',environment.get('TUNNEL_TRANSPORT_PROTOCOL','auto'))
        result['configured_protocol']=protocol if protocol in ('auto','http2','quic') else 'unknown'
        expected=option('--ha-connections',environment.get('TUNNEL_HA_CONNECTIONS','4'))
        expected=int(expected) if expected.isdecimal() and 0<int(expected)<=1024 else None
        result['expected_ha_connections']=expected
        endpoint=option('--metrics')
        if endpoint is None:
            result['readiness_check']='metrics-not-explicit';return result
        host,port=endpoint.rsplit(':',1);host=host.strip('[]');port=int(port)
        if not ipaddress.ip_address(host).is_loopback or not 0<port<65536:raise ValueError('Metrics must be loopback')
        def fetch(path,limit):
            connection=http.client.HTTPConnection(host,port,timeout=3)
            try:
                connection.request('GET',path);response=connection.getresponse()
                if response.status!=200:return response.status,None
                body=response.read(limit+1)
                if len(body)>limit:raise ValueError('Oversize local metrics')
                return response.status,body.decode()
            finally:connection.close()
        status,_=fetch('/ready',4096);result['ready']=status==200
        result['readiness_check']='loopback-ready'
        if not result['ready']:return result
        try:
            status,body=fetch('/metrics',1048576)
            if status!=200:raise ValueError('Local metrics unavailable')
            connections=_metric_total(body,'cloudflared_tunnel_ha_connections')
            result.update(ha_connections=connections,metrics_status='available' if connections is not None else 'partial')
            result['request_errors_total']=_metric_total(body,'cloudflared_tunnel_request_errors')
            result['requests_total']=_metric_total(body,'cloudflared_tunnel_total_requests')
            # Canceled client streams also increment this counter; it is not an outage rate.
            result['request_error_counter_scope']='cumulative_including_client_cancellation'
            if connections is not None:
                result['redundancy']='none' if connections==0 else 'full' if expected is not None and connections>=expected else 'reduced' if expected is not None else 'unknown'
                if connections==0:result['ready']=False
        except (OSError,ValueError,UnicodeError,http.client.HTTPException):result['metrics_status']='unavailable'
    except (OSError,ValueError,IndexError,UnicodeError,subprocess.SubprocessError,http.client.HTTPException):
        result['ready']=False;result['readiness_check']='unavailable'
    return result


def error_info(error):
    result = {'type': type(error).__name__}
    if isinstance(getattr(error, 'errno', None), int):
        result['errno'] = error.errno
    return result


def counters(root=Path('/proc')):
    result = {}
    try:
        lines = (root/'net/snmp').read_text().splitlines()
        for head, values in zip(lines[::2], lines[1::2]):
            if head.startswith(('Udp:', 'Tcp:')):
                prefix, *names = head.split()
                for key, value in zip(names, values.split()[1:]):
                    if key in ('InErrors', 'RcvbufErrors', 'SndbufErrors', 'InCsumErrors', 'RetransSegs', 'AttemptFails'):
                        result[prefix[:-1]+key] = int(value)
        for line in (root/'net/snmp6').read_text().splitlines():
            key, value = line.split()
            if key in ('Udp6InErrors', 'Udp6RcvbufErrors', 'Udp6SndbufErrors', 'Udp6InCsumErrors'):
                result[key] = int(value)
    except (OSError, ValueError):
        pass
    return result


def snapshot(state, root=Path('/proc')):
    """Read socket ownership and cumulative drops, without copying socket handles."""
    services = {}
    units={binding['service'] for binding in state['bindings'].values()}
    uses_cf=any(p['enabled'] and protocol_type(i,p) in ('cf','xhttp') for i,p in state.get('protocols',{}).items())
    if uses_cf:units.add('argo.service')
    for unit in sorted(units):
        try:
            proc = subprocess.run(['systemctl', 'show', unit, '-p', 'MainPID', '-p', 'ActiveState'],
                                  capture_output=True, text=True, check=True, timeout=5)
            values = dict(line.split('=', 1) for line in proc.stdout.splitlines() if '=' in line)
            pid = int(values.get('MainPID', '0'))
            inodes = set()
            if pid:
                for fd in (root/str(pid)/'fd').iterdir():
                    try:
                        target = str(fd.readlink())
                        if target.startswith('socket:['):
                            inodes.add(target[8:-1])
                    except OSError:
                        pass
            services[unit] = {'pid': pid, 'active': values.get('ActiveState') == 'active', 'inodes': inodes}
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            services[unit] = {'pid': 0, 'active': False, 'inodes': set(), 'error': error_info(error)}
    owners = {inode: unit for unit, value in services.items() for inode in value['inodes']}
    sockets = []
    for table in ('tcp', 'tcp6', 'udp', 'udp6'):
        try:
            for line in (root/'net'/table).read_text().splitlines()[1:]:
                parts = line.split()
                if len(parts) < 10 or parts[9] not in owners:
                    continue
                if table.startswith('tcp') and parts[3] != '0A' and not (owners[parts[9]]=='argo.service' and parts[3]=='01'):
                    continue
                address, port = parts[1].split(':')
                sockets.append({'service': owners[parts[9]], 'transport': table.rstrip('6'),
                                'family': 6 if table.endswith('6') else 4, 'port': int(port, 16),
                                'state':'listening' if parts[3]=='0A' else 'connected',
                                'remote_port':int(parts[2].rsplit(':',1)[1],16),
                                'inode': parts[9], 'receive_queue': int(parts[4].split(':')[1], 16),
                                'drops': int(parts[-1]) if table.startswith('udp') else None})
        except (OSError, ValueError, IndexError):
            pass
    try:
        boot_id = (root/'sys/kernel/random/boot_id').read_text().strip()
    except OSError:
        boot_id = None
    result={'boot_id': boot_id, 'monotonic': time.monotonic(), 'counters': counters(root),
            'services': {k: {f: v for f, v in value.items() if f != 'inodes'} for k, value in services.items()},
            'sockets': sockets, 'packet_capture_performed': False,
            'cloud_firewall': 'not_observed', 'syn_arrival': 'not_observed'}
    if uses_cf:result['cloudflare']=connector_health(state,root=root)
    return result


def delta(before, after):
    same_boot = before.get('boot_id') is not None and before.get('boot_id') == after.get('boot_id')
    result = {'valid': same_boot, 'host_counter_delta': {}, 'socket_drop_delta': [],
              'interval_seconds': round(after['monotonic']-before['monotonic'], 3)}
    if not same_boot:
        result['reason'] = 'boot_identity_changed_or_unavailable'
        return result
    for key, value in after['counters'].items():
        old = before['counters'].get(key)
        result['host_counter_delta'][key] = value-old if old is not None and value >= old else None
    old_sockets = {(s['service'], s['inode']): s for s in before['sockets'] if s['transport'] == 'udp'}
    for current in after['sockets']:
        key = (current['service'], current['inode'])
        old = old_sockets.get(key)
        if old and before['services'][key[0]]['pid'] == after['services'][key[0]]['pid']:
            difference = current['drops']-old['drops']
            result['socket_drop_delta'].append({'service': key[0], 'port': current['port'],
                                              'family': current['family'], 'drops': difference if difference >= 0 else None})
    result['processes_preserved'] = before['services'] == after['services']
    return result


def tcp_checks(cases):
    """TCP connect success proves a handshake only; UDP requires a native client."""
    selected = [c for c in cases if c['node']['type'] != 'hysteria2']

    def check(case):
        node = case['node']; attempts = []
        for _ in range(2):
            start = time.monotonic()
            try:
                with socket.create_connection((node['server'], node['port']), timeout=3):
                    attempts.append({'connected': True, 'ms': round((time.monotonic()-start)*1000, 2)})
            except OSError as error:
                attempts.append({'connected': False, 'error': error_info(error)})
        return {'name': case['name'], 'transport': 'tcp', 'attempts': attempts,
                'connected': any(a['connected'] for a in attempts)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        return list(pool.map(check, selected))


def ping_checks(cases):
    binary=shutil.which('ping')
    addresses=set()
    for case in cases:
        try:addresses.add(str(ipaddress.ip_address(case['node']['server'])))
        except ValueError:continue
    def check(address):
        if not binary:return {'address':address,'reply_observed':None,'status':'ping_unavailable'}
        try:
            proc=subprocess.run([binary,'-6' if ':' in address else '-4','-n','-c','2','-W','2','-w','5',address],
                                capture_output=True,text=True,timeout=6,env={**os.environ,'LC_ALL':'C'})
            counts=re.search(r'(\d+) packets transmitted, (\d+) (?:packets )?received',proc.stdout)
            return {'address':address,'reply_observed':bool(int(counts[2])) if counts else None,
                    'transmitted':int(counts[1]) if counts else None,'received':int(counts[2]) if counts else None,
                    'status':'sampled' if counts else 'not_verified'}
        except (OSError,subprocess.SubprocessError) as error:
            return {'address':address,'reply_observed':None,'error':error_info(error)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:return list(pool.map(check,sorted(addresses)))


def classify(cases, raw, native):
    observations = []
    tcp = {r['name']: r for r in raw}
    results = {r['name']: r for r in native['results']}
    for case in cases:
        name = case['name']; r = results.get(name, {}); node = case['node']
        transport = 'udp' if node['type'] == 'hysteria2' else 'tcp'
        if r.get('https_ok') and not r.get('exit_ok'):
            layer = 'unexpected_exit'
        elif r.get('https_ok') and r.get('udp_ok'):
            layer = 'passed_after_retry' if r.get('retry_recovered') else 'passed'
        elif r.get('https_ok'):
            layer = 'udp_forwarding_failed'
        elif r.get('status') == 'setup_failed':
            layer = 'observer_client_failed'
        elif transport == 'tcp' and not tcp.get(name, {}).get('connected'):
            layer = 'tcp_connect_failed'
        else:
            layer = 'native_handshake_or_target_failed'
        observations.append({'name': name, 'transport': transport, 'layer': layer,
                             'entry_reachable': True if r.get('https_ok') else None,
                             'udp_forwarding_ok': r.get('udp_ok') is True})
    return {'observations': observations, 'ip_wide_block': 'not_proven',
            'udp_port_scan_is_proof': False, 'mainland_path_tested': False,
            'limits': ['observer_path_only', 'no_packet_capture', 'cloud_firewall_not_observed',
                       'http_target_failure_can_affect_probe', 'short_sample_not_long_term_stability']}


def run(config, server, remote, observer=None):
    import acceptance
    from fleet import servers, ssh_args
    # The private export is sent over SSH stdin, never printed or saved by this command.
    bundle = remote(config, server['id'], 'diagnostic-source')
    checks = acceptance.cases(server, bundle['nodes'])
    if observer:
        peer = servers(config).get(observer)
        if not peer or peer['id'] == server['id'] or peer.get('status', 'active') != 'active':
            raise ValueError('验收端必须是另一台已启用服务器')
        if any(c['name'].endswith('/ipv6') for c in checks) and not peer.get('ipv6'):
            raise ValueError('所选验收端缺少 IPv6，不能冒充双栈验收')
        groups = {observer: checks}
    else:
        groups = acceptance.observers(config, server, checks)
    import shlex
    wrapper = ("import json,sys;sys.path.insert(0,'/opt/argosbx-fleet/current');"
               "import diagnostics,probe;p=json.load(sys.stdin);"
               "i=diagnostics.ping_checks(p['cases']);r=diagnostics.tcp_checks(p['cases']);n=probe.verify(p['cases']);"
               "print(json.dumps({'icmp':i,'tcp':r,'native':n}))")
    outputs = []
    for peer, selected in groups.items():
        proc = subprocess.run(ssh_args(peer, config)+[shlex.join(['python3', '-B', '-c', wrapper])],
                              input=json.dumps({'cases': selected}), capture_output=True, text=True,
                              timeout=max(180, len(selected)*60))
        if proc.returncode:
            raise RuntimeError('独立诊断客户端未完成；未修改服务或订阅')
        value = json.loads(proc.stdout)
        if sorted(r['name'] for r in value['native']['results']) != sorted(c['name'] for c in selected):
            raise ValueError('独立诊断结果节点集合不符')
        outputs.append({'observer': peer, 'icmp':value['icmp'],'tcp': value['tcp'], 'native': value['native'],
                        'analysis': classify(selected, value['tcp'], value['native'])})
    after = remote(config, server['id'], 'network-snapshot')
    difference=delta(bundle['snapshot'],after)
    return {'server': server['id'], 'read_only': True, 'observers': outputs,
            'network_delta':difference,'local': after,
            'passed':all(r['native']['passed'] for r in outputs) and difference['valid'] and difference.get('processes_preserved') is True}
