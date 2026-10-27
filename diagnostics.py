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
    for binding in state['bindings'].values():
        unit = binding['service']
        if unit in services:
            continue
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
                if table.startswith('tcp') and parts[3] != '0A':
                    continue
                address, port = parts[1].split(':')
                sockets.append({'service': owners[parts[9]], 'transport': table.rstrip('6'),
                                'family': 6 if table.endswith('6') else 4, 'port': int(port, 16),
                                'inode': parts[9], 'receive_queue': int(parts[4].split(':')[1], 16),
                                'drops': int(parts[-1]) if table.startswith('udp') else None})
        except (OSError, ValueError, IndexError):
            pass
    try:
        boot_id = (root/'sys/kernel/random/boot_id').read_text().strip()
    except OSError:
        boot_id = None
    return {'boot_id': boot_id, 'monotonic': time.monotonic(), 'counters': counters(root),
            'services': {k: {f: v for f, v in value.items() if f != 'inodes'} for k, value in services.items()},
            'sockets': sockets, 'packet_capture_performed': False,
            'cloud_firewall': 'not_observed', 'syn_arrival': 'not_observed'}


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
