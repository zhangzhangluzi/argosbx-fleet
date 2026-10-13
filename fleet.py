"""Validated private inventory shared by SSH, DNS and subscription generation."""
import ipaddress
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

WORKSPACE = Path(os.environ.get('ARGOSBX_WORKSPACE', Path.cwd())).resolve()
STATE = Path(os.environ.get('ARGOSBX_STATE', Path.home()/'.local/state/argosbx-fleet'))
DEFAULT = Path(os.environ.get('ARGOSBX_SERVERS_FILE', Path.home()/'.config/argosbx-fleet/servers.json'))


def read(path=None):
    path = Path(path or os.environ.get('ARGOSBX_SERVERS_FILE', DEFAULT)).expanduser().resolve()
    if path.stat().st_mode & 0o077:
        raise ValueError('服务器配置含私有链接，文件权限必须为 0600')
    return validate(json.loads(path.read_text()))


def validate(data):
    if data.get('schema') not in (1,2,3) or not isinstance(data.get('servers'), list) or not data['servers']:
        raise ValueError('需要 schema=1/2/3 和非空 servers')
    def check(value, pattern, label):
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise ValueError('无效字段：' + label)
    def url(value, label):
        p = urlsplit(value)
        if p.scheme != 'https' or not p.hostname or p.username or p.password or p.fragment:
            raise ValueError(label + ' 必须为不含用户名密码的 HTTPS 地址')
        if any(c.isspace() for c in value):
            raise ValueError(label + ' 不能包含空白')
    def domain(value):
        check(value, r'(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}', '域名')
    ids, names, sources, domains, regions = set(), set(), set(), set(), {}
    for s in data['servers']:
        check(s['id'], r'[a-z][a-z0-9_-]{0,31}', 'id')
        check(s['name'], r'[A-Z][A-Z0-9]{0,31}', 'name')
        check(s['country'], r'[A-Z]{2}', 'country')
        check(s['country_name'], r'[^,=\[\]#;\r\n]{1,40}', 'country_name')
        for value, seen in [(s['id'], ids), (s['name'], names), (s['subscription']['name'], sources)]:
            if value in seen: raise ValueError('服务器 id、节点前缀或订阅源名称重复')
            seen.add(value)
        if s['country'] in regions and regions[s['country']] != s['country_name']:
            raise ValueError('同一国家的显示名称必须一致')
        if s['country_name'] in regions.values() and regions.get(s['country']) != s['country_name']:
            raise ValueError('不同国家不能使用相同显示名称')
        regions[s['country']] = s['country_name']
        for family in ('ipv4', 'ipv6'):
            value, host = s[family], s['domains'][family]
            if bool(value) != bool(host): raise ValueError(f'{family} 地址和域名必须同时设置或同时为 null')
            if value:
                ip = ipaddress.ip_address(value)
                if ip.version != (4 if family == 'ipv4' else 6): raise ValueError('IP 地址族不符')
                domain(host)
                if host in domains: raise ValueError('入口域名重复')
                domains.add(host)
        if not s['ipv4'] and not s['ipv6']: raise ValueError('至少需要一种 IP 地址')
        if s['domains']['cf']:
            domain(s['domains']['cf'])
            if s['domains']['cf'] in domains: raise ValueError('CF 域名重复')
            domains.add(s['domains']['cf'])
        ssh = s['ssh']
        ipaddress.ip_address(ssh['host'])
        check(ssh['user'], r'[a-z_][a-z0-9_-]{0,31}', 'SSH user')
        if type(ssh['port']) is not int or not 1 <= ssh['port'] <= 65535: raise ValueError('SSH port 无效')
        for field in ('known_hosts', 'identity_file'):
            value = ssh.get(field)
            if value is not None and (not isinstance(value, str) or not value or '\n' in value):
                raise ValueError('SSH 文件路径无效')
        if not ssh.get('known_hosts'): raise ValueError('必须指定可信 known_hosts')
        check(s['subscription']['name'], r'[a-zA-Z0-9_-]{1,64}', 'subscription.name')
        url(s['subscription']['url'], 'subscription.url')
        if type(s['salamander_ipv6']) is not bool: raise ValueError('salamander_ipv6 必须为布尔值')
    for key in ('backend_url', 'public_url'):
        url(data['subscription'][key], key)
    if not isinstance(data['purpose_order'], list) or len(set(data['purpose_order'])) != len(data['purpose_order']):
        raise ValueError('purpose_order 必须为不重复的国家代码列表')
    if set(data['purpose_order']) != set(regions): raise ValueError('purpose_order 必须包含所有国家且只包含已有国家')
    interval=data.get('health',{}).get('interval',900)
    if type(interval) is not int or interval not in (900,1800): raise ValueError('health.interval 只支持 900 或 1800 秒')
    from protocols import validate_settings
    for server in data['servers']:
        protocols=server.get('protocols',{})
        validate_settings(protocols,complete=data['schema']>=2)
        if data['schema']>=2 and (not protocols or not any(p['enabled'] for p in protocols.values())):
            raise ValueError('每台已登记服务器至少保留一个启用协议；移除整机请从汇总配置中移除')
        certs=server.get('certificates',{})
        for p in protocols.values():
            if 'certificate' in p:
                cert=certs.get(p['certificate'],{})
                if set(cert)!={'certificate_file','key_file'} or any(not isinstance(v,str) or not v.startswith('/') or '\n' in v for v in cert.values()):
                    raise ValueError('证书引用缺失或路径不是绝对路径')
    return data


def servers(data=None):
    return {s['id']: s for s in (data or read())['servers']}


def host_map(data=None):
    return {s['domains'][f]: s[f] for s in (data or read())['servers'] for f in ('ipv4', 'ipv6') if s[f]}


def region_spec(server):
    return {'country': server['country'], 'name': server['name'],
            'IPv4': server['domains']['ipv4'], 'IPv6': server['domains']['ipv6'],
            'cf': server['domains']['cf'], 'salamanderIPv6': server['salamander_ipv6'], 'protocols':server.get('protocols',{})}


def resolve_path(value):
    path = Path(value).expanduser()
    return path if path.is_absolute() else WORKSPACE / path


def ssh_args(server_id, data=None):
    s = servers(data)[server_id]['ssh']
    args = ['ssh', '-S', 'none', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(resolve_path(s['known_hosts'])),
            '-p', str(s['port'])]
    # A multiplexed master ignores a changed destination. Reuse it only when
    # its separately recorded connection identity still matches the inventory.
    sessions = WORKSPACE / '.vpn-deploy/ssh-sessions.json'
    saved = json.loads(sessions.read_text()).get(server_id, {}) if sessions.exists() else {}
    if all(saved.get(k) == s[k] for k in ('host', 'port', 'user')) and saved.get('socket'):
        args[2] = str(resolve_path(saved['socket']))
    if s.get('identity_file'): args += ['-i', str(resolve_path(s['identity_file'])), '-o', 'IdentitiesOnly=yes']
    return args + [s['user'] + '@' + s['host']]
