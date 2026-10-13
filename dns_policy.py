"""DNS policy shared by the deployed Sub-Store templates and their generator."""
import copy
import re
import sys
from pathlib import Path


from fleet import host_map

BOOTSTRAP = ['https://223.5.5.5/dns-query', 'https://223.6.6.6/dns-query']
REMOTE = ['https://1.1.1.1/dns-query', 'https://1.0.0.1/dns-query']
# Only stable, self-owned origin addresses are pinned; CDN ingress remains dynamic.
NODE_HOSTS = host_map()
FEISHU = ['feishu.cn','feishucdn.com']
LOCAL_DOH = 'https://223.6.6.6/dns-query'
DNS_DOMAINS = ['dns.alidns.com', 'doh.pub', 'dot.pub', 'dns.google',
               'cloudflare-dns.com', 'one.one.one.one', 'dns.quad9.net']
DNS_IPS = ['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '223.5.5.5',
           '223.6.6.6', '119.29.29.29', '9.9.9.9', '149.112.112.112']
DNS_IPV6 = ['2606:4700:4700::1111', '2606:4700:4700::1001',
            '2001:4860:4860::8888', '2001:4860:4860::8844',
            '2400:3200::1', '2400:3200:baba::1']


def guarded_rules(original):
    guards = ['DST-PORT,53,REJECT', 'DST-PORT,853,日常线路']
    guards += ['DOMAIN-SUFFIX,'+d+',DIRECT' for d in FEISHU]
    guards += ['IP-CIDR,223.6.6.6/32,DIRECT,no-resolve']
    guards += ['DOMAIN,' + d + ',日常线路' for d in DNS_DOMAINS]
    guards += ['IP-CIDR,' + ip + '/32,日常线路,no-resolve' for ip in DNS_IPS]
    guards += ['IP-CIDR6,' + ip + '/128,日常线路,no-resolve' for ip in DNS_IPV6]
    # Remove old broad DNS exceptions, keeping application routing intact.
    managed = {r.split(',')[0] + ',' + r.split(',')[1] for r in guards}
    return guards + [r for r in original if ','.join(r.split(',')[:2]) not in managed]


def harden_config(original, client):
    config = copy.deepcopy(original)
    config.setdefault('hosts', {}).update(NODE_HOSTS)
    config['rules'] = guarded_rules(config['rules'])
    dns = config['dns']
    dns['default-nameserver'] = list(BOOTSTRAP)
    dns.pop('fallback', None)
    dns.pop('fallback-filter', None)
    if client == 'clash':
        dns['nameserver'] = [u + '#日常线路' for u in REMOTE]
        dns['proxy-server-nameserver'] = [u + '#DIRECT' for u in BOOTSTRAP]
        dns.pop('direct-nameserver', None)
        dns.pop('direct-nameserver-follow-policy', None)
        dns['nameserver-policy'] = {**{'+.'+d:[u+'#日常线路' for u in REMOTE] for d in ['googleapis.cn','xn--ngstr-lra8j.com']}, **{'+.'+d:[LOCAL_DOH+'#DIRECT'] for d in FEISHU}, '+.cn':[LOCAL_DOH+'#DIRECT'], 'rule-set:国内域名':[LOCAL_DOH+'#DIRECT']}
        dns['direct-nameserver']=[LOCAL_DOH+'#DIRECT']
        dns['direct-nameserver-follow-policy']=True
        dns['use-hosts'] = True
        tun = config.setdefault('tun', {})
        tun['dns-hijack'] = list(dict.fromkeys(tun.get('dns-hijack', []) + ['any:53', 'tcp://any:53']))
        tun['strict-route'] = True
    else:
        assert client == 'stash'
        dns['nameserver'] = list(REMOTE)
        dns['proxy-server-nameserver'] = list(BOOTSTRAP)
        dns['nameserver-policy'] = {**{'+.'+d:list(REMOTE) for d in ['googleapis.cn','xn--ngstr-lra8j.com']}, **{'+.'+d:[LOCAL_DOH] for d in FEISHU}, '+.cn':[LOCAL_DOH], 'geosite:cn':[LOCAL_DOH]}
        dns['follow-rule'] = True
    return config


def harden_shadowrocket(original):
    remote = ', '.join(u + '#proxy' for u in REMOTE)
    replacements = {'dns-server': remote, 'fallback-dns-server': remote,
                    'proxy-dns-server': ', '.join(BOOTSTRAP), 'dns-direct-system': 'false',
                    'use-local-host-item-for-proxy': 'true'}
    result = original
    for key, value in replacements.items():
        result, count = re.subn(r'^' + re.escape(key) + r'\s*=.*$', key + ' = ' + value, result, flags=re.M)
        assert count == 1, 'Unexpected Shadowrocket setting: ' + key
    result = re.sub(r'^GEOIP,CN,DIRECT$', 'GEOIP,CN,DIRECT,no-resolve', result, flags=re.M)
    rule_start = result.index('[Rule]') + len('[Rule]')
    next_section = result.find('\n[', rule_start)
    rule_end = next_section if next_section >= 0 else len(result)
    rules = [s for s in result[rule_start:rule_end].splitlines() if s.strip()]
    result = result[:rule_start] + '\n' + '\n'.join(guarded_rules(rules)) + '\n' + result[rule_end:]
    host_section = '[Host]\n' + '\n'.join(k + ' = ' + v for k, v in NODE_HOSTS.items()) + '\n'
    if '[Host]' not in result:
        result += '\n' + host_section
    else:
        start = result.index('[Host]') + len('[Host]')
        end = result.find('\n[', start)
        end = end if end >= 0 else len(result)
        lines = [s for s in result[start:end].splitlines() if s.strip()
                 and s.split('=', 1)[0].strip() not in NODE_HOSTS]
        result = result[:start] + '\n' + ''.join(s + '\n' for s in lines) + host_section[len('[Host]\n'):] + result[end:]
    return result
