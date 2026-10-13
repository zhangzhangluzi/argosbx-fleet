"""DNS policy shared by the deployed Sub-Store templates and their generator."""
import copy
import re
import sys
from pathlib import Path


from fleet import host_map

BOOTSTRAP = ['https://223.5.5.5/dns-query', 'https://223.6.6.6/dns-query']
REMOTE = ['https://1.1.1.1/dns-query', 'https://1.0.0.1/dns-query']
# Only stable, self-owned origin addresses are pinned; CDN ingress remains dynamic.
FEISHU = ['feishu.cn','feishucdn.com']
# These are advertiser consoles, not ad-delivery endpoints for this profile.
# Keep the allowlist exact so unrelated SDK and tracking hosts remain blockable.
BUSINESS_CONSOLES = ['ads.applovin.com', 'ads.tiktok.com']
# Verified public console pages, their UI bundles and application bootstrap API.
# Do not include platform-wide suffixes, telemetry or conversion endpoints.
DOMESTIC_BUSINESS_HOSTS = [
    'e.qq.com', 'ad.qq.com',
    'ad.e.kuaishou.com', 'ad-m.e.kuaishou.com', 'dapi.e.kuaishou.com',
    'p4-ad.adkwai.com', 'p5-ad.adkwai.com',
    'lf3-ad-platform.byteadverts.com',
]
LOCAL_DOH = 'https://223.6.6.6/dns-query'
# Remote-control signaling, relays and app-owned P2P must keep the local exit.
REMOTE_CONTROL_DOMAINS = [
    'nrd.nie.163.com', 'uuyc.163.com', 'uuyc.webapp.163.com',
    'nrd-ugc.fp.ps.netease.com', 'todesk.com', 'oray.com', 'oray.net',
    'orayimg.com',
]
REMOTE_CONTROL_PROCESS = r'(?i)^(uuremote|uuyc|todesk|sunlogin|oray-sunlogin).*$'
REMOTE_CONTROL_RULE = 'PROCESS-NAME-REGEX,' + REMOTE_CONTROL_PROCESS + ',DIRECT'
DNS_DOMAINS = ['dns.alidns.com', 'doh.pub', 'dot.pub', 'dns.google',
               'cloudflare-dns.com', 'one.one.one.one', 'dns.quad9.net']
DNS_IPS = ['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '223.5.5.5',
           '119.29.29.29', '9.9.9.9', '149.112.112.112']
DNS_IPV6 = ['2606:4700:4700::1111', '2606:4700:4700::1001',
            '2001:4860:4860::8888', '2001:4860:4860::8844',
            '2400:3200::1', '2400:3200:baba::1']
TAILSCALE_CIDRS = ['100.64.0.0/10', 'fd7a:115c:a1e0::/48']
MAGIC_DNS_RULE = 'IP-CIDR,100.100.100.100/32,DIRECT,no-resolve'


def guarded_rules(original, tailscale=None):
    guards = ['DST-PORT,53,REJECT', 'DST-PORT,853,日常线路']
    if tailscale:
        # Only the local MagicDNS stub bypasses the plaintext DNS guard.
        guards.insert(0, MAGIC_DNS_RULE)
        guards += ['DOMAIN-SUFFIX,' + tailscale['magic_dns_suffix'] + ',DIRECT',
                   'IP-CIDR,' + TAILSCALE_CIDRS[0] + ',DIRECT,no-resolve',
                   'IP-CIDR6,' + TAILSCALE_CIDRS[1] + ',DIRECT,no-resolve']
    guards += ['DOMAIN-SUFFIX,'+d+',DIRECT' for d in REMOTE_CONTROL_DOMAINS]
    guards += ['DOMAIN-SUFFIX,'+d+',DIRECT' for d in FEISHU]
    guards += ['DOMAIN,'+d+',日常线路' for d in BUSINESS_CONSOLES]
    guards += ['DOMAIN,'+d+',DIRECT' for d in DOMESTIC_BUSINESS_HOSTS]
    guards += ['IP-CIDR,223.6.6.6/32,DIRECT,no-resolve']
    guards += ['DOMAIN,' + d + ',日常线路' for d in DNS_DOMAINS]
    guards += ['IP-CIDR,' + ip + '/32,日常线路,no-resolve' for ip in DNS_IPS]
    guards += ['IP-CIDR6,' + ip + '/128,日常线路,no-resolve' for ip in DNS_IPV6]
    # Remove old broad DNS exceptions, keeping application routing intact.
    managed = {r.split(',')[0] + ',' + r.split(',')[1] for r in guards}
    return guards + [r for r in original if ','.join(r.split(',')[:2]) not in managed]


def harden_config(original, client, hosts=None, tailscale=None):
    config = copy.deepcopy(original)
    config.setdefault('hosts', {}).update(host_map() if hosts is None else hosts)
    # Resolve only the final domestic IP fallback. Earlier IP rules intentionally
    # avoid DNS so explicit app/domain policies remain first and DNS cannot loop.
    config['rules'] = guarded_rules([
        'RULE-SET,国内IP,DIRECT' if r == 'RULE-SET,国内IP,DIRECT,no-resolve' else r
        for r in config['rules']], tailscale)
    dns = config['dns']
    dns['default-nameserver'] = list(BOOTSTRAP)
    dns.pop('fallback', None)
    dns.pop('fallback-filter', None)
    if client == 'clash':
        # Keep the plaintext DNS guard first; process rules cover pure IP and
        # changing relay addresses before generic UDP and foreign-IP fallbacks.
        config['rules'] = [r for r in config['rules'] if r != REMOTE_CONTROL_RULE]
        config['rules'].insert(config['rules'].index('DST-PORT,53,REJECT') + 1, REMOTE_CONTROL_RULE)
        if config.get('find-process-mode') not in ('strict', 'always'):
            config['find-process-mode'] = 'strict'
        dns['nameserver'] = [u + '#日常线路' for u in REMOTE]
        dns['proxy-server-nameserver'] = [u + '#DIRECT' for u in BOOTSTRAP]
        from ech import PUBLIC_NAME, DNS
        dns['proxy-server-nameserver-policy'] = {PUBLIC_NAME: [DNS+'#DIRECT']}
        dns.pop('direct-nameserver', None)
        dns.pop('direct-nameserver-follow-policy', None)
        dns['nameserver-policy'] = {**{'+.'+d:[u+'#日常线路' for u in REMOTE] for d in ['googleapis.cn','xn--ngstr-lra8j.com']}, **{'+.'+d:[LOCAL_DOH+'#DIRECT'] for d in FEISHU}, **{d:[u+'#日常线路' for u in REMOTE] for d in BUSINESS_CONSOLES}, '+.cn':[LOCAL_DOH+'#DIRECT'], 'rule-set:国内域名':[LOCAL_DOH+'#DIRECT']}
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
        dns['nameserver-policy'] = {**{'+.'+d:list(REMOTE) for d in ['googleapis.cn','xn--ngstr-lra8j.com']}, **{'+.'+d:[LOCAL_DOH] for d in FEISHU}, **{d:list(REMOTE) for d in BUSINESS_CONSOLES}, '+.cn':[LOCAL_DOH], 'geosite:cn':[LOCAL_DOH]}
        dns['follow-rule'] = True
    dns['nameserver-policy'].update({d: [LOCAL_DOH + ('#DIRECT' if client == 'clash' else '')]
                                    for d in DOMESTIC_BUSINESS_HOSTS})
    dns['nameserver-policy'].update({'+.'+d: [LOCAL_DOH + ('#DIRECT' if client == 'clash' else '')]
                                    for d in REMOTE_CONTROL_DOMAINS})
    if client == 'clash':
        dns['fake-ip-filter'] = list(dict.fromkeys(dns.get('fake-ip-filter', []) +
                                                 ['+.'+d for d in REMOTE_CONTROL_DOMAINS]))
    if tailscale:
        suffix = '+.' + tailscale['magic_dns_suffix']
        dns['nameserver-policy'][suffix] = ['100.100.100.100' + ('#DIRECT' if client == 'clash' else '')]
        dns['fake-ip-filter'] = list(dict.fromkeys(dns.get('fake-ip-filter', []) + [suffix]))
        if client == 'clash':
            tun['route-exclude-address'] = list(dict.fromkeys(tun.get('route-exclude-address', []) + TAILSCALE_CIDRS))
    return config


def harden_shadowrocket(original, hosts=None):
    node_hosts=host_map() if hosts is None else hosts
    remote = ', '.join(u + '#proxy' for u in REMOTE)
    replacements = {'dns-server': LOCAL_DOH, 'fallback-dns-server': LOCAL_DOH,
                    'proxy-dns-server': ', '.join(BOOTSTRAP), 'dns-direct-system': 'false',
                    'use-local-host-item-for-proxy': 'true'}
    result = original
    for key, value in replacements.items():
        result, count = re.subn(r'^' + re.escape(key) + r'\s*=.*$', key + ' = ' + value, result, flags=re.M)
        assert count == 1, 'Unexpected Shadowrocket setting: ' + key
    result = re.sub(r'^GEOIP,CN,DIRECT,no-resolve$', 'GEOIP,CN,DIRECT', result, flags=re.M)
    direct_set='DOMAIN-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/ChinaMax/ChinaMax_Domain.list,DIRECT'
    if direct_set not in result:result=result.replace('GEOIP,CN,DIRECT',direct_set+'\nGEOIP,CN,DIRECT')
    rule_start = result.index('[Rule]') + len('[Rule]')
    next_section = result.find('\n[', rule_start)
    rule_end = next_section if next_section >= 0 else len(result)
    rules = [s for s in result[rule_start:rule_end].splitlines() if s.strip()]
    result = result[:rule_start] + '\n' + '\n'.join(guarded_rules(rules)) + '\n' + result[rule_end:]
    host_section = '[Host]\n' + '\n'.join(k + ' = ' + v for k, v in node_hosts.items()) + '\n'
    if '[Host]' not in result:
        result += '\n' + host_section
    else:
        start = result.index('[Host]') + len('[Host]')
        end = result.find('\n[', start)
        end = end if end >= 0 else len(result)
        lines = [s for s in result[start:end].splitlines() if s.strip()
                 and s.split('=', 1)[0].strip() not in node_hosts]
        result = result[:start] + '\n' + ''.join(s + '\n' for s in lines) + host_section[len('[Host]\n'):] + result[end:]
    return result
