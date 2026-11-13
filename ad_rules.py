"""Fetch and validate the two formats of one upstream ad-list revision."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
import urllib.error
import urllib.request
import urllib.error

from storage import save


REPOSITORY = 'https://api.github.com/repos/MetaCubeX/meta-rules-dat'
FILE = REPOSITORY + '/contents/geo/geosite/category-ads-all'
MAX_BYTES = 1024 * 1024
DOMAIN = r'[a-z0-9_-]+(?:\.[a-z0-9_-]+)+'
MRS_MAGIC = bytes.fromhex('28b52ffd')
REF = r'[0-9a-f]{40}'
MANAGED_SNAPSHOT = '@sub-store'
STATE_FILE = 'fleet-ad-state'
# Exact ad-delivery and SDK hosts selected from AWAvenue Only.Ads v1.7.8.
EXTRA_ADS = ('ads-video-al.xhscdn.com', 'ads-video-qc.xhscdn.com', 'adsdk.vivo.com.cn')
BLOCK_SAMPLES = ('ms.applovin.com', 'probe.r.applovin.com', 'googleads.g.doubleclick.net',
                 'www.google-analytics.com', 'pixel.facebook.com', 'analytics.tiktok.com',
                 'api.appsflyersdk.com', *EXTRA_ADS)
AD_RULE = 'RULE-SET,广告域名,去广告'
# Public login, reporting, API and required UI hosts audited for these platforms.
# A newly blocked host stops publication until a narrow exception is reviewed.
CONSOLE_SAMPLES = (
    'adsmanager.facebook.com', 'business.facebook.com', 'www.facebook.com',
    'accountscenter.facebook.com', 'graph.facebook.com', 'static.facebook.com',
    'ads.google.com', 'accounts.google.com', 'googleads.googleapis.com',
    'www.gstatic.com', 'ssl.gstatic.com', 'ads.tiktok.com',
    'business.tiktok.com', 'accounts.tiktok.com', 'business-api.tiktok.com',
    'lf-tt4b.tiktokcdn.com', 'sf16-website-login.neutral.ttwstatic.com',
    'ads.applovin.com', 'ads.axon.ai', 'api.ads.axon.ai', 'max.applovin.com',
    'dash.applovin.com', 'r.applovin.com', 'www.recaptcha.net',
    'hq1.appsflyer.com', 'cdn.appsflyer.com',
    '86c17a2d2df0.edge.sdk.awswaf.com',
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def get(url, accept):
    request = urllib.request.Request(url, headers={'Accept': accept, 'User-Agent': 'argosbx-fleet-rules'})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                body = response.read(MAX_BYTES + 1)
            break
        except urllib.error.HTTPError as error:
            error.close()
            if error.code not in (408, 429, 500, 502, 503, 504) or attempt == 2:
                raise
            reason = 'HTTP-' + str(error.code)
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == 2:
                raise
            reason = 'network'
        print(json.dumps({'event': 'ad-fetch-retry', 'attempt': attempt + 1, 'reason': reason}), file=sys.stderr)
        time.sleep(attempt + 1)
    if not body or len(body) > MAX_BYTES:
        raise ValueError('广告名单为空或超出大小限制')
    return body


def convert(text):
    entries = []
    for line in text.splitlines():
        value = line.strip().lower()
        if not value or value.startswith('#'):
            continue
        if not re.fullmatch(r'(?:\+\.)?' + DOMAIN, value):
            raise ValueError('上游广告名单包含不支持的条目')
        entries.append(value[1:] if value.startswith('+.') else value)
    if not entries:
        raise ValueError('上游广告名单没有可用条目')
    return '\n'.join(dict.fromkeys(entries)) + '\n'


def upstream_domains():
    revision = json.loads(get(REPOSITORY + '/commits/meta', 'application/vnd.github+json'))['sha']
    if not re.fullmatch(REF, revision):
        raise ValueError('上游版本标识无效')
    return revision, convert(get(FILE + '.list?ref=' + revision, 'application/vnd.github.raw+json').decode('utf-8'))


def fetch(node='node'):
    revision, domains = upstream_domains()
    mrs = get(FILE + '.mrs?ref=' + revision, 'application/vnd.github.raw+json')
    # Node is already used by the subscription publisher. Bound decompression
    # and check the documented MRS v1 header and domain record count.
    inspect = '''
const fs = require('node:fs');
const zlib = require('node:zlib');
const body = zlib.zstdDecompressSync(fs.readFileSync(0), {maxOutputLength: 1048576});
if (body.length < 22 || body.subarray(0, 5).toString('hex') !== '4d52530100') process.exit(2);
process.stdout.write(String(body.readBigInt64BE(5)));
'''
    result = subprocess.run([node, '-e', inspect], input=mrs, capture_output=True, timeout=10)
    count = len(domains.splitlines())
    if result.returncode or result.stdout != str(count).encode():
        raise ValueError('MRS 类型或条目数与域名名单不一致')
    return snapshot(revision, domains, mrs)


def snapshot(revision, domains, mrs):
    return validate({'revision': revision, 'domains': domains, 'domain_count': len(domains.splitlines()),
                     'domains_sha256': sha(domains.encode()), 'mrs_sha256': sha(mrs),
                     'mrs': base64.b64encode(mrs).decode()})


def matches(host, entries):
    labels = host.split('.')
    return host in entries or any('.' + '.'.join(labels[i:]) in entries for i in range(len(labels)-1))


def compile_snapshot(revision, domains, mihomo):
    # Convert the same normalized exact and suffix rules exported to Shadowrocket.
    with tempfile.TemporaryDirectory(prefix='argosbx-ad-') as directory:
        source = Path(directory)/'domains.txt'
        target = source.with_suffix('.mrs')
        source.write_text(''.join(('+' if row.startswith('.') else '') + row + '\n'
                                  for row in domains.splitlines()))
        subprocess.run([str(mihomo), 'convert-ruleset', 'domain', 'text', str(source), str(target)],
                       check=True, capture_output=True, timeout=30)
        return snapshot(revision, domains, target.read_bytes())


def refresh(previous, mihomo):
    revision, text = upstream_domains()
    entries = set(text.splitlines())
    entries.update(host for host in EXTRA_ADS if not matches(host, entries))
    if not all(matches(host, entries) for host in BLOCK_SAMPLES):
        raise ValueError('广告名单缺少关键拦截样本，保留当前版本')
    old = set(previous['domains'].splitlines())
    if entries == old:
        return previous
    if len(entries ^ old) > max(20, len(old) // 5):
        raise ValueError('广告名单变动超过验收范围，保留当前版本')
    return compile_snapshot(revision, '\n'.join(sorted(entries)) + '\n', mihomo)


def validate(snapshot):
    if not re.fullmatch(REF, snapshot['revision']):
        raise ValueError('广告快照版本无效')
    domains = snapshot['domains']
    rows = domains.splitlines()
    if (not rows or len(domains.encode()) > MAX_BYTES or len(set(rows)) != len(rows)
            or any(not re.fullmatch(r'\.?' + DOMAIN, row) for row in rows)
            or len(rows) != snapshot['domain_count']
            or sha(domains.encode()) != snapshot['domains_sha256']):
        raise ValueError('广告快照的文本名单校验失败')
    mrs = base64.b64decode(snapshot['mrs'], validate=True)
    if len(mrs) > MAX_BYTES or not mrs.startswith(MRS_MAGIC) or sha(mrs) != snapshot['mrs_sha256']:
        raise ValueError('广告快照的 MRS 文件校验失败')
    return snapshot


def load(config):
    path = config['subscription'].get('ad_rules_snapshot')
    if path == MANAGED_SNAPSHOT:
        from dns_policy import console_routes
        import backend_transport
        url = config['subscription']['backend_url'].rstrip('/') + '/api/file/' + STATE_FILE
        data = (backend_transport.request(config,'/api/file/'+STATE_FILE,raw=True).encode()
                if backend_transport.active(config) else get(url, 'application/json'))
        state = json.loads(data)
        if state['console_routes'] != console_routes():
            raise ValueError('广告例外与订阅服务器版本不同，请先同步维护代码')
        return validate(state['snapshot'])
    if path:
        from fleet import resolve_path
        return validate(json.loads(resolve_path(path,config).read_text()))
    return None


def asset_name(snapshot):
    return 'ads-' + snapshot['mrs_sha256'] + '.mrs'


def asset_url(config, snapshot):
    origin = urlsplit(config['subscription']['backend_url'])
    return origin.scheme + '://' + origin.netloc + '/rules/ad/' + asset_name(snapshot)


def verify_asset(config, snapshot):
    # get() already bounds transient network retries; do not multiply them.
    body = get(asset_url(config, snapshot), 'application/octet-stream')
    if sha(body) != snapshot['mrs_sha256']:
        raise ValueError('已发布的广告 MRS 与候选快照不同')


def use_provider(profile, config, snapshot):
    provider = profile['rule-providers']['广告域名']
    provider['url'] = asset_url(config, snapshot)
    provider['path'] = './rules/' + asset_name(snapshot)


def file_object(name, title, snapshot):
    return {'name': name, 'displayName': title, 'source': 'local',
            'content': snapshot['domains'], 'process': []}


def first_domain_target(rules, host):
    for rule in rules:
        kind, _, tail = rule.partition(',')
        value, _, target = tail.partition(',')
        if ((kind == 'DOMAIN' and value == host)
                or (kind == 'DOMAIN-SUFFIX' and (host == value or host.endswith('.' + value)))
                or (kind == 'DOMAIN-KEYWORD' and value in host)):
            return target
    return None


def check_exceptions(rules, ad):
    from dns_policy import console_routes
    for host, route in console_routes().items():
        if f'DOMAIN,{host},{route}' not in rules[:ad] or first_domain_target(rules[:ad], host) != route:
            raise ValueError('投放后台例外缺失或被前置规则覆盖：' + host)


def check_console_samples(rules, marker, domains):
    earlier = rules[:rules.index(marker)]
    entries = set(domains.splitlines())
    for host in CONSOLE_SAMPLES:
        target = first_domain_target(earlier, host)
        if target in ('REJECT', 'REJECT-DROP', '去广告', '开启去广告') or (target is None and matches(host, entries)):
            raise ValueError('投放后台可能被广告规则拦截：' + host)


def check_profile(value, client):
    from dns_policy import console_dns, console_routes
    provider = value['rule-providers']['广告域名']
    if (provider.get('behavior'), provider.get('format')) != ('domain', 'mrs'):
        raise ValueError('广告规则集格式不符')
    rules = value['rules']
    ad = rules.index(AD_RULE)
    check_exceptions(rules, ad)
    policy = value['dns']['nameserver-policy']
    if any(policy.get(host) != dns for host, dns in console_dns(client, console_routes()).items()):
        raise ValueError('投放后台 DNS 策略不匹配')
    groups = {group['name']: group['proxies'] for group in value['proxy-groups']}
    if (groups.get('去广告') != ['开启去广告', '关闭去广告']
            or groups.get('开启去广告') != ['REJECT']
            or groups.get('关闭去广告') != ['PASS' if client == 'clash' else '日常线路']):
        raise ValueError('去广告开关行为与客户端配置不符')


def check_shadowrocket(config, domains, ads_url):
    rules = config.split('[Rule]', 1)[1].split('\n[', 1)[0].splitlines()
    ad = rules.index('DOMAIN-SET,' + ads_url + ',REJECT')
    check_exceptions(rules, ad)
    entries = set(domains.splitlines())
    if '.doubleclick.net' not in entries or '.applovin.com' not in entries:
        raise ValueError('广告名单缺少关键拦截样本，需重新核对上游内容')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='生成同一版本的广告规则候选快照')
    parser.add_argument('output', type=Path)
    parser.add_argument('--node', default='node')
    args = parser.parse_args()
    candidate = validate(fetch(args.node))
    save(args.output, candidate)
    print(json.dumps({key: candidate[key] for key in ('revision', 'domain_count', 'mrs_sha256')}))
