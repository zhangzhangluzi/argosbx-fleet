"""Fetch and validate the two formats of one upstream ad-list revision."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit
import urllib.request

from storage import save


REPOSITORY = 'https://api.github.com/repos/MetaCubeX/meta-rules-dat'
FILE = REPOSITORY + '/contents/geo/geosite/category-ads-all'
MAX_BYTES = 1024 * 1024
DOMAIN = r'[a-z0-9_-]+(?:\.[a-z0-9_-]+)+'
MRS_MAGIC = bytes.fromhex('28b52ffd')
REF = r'[0-9a-f]{40}'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def get(url, accept):
    request = urllib.request.Request(url, headers={'Accept': accept, 'User-Agent': 'argosbx-fleet-rules'})
    with urllib.request.urlopen(request, timeout=15) as response:
        body = response.read(MAX_BYTES + 1)
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


def fetch(node='node'):
    revision = json.loads(get(REPOSITORY + '/commits/meta', 'application/vnd.github+json'))['sha']
    if not re.fullmatch(REF, revision):
        raise ValueError('上游版本标识无效')
    suffix = '?ref=' + revision
    media = 'application/vnd.github.raw+json'
    domains = convert(get(FILE + '.list' + suffix, media).decode('utf-8'))
    mrs = get(FILE + '.mrs' + suffix, media)
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
    return {'revision': revision, 'domains': domains, 'domain_count': count,
            'domains_sha256': sha(domains.encode()), 'mrs_sha256': sha(mrs),
            'mrs': base64.b64encode(mrs).decode()}


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
    if path:
        from fleet import resolve_path
        return validate(json.loads(resolve_path(path).read_text()))
    return None


def asset_name(snapshot):
    return 'ads-' + snapshot['mrs_sha256'] + '.mrs'


def asset_url(config, snapshot):
    origin = urlsplit(config['subscription']['backend_url'])
    return origin.scheme + '://' + origin.netloc + '/rules/ad/' + asset_name(snapshot)


def verify_asset(config, snapshot):
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


def check_profile(value, client):
    from dns_policy import BUSINESS_CONSOLES, DOMESTIC_BUSINESS_HOSTS
    provider = value['rule-providers']['广告域名']
    if (provider.get('behavior'), provider.get('format')) != ('domain', 'mrs'):
        raise ValueError('广告规则集格式不符')
    rules = value['rules']
    ad = rules.index('RULE-SET,广告域名,去广告')
    policy = value['dns']['nameserver-policy']
    for hosts, target in ((BUSINESS_CONSOLES, '日常线路'), (DOMESTIC_BUSINESS_HOSTS, 'DIRECT')):
        if any('DOMAIN,' + host + ',' + target not in rules[:ad] or host not in policy for host in hosts):
            raise ValueError('投放后台例外或 DNS 策略缺失')
    groups = {group['name']: group['proxies'] for group in value['proxy-groups']}
    if (groups.get('去广告') != ['开启去广告', '关闭去广告']
            or groups.get('开启去广告') != ['REJECT']
            or groups.get('关闭去广告') != ['PASS' if client == 'clash' else '日常线路']):
        raise ValueError('去广告开关行为与客户端配置不符')


def check_shadowrocket(config, domains, ads_url):
    from dns_policy import BUSINESS_CONSOLES, DOMESTIC_BUSINESS_HOSTS
    rules = config.split('[Rule]', 1)[1].split('\n[', 1)[0].splitlines()
    ad = rules.index('DOMAIN-SET,' + ads_url + ',REJECT')
    for hosts, target in ((BUSINESS_CONSOLES, '日常线路'), (DOMESTIC_BUSINESS_HOSTS, 'DIRECT')):
        if any('DOMAIN,' + host + ',' + target not in rules[:ad] for host in hosts):
            raise ValueError('Shadowrocket 投放后台例外缺失或顺序错误')
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
