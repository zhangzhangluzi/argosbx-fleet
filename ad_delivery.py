"""Refresh ad rules in the two existing aggregates through the local Sub-Store API."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import copy
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
from urllib.parse import parse_qsl, urlsplit

import yaml

import ad_rules
from country_routes import AD_JOURNAL, store_ad_asset
from dns_policy import console_dns, console_routes, console_rules
import publication
from servers import check_profile, check_sr_ads, digest, get, request
from storage import lock, save


CONFIG = Path('/etc/argosbx-fleet/ad-publisher.json')
JOURNAL = CONFIG.with_name('ad-delivery-journal.json')
ONBOARDING = CONFIG.with_name('onboarding-publication.id')

def check_onboarding(path=None):
    path=ONBOARDING if path is None else Path(path)
    if path.exists() or path.is_symlink():raise ValueError('新机接入发布尚未完成，广告更新稍后重试')
PREFIXES = ('', 'external-seven-')
FORMATS = ('clash', 'stash', 'shadowrocket-config', 'shadowrocket-ads')
CLIENTS = (('clash', 'FlClash/0.8.99'), ('stash', 'Stash/3.6.0'), ('stash', 'Stash/3.4.0'))
SR = 'Shadowrocket/2.2.72'


def aggregates(settings):
    if 'aggregates' in settings:
        return settings['aggregates']
    values = [{'prefix': ''}]
    if settings.get('external_ads_url'):
        values.append({'prefix': 'external-seven-', 'ads_url': settings['external_ads_url']})
    return values


def read_config(path):
    if path.stat().st_mode & 0o077:
        raise ValueError('广告发布设置的权限必须为 0600')
    return validate_config(json.loads(path.read_text()))


def validate_config(settings):
    if not isinstance(settings, dict):
        raise ValueError('广告发布设置格式无效')
    origin = urlsplit(settings['backend_url'])
    if (origin.scheme != 'https' or not origin.hostname or origin.username is not None or origin.query or origin.fragment
            or not re.fullmatch(r'/[A-Za-z0-9_-]+', origin.path)
            or not Path(settings['mihomo']).is_absolute()):
        raise ValueError('广告发布设置与现有订阅入口不匹配')
    scopes = aggregates(settings)
    if not isinstance(scopes, list) or not scopes:
        raise ValueError('广告发布范围无效')
    prefixes = []
    for scope in scopes:
        if not isinstance(scope, dict) or set(scope) - {'prefix', 'ads_url'}:
            raise ValueError('广告发布范围格式无效')
        prefix = scope.get('prefix')
        if not isinstance(prefix, str) or (prefix and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,47}-', prefix)):
            raise ValueError('广告发布范围前缀无效')
        prefixes.append(prefix)
        if not prefix:
            if 'ads_url' in scope:
                raise ValueError('原统一订阅广告地址由后端自动生成')
            continue
        ads = urlsplit(scope.get('ads_url', ''))
        tokens = [v for k, v in parse_qsl(ads.query, keep_blank_values=True) if k == 'token']
        if ((ads.scheme, ads.netloc, ads.path) != ('https', origin.netloc, '/share/file/' + prefix + 'shadowrocket-ads')
                or ads.username is not None or ads.fragment or len(tokens) != 1 or not tokens[0]):
            raise ValueError('广告分享地址与发布范围不匹配')
    if '' not in prefixes or len(prefixes) != len(set(prefixes)) or len(prefixes) > 12:
        raise ValueError('广告发布范围缺少原统一订阅或重复')
    labels = ['native' if not p else 'external' if p == 'external-seven-' else p[:-1] for p in prefixes]
    if len(labels) != len(set(labels)):
        raise ValueError('广告发布范围名称冲突')
    return settings


def api_config(settings):
    prefix = urlsplit(settings['backend_url']).path
    return {'subscription': {'backend_url': 'http://127.0.0.1:3001' + prefix}}


def asset_config(settings):
    return {'subscription': {'backend_url': settings['backend_url']}}


def check_asset(settings, snapshot):
    url = ad_rules.asset_url(asset_config(settings), snapshot)
    address = urlsplit(url)
    origin = f'{address.hostname}:{address.port or 443}:127.0.0.1'
    body = subprocess.check_output(['curl', '-fsS', '--max-time', '12', '--resolve', origin, url], timeout=14)
    if ad_rules.sha(body) != snapshot['mrs_sha256']:
        raise ValueError('Caddy 返回的广告 MRS 校验失败')


def replace_exceptions(rules, previous, desired, ad_rule):
    if rules.count(ad_rule) != 1:
        raise ValueError('广告规则位置不唯一')
    anchor = rules.index(ad_rule)
    old_or_new = set(console_rules(previous) + console_rules(desired))
    removed = set()
    for index, rule in enumerate(rules):
        kind, _, tail = rule.partition(',')
        host = tail.split(',', 1)[0]
        if kind == 'DOMAIN' and (host in previous or host in desired):
            if rule not in old_or_new:
                raise ValueError('后台域名已有独立路由：' + host)
            anchor = min(anchor, index)
            removed.add(index)
    filtered = [rule for index, rule in enumerate(rules) if index not in removed]
    return filtered[:anchor] + console_rules(desired) + filtered[anchor:]


def replace_dns(policy, client, previous, desired):
    old, new = console_dns(client, previous), console_dns(client, desired)
    for host in dict.fromkeys((*old, *new)):
        if host in policy and policy[host] not in (old.get(host), new.get(host)):
            raise ValueError('后台域名已有独立 DNS 策略：' + host)
        if host in new:
            policy[host] = new[host]
        else:
            policy.pop(host, None)


def patch_literal(script, marker, update):
    if script.count(marker) != 1:
        raise ValueError('订阅模板结构已改变')
    offset = script.index(marker) + len(marker)
    value, size = json.JSONDecoder().raw_decode(script[offset:])
    return script[:offset] + json.dumps(update(value), ensure_ascii=False) + script[offset+size:]


def ads_url(settings, prefix):
    if not prefix:
        return settings['backend_url'] + '/api/file/shadowrocket-ads'
    return next(scope['ads_url'] for scope in aggregates(settings) if scope['prefix'] == prefix)


def candidate(before, settings, previous, desired, snapshot, prefix, fmt):
    value = copy.deepcopy(before)
    if fmt == 'shadowrocket-ads':
        value.update(ad_rules.file_object(value['name'], value['displayName'], snapshot))
        return value

    def update_shadowrocket(content):
        begin = content.index('[Rule]\n') + len('[Rule]\n')
        end = content.find('\n[', begin)
        end = len(content) if end < 0 else end
        rules = content[begin:end]
        anchor = 'DOMAIN-SET,' + ads_url(settings, prefix) + ',REJECT'
        replaced = '\n'.join(replace_exceptions(rules.splitlines(), previous, desired, anchor))
        return content[:begin] + replaced + ('\n' if rules.endswith('\n') else '') + content[end:]

    if fmt == 'shadowrocket-config' and not prefix:
        value['content'] = update_shadowrocket(value['content'])
        return value

    operator = value['process'][0]
    if operator['type'] != 'Script Operator':
        raise ValueError('订阅模板处理器类型已改变')
    args = operator['args']

    def update_profile(profile):
        profile['rules'] = replace_exceptions(profile['rules'], previous, desired, ad_rules.AD_RULE)
        replace_dns(profile['dns']['nameserver-policy'], fmt, previous, desired)
        ad_rules.use_provider(profile, asset_config(settings), snapshot)
        return profile

    marker, update = (('input.$content=', update_shadowrocket) if fmt == 'shadowrocket-config'
                      else ('const config=', update_profile))
    args['content'] = patch_literal(args['content'], marker, update)
    return value


def verify_scope(settings, api, snapshot, prefix, names):
    def read(fmt, ua):
        name = names.get(prefix + fmt, prefix + fmt)
        return request(api, '/api/file/' + name, raw=True, user_agent=ua)

    domains = read('shadowrocket-ads', SR)
    check_sr_ads(domains)
    if domains != snapshot['domains']:
        raise ValueError('Shadowrocket 广告名单与发布版本不同')
    sr = read('shadowrocket-config', SR)
    url = ads_url(settings, prefix)
    ad_rules.check_shadowrocket(sr, domains, url)
    sr_rules = sr.split('[Rule]', 1)[1].split('\n[', 1)[0].splitlines()
    check_blocks(sr_rules, 'DOMAIN-SET,' + url + ',REJECT', domains)
    ad_rules.check_console_samples(sr_rules, 'DOMAIN-SET,' + url + ',REJECT', domains)
    profiles = {}
    for fmt, ua in CLIENTS:
        profile = yaml.safe_load(read(fmt, ua))
        check_profile(profile)
        ad_rules.check_profile(profile, fmt)
        check_blocks(profile['rules'], ad_rules.AD_RULE, domains)
        ad_rules.check_console_samples(profile['rules'], ad_rules.AD_RULE, domains)
        provider = profile['rule-providers']['广告域名']
        if provider['url'] != ad_rules.asset_url(asset_config(settings), snapshot):
            raise ValueError('客户端引用的广告 MRS 版本不同')
        profiles[ua] = len(profile['proxies'])
    return profiles


def check_blocks(rules, marker, domains):
    earlier = rules[:rules.index(marker)]
    entries = set(domains.splitlines())
    if any(not ad_rules.matches(host, entries) or ad_rules.first_domain_target(earlier, host)
           for host in ad_rules.BLOCK_SAMPLES):
        raise ValueError('关键广告或采集域名的拦截样本不通过')


def verify(settings, api, snapshot, names=None):
    check_asset(settings, snapshot)
    scopes = aggregates(settings)
    with ThreadPoolExecutor(max_workers=2) as pool:
        checks = [pool.submit(verify_scope, settings, api, snapshot, scope['prefix'], names or {}) for scope in scopes]
        labels = ['native' if not s['prefix'] else 'external' if s['prefix'] == 'external-seven-' else s['prefix'][:-1] for s in scopes]
        if len(labels) != len(set(labels)):
            raise ValueError('广告发布范围名称冲突')
        return dict(zip(labels, (check.result() for check in checks)))


def read_state(raw):
    state = json.loads(raw)
    ad_rules.validate(state['snapshot'])
    routes = state['console_routes']
    if not routes or any(not re.fullmatch(ad_rules.DOMAIN, host) or target not in ('DIRECT', '日常线路')
                         for host, target in routes.items()):
        raise ValueError('上一次发布的广告例外无效')
    return state


def publish(settings, api, previous, desired, snapshot, active_file):
    items = []
    for scope in aggregates(settings):
        prefix = scope['prefix']
        for fmt in FORMATS:
            name = prefix + fmt
            before = get(api, 'file', name)
            if before is None:
                raise ValueError('原订阅文件缺失：' + name)
            after = candidate(before, settings, previous, desired, snapshot, prefix, fmt)
            items.append({'kind': 'file', 'name': name, 'before': before, 'after': after})

    name = ad_rules.STATE_FILE
    state = json.dumps({'snapshot': snapshot, 'console_routes': desired}, ensure_ascii=False)
    items.append({'kind': 'file', 'name': name, 'before': active_file,
                  'after': {**(active_file or {}), 'name': name, 'displayName': '广告规则发布状态',
                            'source': 'local', 'content': state, 'process': []}})
    store_ad_asset(snapshot)
    journal = publication.begin(JOURNAL, api, digest)
    aliases = {}
    try:
        for item in items[:-1]:
            alias = 'server-check-ad-' + secrets.token_hex(6)
            aliases[item['name']] = alias
            journal['temporary'].append(['file', alias])
            save(JOURNAL, journal)
            request(api, '/api/files', {**item['after'], 'name': alias}, 'POST')
        verify(settings, api, snapshot, aliases)
        publication.cleanup(JOURNAL, journal, api, request)
        for item in items:
            name, before, after = (item[key] for key in ('name', 'before', 'after'))
            if get(api, 'file', name) != before:
                raise ValueError('发布期间文件发生变化：' + name)
            if before == after:
                continue
            journal['attempted'].append(item)
            save(JOURNAL, journal)
            path, method = ('/api/files', 'POST') if before is None else ('/api/file/' + name, 'PATCH')
            request(api, path, after, method)
            if get(api, 'file', name) != after:
                raise ValueError('发布回读不一致：' + name)
        result = verify(settings, api, snapshot)
    except Exception:
        publication.recover(JOURNAL, api, get, request, digest)
        raise
    JOURNAL.unlink()
    return result


def refresh(settings, seed=None, verify_only=False, progress=None):
    def phase(name):
        if progress:
            progress(name)

    api = api_config(settings)
    phase('recovery')
    if AD_JOURNAL.exists():
        raise ValueError('Caddy 广告规则路由有未完成事务')
    if verify_only and JOURNAL.exists():
        raise ValueError('广告发布有待恢复事务')
    publication.recover(JOURNAL, api, get, request, digest)
    active = get(api, 'file', ad_rules.STATE_FILE)
    if active is None and seed is None:
        raise ValueError('缺少首次发布使用的现行名单')
    previous = read_state(active['content'] if active else seed)
    desired = console_routes()
    current = previous['snapshot']
    if verify_only:
        if active is None or previous['console_routes'] != desired:
            raise ValueError('线上广告例外与维护代码不同')
        phase('console-verification')
        return {'verified': True, 'domains': current['domain_count'], 'profiles': verify(settings, api, current)}
    phase('upstream-download')
    snapshot = ad_rules.refresh(current, settings['mihomo'])
    result = {'changed': False, 'domains': snapshot['domain_count'], 'revision': snapshot['revision'],
              'mrs_sha256': snapshot['mrs_sha256']}
    if active and snapshot == current and previous['console_routes'] == desired:
        phase('console-verification')
        profiles = verify(settings, api, snapshot)
        return {**result, 'profiles': profiles}
    phase('publication')
    profiles = publish(settings, api, previous['console_routes'], desired, snapshot, active)
    return {**result, 'changed': True, 'profiles': profiles}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='刷新现有聚合订阅的广告规则')
    parser.add_argument('action', choices=('refresh', 'verify', 'initialize'))
    parser.add_argument('--config', type=Path, default=CONFIG)
    args = parser.parse_args()
    try:
        with lock('/run/argosbx-publisher.lock'):
            check_onboarding()
            settings = read_config(args.config)
            seed = sys.stdin.read(ad_rules.MAX_BYTES) if args.action == 'initialize' else None
            result = refresh(settings, seed, verify_only=args.action == 'verify')
        print(json.dumps(result, ensure_ascii=False))
    except Exception as error:
        message = str(error) if isinstance(error, ValueError) else type(error).__name__
        print('广告规则维护失败，' + message, file=sys.stderr)
        raise SystemExit(1)
