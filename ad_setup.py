"""Initialize managed ad updates on an existing Sub-Store publisher."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from urllib.parse import urlencode, urlsplit, urlunsplit

import ad_delivery
import ad_rules
import country_routes
import publication
from dns_policy import console_routes
from servers import digest, get, request
from storage import atomic, lock, save

ROOT = Path(__file__).resolve().parent
INSTALL_ROOT = Path('/opt/argosbx-fleet')
UNIT_DIR = Path('/etc/systemd/system')
CONFIG = ad_delivery.CONFIG
LOCK = Path('/run/argosbx-publisher.lock')
DEFAULT_COMPILER = INSTALL_ROOT/'tools/mihomo-1.19.33'
CADDY_MAIN = Path('/etc/caddy-sub/Caddyfile')
CADDY_INCLUDE = Path('/etc/caddy-sub/argosbx.caddy')
UNITS = ('argosbx-ad-refresh.service', 'argosbx-ad-refresh.timer', 'argosbx-ad-alert@.service')
BUILDS = {
    'x86_64': ('mihomo-linux-amd64-compatible-v1.19.33.gz', 663189170, 22893972,
               '386508bfb1c72c43b6a0eda73708ecdce82546581b0ebcb16366c53757c622b6'),
    'aarch64': ('mihomo-linux-arm64-v1.19.33.gz', 663189164, 20824326,
                'ba408b317080ee265c46cb923a50018c1b82cbd708551cdd46a1e3e307396187'),
}


def check_compiler(path):
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError('Mihomo 规则工具不可执行')
    result = subprocess.run([str(path), '-v'], capture_output=True, text=True, timeout=10)
    if result.returncode or not any(word in result.stdout.lower() for word in ('mihomo', 'meta')):
        raise ValueError('规则工具版本无法确认')


def install_compiler(path=DEFAULT_COMPILER):
    path = Path(path)
    if path.exists():
        check_compiler(path)
        return path
    if path != DEFAULT_COMPILER:
        raise ValueError('指定的规则工具不存在')
    build = BUILDS.get(platform.machine())
    if not build:
        raise ValueError('规则工具仅支持 amd64 / arm64')
    name, asset_id, size, expected = build
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    urls = [f'https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/{name}',
            f'https://api.github.com/repos/MetaCubeX/mihomo/releases/assets/{asset_id}']
    with tempfile.TemporaryDirectory(prefix='.mihomo-', dir=path.parent) as directory:
        archive = Path(directory)/'asset.gz'
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={'Accept': 'application/octet-stream',
                                                            'User-Agent': 'argosbx-fleet-setup'})
                with urllib.request.urlopen(req, timeout=35) as source, archive.open('wb') as target:
                    total = 0
                    sha = hashlib.sha256()
                    while True:
                        block = source.read(1024*1024)
                        if not block:
                            break
                        total += len(block)
                        if total > size:
                            raise ValueError('规则工具发布包大小异常')
                        sha.update(block)
                        target.write(block)
                if total == size and sha.hexdigest() == expected:
                    break
            except (OSError, TimeoutError, ValueError):
                pass
        else:
            raise ValueError('Mihomo 官方发布包下载或校验失败')
        candidate = Path(directory)/'mihomo'
        with gzip.open(archive, 'rb') as source, candidate.open('wb') as target:
            total = 0
            while True:
                block = source.read(1024*1024)
                if not block:
                    break
                total += len(block)
                if total > 128*1024*1024:
                    raise ValueError('Mihomo 解压后大小异常')
                target.write(block)
            target.flush()
            os.fsync(target.fileno())
        candidate.chmod(0o755)
        check_compiler(candidate)
        if path.exists():
            raise ValueError('规则工具在安装期间发生变化')
        os.replace(candidate, path)
    return path


def available_prefixes(api):
    names = publication.temporary_names(api, 'file', request)
    required = set(ad_delivery.FORMATS)
    if not required <= names:
        raise ValueError('原统一订阅的广告文件不完整')
    discovered = {''}
    for name in names:
        if name.endswith('-shadowrocket-config'):
            prefix = name.removesuffix('shadowrocket-config')
            if all(prefix + fmt in names for fmt in ad_delivery.FORMATS):
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,47}-', prefix):
                    raise ValueError('已发现无法识别的聚合文件前缀')
                discovered.add(prefix)
    return discovered


def discover(settings, api):
    discovered = available_prefixes(api)
    configured = {item['prefix'] for item in ad_delivery.aggregates(settings)}
    if configured != discovered:
        raise ValueError('聚合文件与广告分享配置不一致，请检查各聚合分享地址')
    return sorted(discovered)


def initial_settings(spec):
    if not isinstance(spec, dict) or not spec.get('backend_url'):
        raise ValueError('首次接入需要私有后端地址')
    shares = spec.get('shares', {})
    if not isinstance(shares, dict):
        raise ValueError('聚合分享设置无效')
    settings = {'backend_url': spec['backend_url'], 'mihomo': spec.get('mihomo', str(DEFAULT_COMPILER))}
    ad_delivery.validate_config(settings)
    api = ad_delivery.api_config(settings)
    prefixes = available_prefixes(api)
    if set(shares) - prefixes or '' in shares:
        raise ValueError('提供的聚合分享与已发现的文件不匹配')
    origin = urlsplit(settings['backend_url'])
    scopes = [{'prefix': ''}]
    for prefix in sorted(prefixes - {''}):
        url = shares.get(prefix)
        if not url:
            query = urlencode({'type': 'file', 'name': prefix + 'shadowrocket-ads'})
            tokens = request(api, '/api/tokens?' + query)
            if not isinstance(tokens, list):
                raise ValueError('聚合广告分享凭据响应无效')
            values = [x['token'] for x in tokens if isinstance(x, dict) and isinstance(x.get('token'), str) and x['token']]
            if len(values) != 1:
                raise ValueError('聚合广告分享凭据不唯一，请在私有输入中指定')
            url = urlunsplit((origin.scheme, origin.netloc, '/share/file/' + prefix + 'shadowrocket-ads',
                              urlencode({'token': values[0]}), ''))
        scopes.append({'prefix': prefix, 'ads_url': url})
    settings['aggregates'] = scopes
    return ad_delivery.validate_config(settings)


def candidate_snapshot(compiler):
    revision, domains = ad_rules.upstream_domains()
    entries = set(domains.splitlines())
    entries.update(host for host in ad_rules.EXTRA_ADS if not ad_rules.matches(host, entries))
    if not all(ad_rules.matches(host, entries) for host in ad_rules.BLOCK_SAMPLES):
        raise ValueError('上游广告名单未通过拦截样本检查')
    return ad_rules.compile_snapshot(revision, '\n'.join(sorted(entries)) + '\n', compiler)


def wait_asset(settings, snapshot):
    for attempt in range(5):
        try:
            ad_delivery.check_asset(settings, snapshot)
            return
        except Exception:
            if attempt == 4:
                raise
            time.sleep(0.4 * (attempt + 1))


def install_units():
    sources = {name: (ROOT/'systemd'/name).read_bytes() for name in UNITS}
    before = {}
    for name, body in sources.items():
        path = UNIT_DIR/name
        if path.is_symlink():
            raise ValueError('广告定时任务文件不能是符号链接')
        old = path.read_bytes() if path.exists() else None
        if old is not None and old != body:
            known = any(p.is_file() and p.read_bytes() == old for p in INSTALL_ROOT.glob('v*/systemd/' + name))
            if not known:
                raise ValueError('广告定时任务有自定义修改，保留原文件')
        before[name] = (old, path.stat().st_mode & 0o777 if old is not None else 0o644)
    for name in UNITS:
        result = subprocess.run(['systemctl', 'show', name, '-p', 'DropInPaths', '--value'],
                                text=True, capture_output=True)
        if result.returncode and before[name][0] is not None:
            raise ValueError('无法确认现有广告定时任务')
        if result.stdout.strip():
            raise ValueError('广告定时任务存在自定义覆盖，需先核对')
    subprocess.run(['systemd-analyze', 'verify', *[str(ROOT/'systemd'/n) for n in UNITS]],
                   capture_output=True, check=True)
    changed = []
    try:
        for name, body in sources.items():
            path = UNIT_DIR/name
            if (path.read_bytes() if path.exists() else None) != before[name][0]:
                raise ValueError('广告定时任务安装期间发生变化')
            if before[name][0] != body:
                atomic(path, body, 0o644)
                changed.append(name)
        if changed:
            subprocess.run(['systemctl', 'daemon-reload'], check=True, capture_output=True)
        effective = subprocess.check_output(['systemctl', 'show', 'argosbx-ad-refresh.service',
                                             '-p', 'ExecStart', '-p', 'OnFailure'], text=True)
        if 'ad_monitor.py run' not in effective or 'argosbx-ad-alert@' not in effective:
            raise ValueError('广告定时任务生效配置不匹配')
    except Exception:
        for name in reversed(changed):
            old, mode = before[name]
            if old is None:
                (UNIT_DIR/name).unlink(missing_ok=True)
            else:
                atomic(UNIT_DIR/name, old, mode)
        if changed:
            subprocess.run(['systemctl', 'daemon-reload'], check=True, capture_output=True)
        raise
    return {'unit_files_changed': len(changed)}


def enable_timer():
    args = ['systemctl', 'show', 'argosbx-ad-refresh.timer', '-p', 'ActiveState', '-p', 'UnitFileState']
    state = subprocess.check_output(args, text=True)
    if 'ActiveState=active' not in state or 'UnitFileState=enabled' not in state:
        subprocess.run(['systemctl', 'enable', '--now', 'argosbx-ad-refresh.timer'],
                       check=True, capture_output=True)
        state = subprocess.check_output(args, text=True)
    if 'ActiveState=active' not in state or 'UnitFileState=enabled' not in state:
        raise ValueError('广告定时任务未启用')


def recover_setup(settings, api):
    if country_routes.AD_JOURNAL.exists():
        journal = json.loads(country_routes.AD_JOURNAL.read_text())
        if journal.get('owner') != 'ad-setup':
            raise ValueError('存在其他广告路由事务，请先恢复')
    if ad_delivery.JOURNAL.exists():
        publication.recover(ad_delivery.JOURNAL, api, get, request, digest)
    if not country_routes.AD_JOURNAL.exists():
        return
    active = get(api, 'file', ad_rules.STATE_FILE)
    if active is None:
        country_routes.ad_finish(restore=True)
        return
    snapshot = ad_delivery.read_state(active['content'])['snapshot']
    if snapshot['mrs_sha256'] != journal.get('asset_sha256'):
        raise ValueError('广告路由事务与现行版本不一致，请先核对')
    wait_asset(settings, snapshot)
    ad_delivery.verify(settings, api, snapshot)
    country_routes.ad_finish()


def rollback_unpublished_route(api):
    if country_routes.AD_JOURNAL.exists() and not ad_delivery.JOURNAL.exists():
        # A committed publication may already reference the new route.
        # Preserve its recovery journal rather than breaking that live asset.
        if get(api, 'file', ad_rules.STATE_FILE) is None:
            country_routes.ad_finish(restore=True)


def setup(spec=None):
    with lock(LOCK):
        ad_delivery.check_onboarding()
        if CONFIG.exists():
            if spec:
                raise ValueError('广告发布设置已存在，请使用现有配置')
            settings = ad_delivery.read_config(CONFIG)
        else:
            settings = initial_settings(spec)
        api = ad_delivery.api_config(settings)
        recover_setup(settings, api)
        scopes = discover(settings, api)
        compiler = install_compiler(Path(settings['mihomo']))
        if not CONFIG.exists():
            save(CONFIG, settings)
        active = get(api, 'file', ad_rules.STATE_FILE)
        initialized = False
        if active:
            verified = ad_delivery.refresh(settings, verify_only=True)
        else:
            snapshot = candidate_snapshot(compiler)
            if country_routes.AD_ROUTES in CADDY_MAIN.read_text() or (CADDY_INCLUDE.exists() and country_routes.AD_ROUTES in CADDY_INCLUDE.read_text()):
                country_routes.store_ad_asset(snapshot)
                wait_asset(settings, snapshot)
            else:
                country_routes.stage_ads_main(snapshot, owner='ad-setup')
            try:
                wait_asset(settings, snapshot)
                routes = console_routes()
                verified = ad_delivery.publish(settings, api, routes, routes, snapshot, None)
                country_routes.ad_finish()
                initialized = True
            except Exception:
                rollback_unpublished_route(api)
                raise
        units = install_units()
        result = {'scopes': scopes, 'initialized': initialized, 'verified': bool(verified), **units}
    enable_timer()
    return {**result, 'timer_enabled': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='一次接入现有 Sub-Store 广告更新')
    parser.add_argument('--input', action='store_true', help='首次设置从标准输入读取私有 JSON')
    args = parser.parse_args()
    try:
        print(json.dumps(setup(json.load(sys.stdin) if args.input else None), ensure_ascii=False))
    except Exception as error:
        print('广告接入停止，' + (str(error) if isinstance(error, ValueError) else type(error).__name__), file=sys.stderr)
        raise SystemExit(1)
