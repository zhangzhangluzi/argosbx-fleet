"""Attach a stable Stash update URL to complete aggregate profiles."""
import json
from urllib.parse import parse_qsl, urlencode, urlsplit


PATHS = {
    'stash': ('/api/file/stash', '/download/collection/all', '/download/collection/all/Stash'),
    'external-seven-stash': ('/share/col/external-seven', '/share/col/external-seven/Stash'),
}
RENDER = ' input.$content=ProxyUtils.yaml.safeDump(config);\n'
BEGIN = ' // BEGIN STASH AUTO REFRESH\n'
END = ' // END STASH AUTO REFRESH\n'
MARKER = '#SUBSCRIBED '


def update_url(name, url):
    if not isinstance(url, str) or any(c.isspace() or ord(c) < 32 for c in url):
        raise ValueError('Stash 更新地址格式无效')
    parts = urlsplit(url)
    if parts.scheme != 'https' or not parts.hostname or parts.username is not None or parts.fragment:
        raise ValueError('Stash 更新地址必须是现有 HTTPS 订阅')
    query = parse_qsl(parts.query, keep_blank_values=True)
    if name == 'external-seven-stash':
        tokens = [v for k, v in query if k == 'token']
        if parts.path != PATHS[name][0] or len(tokens) != 1 or not tokens[0]:
            raise ValueError('七国 Stash 更新地址必须是原集合分享链接')
        replaced, fmt = {'target', 'platform'}, ('target', 'Stash')
    elif name == 'stash':
        replaced, fmt = {'format'}, ('format', 'stash')
    else:
        raise ValueError('未知 Stash 订阅范围')
    return parts._replace(query=urlencode([p for p in query if p[0] not in replaced] + [fmt])).geturl()


def template(script, name, url, *, staged_name=None):
    if BEGIN in script or END in script:
        if script.count(BEGIN) != 1 or script.count(END) != 1:
            raise ValueError('Stash 更新模板标记不唯一')
        start, _, rest = script.partition(BEGIN)
        _, end, tail = rest.partition(END)
        if not end:
            raise ValueError('Stash 更新模板标记位置无效')
        script = start + RENDER + tail
    if script.count(RENDER) != 1:
        raise ValueError('Stash 配置输出位置不唯一')
    paths = (f'/api/file/{staged_name}',) if staged_name else PATHS[name]
    line = json.dumps(MARKER + update_url(name, url) + '\n')
    block = (
        BEGIN
        + " const refreshPath=String(input.$options?._req?.path ?? '').replace(/\\/$/, '');\n"
        + ' const refreshPaths=' + json.dumps(paths) + ';\n'
        + f" const refreshLine=refreshPaths.includes(refreshPath) ? {line} : '';\n"
        + ' input.$content=refreshLine+ProxyUtils.yaml.safeDump(config);\n'
        + END
    )
    return script.replace(RENDER, block)


def check(body, url=None):
    lines = body.splitlines()
    markers = [line for line in lines if line.startswith(MARKER)]
    if url is None:
        if markers:
            raise ValueError('此导出不应携带聚合订阅更新地址')
    elif not lines or lines[0] != MARKER + url or markers != [lines[0]]:
        raise ValueError('Stash 首行更新地址或订阅范围不匹配')


def deploy(links, settings):
    """Stage the two live templates, publish, and roll back on failed readback."""
    import copy
    import secrets
    import urllib.request

    import yaml

    import ad_rules
    from ad_delivery import JOURNAL, api_config
    import publication
    from servers import check_equivalent_profile, check_profile, digest, get, request
    from storage import lock, save

    api = api_config(settings)
    urls = {name: update_url(name, links[name]) for name in PATHS}
    if urlsplit(urls['external-seven-stash']).netloc != urlsplit(settings['backend_url']).netloc:
        raise ValueError('七国订阅链接与当前发布服务器不匹配')
    agents = ('Stash/3.6.0', 'Mozilla/5.0')

    def read_file(name, ua):
        return request(api, '/api/file/' + name, raw=True, user_agent=ua)

    def read_public(name, ua):
        req = urllib.request.Request(urls[name], headers={'User-Agent': ua})
        with urllib.request.urlopen(req, timeout=25) as response:
            return response.read().decode()

    with lock('/run/argosbx-publisher.lock'):
        journal = publication.begin(JOURNAL, api, digest)
        result = {}
        try:
            items = []
            for name, source in (('stash', 'all'), ('external-seven-stash', 'external-seven')):
                before = get(api, 'file', name)
                if not before or (before.get('type'), before.get('sourceType'), before.get('sourceName')) != ('mihomoConfig', 'collection', source):
                    raise ValueError('Stash 文件与预期订阅范围不一致，' + name)
                after = copy.deepcopy(before)
                operator = after['process'][0]
                if operator['type'] != 'Script Operator':
                    raise ValueError('Stash 模板处理器类型已改变，' + name)
                args = operator['args']
                args['content'] = template(args['content'], name, links[name])
                baseline = {}
                for ua in agents:
                    value = yaml.safe_load(read_file(name, ua))
                    check_profile(value)
                    ad_rules.check_profile(value, 'stash')
                    check_equivalent_profile(yaml.safe_load(read_public(name, ua)), value, name)
                    baseline[ua] = value
                if before != after:
                    alias = 'server-check-stash-' + secrets.token_hex(6)
                    stage = copy.deepcopy(after)
                    stage['name'] = alias
                    staged = stage['process'][0]['args']
                    staged['content'] = template(staged['content'], name, links[name], staged_name=alias)
                    journal['temporary'].append(['file', alias])
                    save(JOURNAL, journal)
                    request(api, '/api/files', stage, 'POST')
                    for ua, expected in baseline.items():
                        raw = read_file(alias, ua)
                        check(raw, urls[name])
                        check_equivalent_profile(yaml.safe_load(raw), expected, name)
                items.append(({'kind': 'file', 'name': name, 'before': before, 'after': after}, baseline))
            publication.cleanup(JOURNAL, journal, api, request)
            for item, _ in items:
                name = item['name']
                if get(api, 'file', name) != item['before']:
                    raise ValueError('Stash 模板发布期间发生变化，' + name)
                if item['after'] != item['before']:
                    journal['attempted'].append(item)
                    save(JOURNAL, journal)
                    request(api, '/api/file/' + name, item['after'], 'PATCH')
                    if get(api, 'file', name) != item['after']:
                        raise ValueError('Stash 模板发布回读不一致，' + name)
            for item, baseline in items:
                name = item['name']
                for ua, expected in baseline.items():
                    raw = read_public(name, ua)
                    check(raw, urls[name])
                    check_equivalent_profile(yaml.safe_load(raw), expected, name)
                result[name] = {ua: len(value['proxies']) for ua, value in baseline.items()}
            raw = request(api, '/download/collection/all?target=Stash', raw=True, user_agent=agents[0])
            check(raw, urls['stash'])
            check_profile(yaml.safe_load(raw))
        except Exception:
            publication.recover(JOURNAL, api, get, request, digest)
            raise
        JOURNAL.unlink()
    return {'profiles': result, 'changed': len(journal['attempted'])}


if __name__ == '__main__':
    import sys
    from ad_delivery import CONFIG, read_config

    try:
        print(json.dumps(deploy(json.load(sys.stdin), read_config(CONFIG)), ensure_ascii=False))
    except Exception as error:
        # Parser and HTTP exception details may contain subscription credentials.
        print('Stash 发布停止，' + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
