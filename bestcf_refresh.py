#!/usr/bin/env python3
"""Warm and verify the existing private JP-CF subscription without logging secrets."""
import json
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import yaml

STATE = Path('/var/lib/sub-store/sub-store.json')
BASE = 'http://127.0.0.1:3001/share/col/external-seven'


def token_for_collection(state):
    tokens = state.get('tokens', [])
    if isinstance(tokens, dict):
        tokens = list(tokens.values())
    matches = [v.get('token') for v in tokens if v.get('name') == 'external-seven' and v.get('type') == 'col' and v.get('token')]
    if len(matches) != 1:
        raise ValueError('seven-region share identity is ambiguous')
    return matches[0]


def check(body):
    doc = yaml.safe_load(body)
    proxies = doc.get('proxies', []) if isinstance(doc, dict) else []
    entries = {p.get('name') for p in proxies if p.get('name', '').startswith('CF入口-')}
    exits = [p for p in proxies if p.get('name', '').startswith('JP-T-v4-CF-自建-')]
    groups = doc.get('proxy-groups', []) if isinstance(doc, dict) else []
    group = next((g for g in groups if g.get('name') == '地区-日本自建'), None)
    if (len(entries) < 2 or len(exits) < 2 or not group or group.get('interval') != 1800 or
            any(not p.get('reality-opts') or p.get('dialer-proxy') not in entries for p in exits) or
            not all(any(source in p['name'] for p in exits) for source in ('Mia', 'Qilin'))):
        raise ValueError('Japan CF chain is incomplete')
    return len(entries), len(exits)


def refresh(state=STATE):
    token = token_for_collection(json.loads(Path(state).read_text()))
    query = urlencode({'token':token, 'target':'ClashMeta', 'only':'jpself'})
    req = Request(BASE+'?'+query, headers={'User-Agent':'FlClash/0.8.99', 'Cache-Control':'no-cache'})
    with urlopen(req, timeout=50) as response:
        body = response.read(8*1024*1024+1)
    if len(body) > 8*1024*1024:
        raise ValueError('subscription exceeds expected size')
    return check(body)


if __name__ == '__main__':
    try:
        entries, exits = refresh()
        print('Japan CF source refresh verified:', entries, 'entrances,', exits, 'chains')
    except Exception as error:
        print('Japan CF source refresh failed:', type(error).__name__)
        raise SystemExit(1)
