"""Integrate the JP-through-CF nodes into the existing seven-region profiles."""
import copy
import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import UUID

SELF_PREFIX = 'JP-T-v4-CF-自建-'
SELF_GROUP = '地区-日本自建'


def source_template(uri):
    """Retain the Pages identity but not the old country, IP or ProxyIP."""
    parts = urlsplit(uri)
    if parts.scheme != 'vless' or not parts.username or parts.password:
        raise ValueError('Cloudflare source template is invalid')
    UUID(parts.username)
    query = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True)
             if key.lower() not in ('path', 'chain')]
    query.append(('path', '/'))
    return urlunsplit(('vless', parts.username+'@1.1.1.1:443', '', urlencode(query), 'CF-ENTRY-TEMPLATE'))


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Existing subscription template has changed')
    return text.replace(old, new, 1)


def mihomo_file(obj):
    obj = copy.deepcopy(obj)
    args = obj['process'][0]['args']
    text = args['content']
    match = re.search(r'(?m)^ const countryCodes=(.*);$', text)
    if not match:
        raise ValueError('Country map is missing')
    countries = json.loads(match.group(1))
    if countries.get('德国') != ['DE'] or '日本自建' in countries:
        raise ValueError('Country map has changed')
    countries.pop('德国')
    countries['日本自建'] = ['JP']
    text = text[:match.start(1)] + json.dumps(countries, ensure_ascii=False, separators=(',', ':')) + text[match.end(1):]
    old = " const inCountry=(n,c)=>countryCodes[c].some(prefix=>n.startsWith(prefix+'-T-')||n.startsWith(prefix+'-U-'));"
    new = (" const isSelf=n=>n.startsWith(" + json.dumps(SELF_PREFIX, ensure_ascii=False) + ");\n"
           " const inCountry=(n,c)=>c==='日本自建'?isSelf(n):!isSelf(n)&&countryCodes[c].some(prefix=>n.startsWith(prefix+'-T-')||n.startsWith(prefix+'-U-'));" )
    text = replace_once(text, old, new).replace('地区-德国', SELF_GROUP)
    args['content'] = text
    return obj


def shadowrocket_file(obj):
    obj = copy.deepcopy(obj)
    args = obj['process'][0]['args']
    text = args['content']
    match = re.search(r'(?m)^ const countries=(.*);$', text)
    if not match:
        raise ValueError('Shadowrocket country map is missing')
    countries = json.loads(match.group(1))
    found = [x for x in countries if x == {'code': 'DE', 'label': '德国'}]
    if len(found) != 1 or any(x.get('label') == '日本自建' for x in countries):
        raise ValueError('Shadowrocket country map has changed')
    countries[countries.index(found[0])] = {'code':'JP', 'label':'日本自建'}
    text = text[:match.start(1)] + json.dumps(countries, ensure_ascii=False) + text[match.end(1):]
    old = " const available=countries.filter(c=>nodes.some(p=>p.name.startsWith(c.code+'-')));"
    new = (" const isSelf=p=>p.name.startsWith(" + json.dumps(SELF_PREFIX, ensure_ascii=False) + ");\n"
           " const belongs=(p,c)=>c.label==='日本自建'?isSelf(p):!isSelf(p)&&p.name.startsWith(c.code+'-');\n"
           " const available=countries.filter(c=>nodes.some(p=>belongs(p,c)));" )
    text = replace_once(text, old, new)
    text = replace_once(text, "nodes.filter(p=>p.name.startsWith(c.code+'-'))", "nodes.filter(p=>belongs(p,c))")
    text = text.replace('地区-德国', SELF_GROUP)
    marker = ' input.$options??={};'
    guard = (" if(!/^\\[General\\]\\s*$/m.test(input.$content))throw new Error('Shadowrocket General section missing');\n"
             " input.$content=input.$content.replace(/^\\s*close-if-proxy-chain-missing\\s*=.*$/gmi,'')"
             ".replace(/^(\\[General\\]\\s*)$/m,'$1\\nclose-if-proxy-chain-missing = true');\n")
    text = replace_once(text, marker, guard + marker)
    args['content'] = text
    return obj


def collection(obj, *, source='external-seven-de'):
    obj = copy.deepcopy(obj)
    args = obj['process'][0]['args']
    text = args['content']
    helper = (Path(__file__).with_name('bestcf-shadowrocket.js')).read_text()
    text = replace_once(text, 'async function transformFunction(res, context) {',
                        helper + '\nasync function transformFunction(res, context) {')
    target = "  const target = String(req.params?.target || req.query?.platform || req.query?.target || '').toLowerCase();"
    text = replace_once(text, target, target + "\n  const jpSelfOnly = String(req.params?.only || req.query?.only || '').toLowerCase() === 'jpself';")
    text = replace_once(text,
        "  const isShadowrocket = target ? target === 'shadowrocket' : ua.includes('shadowrocket');",
        "  const isShadowrocket = target ? ['shadowrocket','uri'].includes(target) : ua.includes('shadowrocket') || (jpSelfOnly && !isStash && !isMihomo);")
    marker = "    res.body = await produceArtifact({type:'collection',name:sourceName,platform:'URI',noFlow:true});"
    text = replace_once(text, marker, marker + "\n    res.body = await addJapanChains(res.body, $arguments.jp_chain_source, jpSelfOnly);")
    source_marker = '  const source = ProxyUtils.yaml.safeLoad(res.body);'
    text = replace_once(text, source_marker, source_marker +
        "\n  if (jpSelfOnly && Array.isArray(source?.proxies)) source.proxies = source.proxies.filter(p => p.name?.startsWith('CF入口-') || p.name?.startsWith('JP-T-v4-CF-自建-'));" )
    text = text.replace('Seven Regions HK-TW-SG-JP-US-KR-DE', 'Six Regions + JP Self')
    args.setdefault('arguments', {})['jp_chain_source'] = source
    args['content'] = text
    obj['displayName'] = obj.get('displayName','').replace('德国', '日本自建')
    return obj
