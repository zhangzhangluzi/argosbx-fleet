"""Automatic ECH policy; private keys stay in transaction-protected native files."""
import base64
import copy
import hashlib
import re
import subprocess

PUBLIC_NAME = 'cloudflare-ech.com'
DNS = 'https://dns.alidns.com/dns-query'
DIRECT_TYPES = frozenset(('hy2', 'anytls', 'salamander'))

def pem_config(config):
    raw = base64.b64decode(config, validate=True)
    if len(raw) < 6 or int.from_bytes(raw[:2], 'big') != len(raw) - 2:
        raise ValueError('ECH public config list is invalid')
    return '-----BEGIN ECH CONFIGS-----\n' + config + '\n-----END ECH CONFIGS-----\n'

def generate(core):
    args = (['/root/agsbx/xray', 'tls', 'ech', '--serverName', PUBLIC_NAME]
            if core == 'xray' else ['/root/agsbx/sing-box', 'generate', 'ech-keypair', PUBLIC_NAME])
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise ValueError('Native ECH key generation failed: ' + core)
    if core == 'xray':
        config = re.search(r'ECH config list:\s*([A-Za-z0-9+/=]+)', result.stdout)
        key = re.search(r'ECH server keys:\s*([A-Za-z0-9+/=]+)', result.stdout)
        if not config or not key:raise ValueError('Xray did not return an ECH key pair')
        config, key = config[1], key[1]
    else:
        config = re.search(r'-----BEGIN ECH CONFIGS-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END ECH CONFIGS-----', result.stdout)
        key = re.search(r'-----BEGIN ECH KEYS-----[\s\S]+?-----END ECH KEYS-----', result.stdout)
        if not config or not key:raise ValueError('sing-box did not return an ECH key pair')
        config, key = ''.join(config[1].split()), key[0] + '\n'
    pem_config(config)
    return key, config

def native_key(inbound, core):
    if core == 'xray':
        return inbound.get('streamSettings', {}).get('tlsSettings', {}).get('echServerKeys', '')
    value = inbound.get('tls', {}).get('ech', {})
    if value and (not value.get('enabled') or value.get('key_path')):
        raise ValueError('Unexpected native ECH key configuration')
    key = value.get('key', [])
    return '\n'.join(key).strip() + '\n' if isinstance(key, list) and key else key or ''

def fingerprint(key):
    return hashlib.sha256(key.encode()).hexdigest()

def configure(configs, state, keygen=None):
    from protocols import entry, protocol_type
    keygen = keygen or generate
    managed = state.setdefault('ech', {})
    for ident in set(managed) - set(state['bindings']):del managed[ident]
    for ident, binding in state['bindings'].items():
        settings = state['protocols'][ident]
        if not settings['enabled'] or protocol_type(ident, settings) not in DIRECT_TYPES:continue
        inbound = entry(configs[binding['path']], binding)
        core = binding['core'];key = native_key(inbound, core)
        if key:
            saved = managed.get(ident, {})
            if fingerprint(key) != saved.get('key_sha256') or not saved.get('config'):
                raise ValueError('Unmanaged or mismatched ECH key: ' + ident)
            pem_config(saved['config'])
        else:
            if ident in managed:raise ValueError('Managed ECH key is missing: ' + ident)
            key, config = keygen(core);pem_config(config)
            if core == 'xray':inbound['streamSettings']['tlsSettings']['echServerKeys'] = key
            else:inbound['tls']['ech'] = {'enabled': True, 'key': [key]}
            managed[ident] = {'config': config, 'key_sha256': fingerprint(key), 'public_name': PUBLIC_NAME}
        # Preserve the ECH identity when this inbound is disabled and enabled.
        binding['inbound'] = copy.deepcopy(inbound)
    state['ech_policy'] = 1

def client_options(state, ident, inbound):
    from protocols import protocol_type
    if state.get('ech_policy') != 1:return {}
    kind = protocol_type(ident, state['protocols'][ident])
    if kind == 'cf':
        return {'ech-opts': {'enable': True, 'query-server-name': PUBLIC_NAME, '_dns': DNS}, 'client-fingerprint': 'chrome'}
    if kind not in DIRECT_TYPES:return {}
    saved = state.get('ech', {}).get(ident, {})
    key = native_key(inbound, state['bindings'][ident]['core'])
    if not key or fingerprint(key) != saved.get('key_sha256'):
        raise ValueError('Cannot export an unverified ECH identity: ' + ident)
    pem_config(saved['config'])
    result = {'ech-opts': {'enable': True, 'config': saved['config']}}
    if kind == 'anytls':result['client-fingerprint'] = 'chrome'
    return result
