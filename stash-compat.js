// Shared by Stash file generation and download response headers.
function stashModern(req = {}) {
  const ua = String(Object.entries(req.headers || {}).find(([k]) => k.toLowerCase() === 'user-agent')?.[1] || '').toLowerCase();
  // XHTTP / VLESS Encryption: iOS/tvOS 3.6+, macOS 4.3+.
  // Unknown clients receive the fleet's 3.4-compatible subset.
  const version = ua.match(/\bstash(?:[\s_-]?mac)?[\/\s]+(\d+)\.(\d+)(?:\.(\d+))?/);
  const mac = /stash[\s_-]?mac|macos|mac os x/.test(ua) || (version && Number(version[1]) >= 4 && !/iphone|ipad|ios|tvos/.test(ua));
  const minimum = mac ? [4, 3] : [3, 6];
  return !!(version && (Number(version[1]) > minimum[0] || Number(version[1]) === minimum[0] && Number(version[2]) >= minimum[1]));
}

function stashCompatibleConfig(config, req = {}) {
  if (!stashModern(req)) {
    const policy = config.dns['nameserver-policy'];
    policy['geosite:cn'] = policy['rule-set:国内域名'];
    delete policy['rule-set:国内域名'];
  }
  return config;
}

function stashCompatibleProxies(proxies, req = {}) {
  const compatible = stashModern(req) ? proxies : proxies.filter(p =>
    p.network !== 'xhttp' && !(p.type === 'vless' && p.encryption && p.encryption !== 'none'));
  if (!compatible.length) throw new Error('No proxies compatible with this Stash version');
  return compatible;
}

function stashResponseHeaders(headers = {}) {
  const vary = Object.entries(headers).filter(([k]) => k.toLowerCase() === 'vary')
    .flatMap(([,v]) => String(v).split(',').map(s => s.trim())).filter(Boolean);
  const result = {...headers};
  for (const key of Object.keys(result)) {
    if (['cache-control','vary','content-type','content-length'].includes(key.toLowerCase())) delete result[key];
  }
  return {...result, 'content-type': 'text/yaml; charset=utf-8',
    'cache-control': 'private, no-store', vary: [...new Set([...vary, 'User-Agent'])].join(', ')};
}
