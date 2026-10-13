// Native Sub-Store Response Transformer. Reuse the existing complete profile.
async function transformFunction(res, context) {
  const sourceName = context.source?._collection?.name || Object.keys(context.source || {})[0] || 'all';
  const titles = PROFILE_TITLES;
  const title = titles[sourceName] || 'ArgoSBX ' + sourceName.replace(/[^a-zA-Z0-9_-]/g, '-');
  const suffix = sourceName.replace(/[^a-zA-Z0-9_-]/g, '-');
  const setTitle = (fallback) => {
    res.headers = {...res.headers};
    for (const key of Object.keys(res.headers)) {
      if (['content-disposition','profile-title'].includes(key.toLowerCase())) delete res.headers[key];
    }
    res.headers['content-disposition'] = `attachment; filename="${fallback}"; filename*=UTF-8''${encodeURIComponent(title)}`;
    res.headers['profile-title'] = title;
  };
  setTitle(`ArgoSBX-${suffix}.txt`);
  const req = $options?._req || {};
  const target = String(req.params?.target || req.query?.platform || req.query?.target || '').toLowerCase();
  const ua = String(Object.entries(req.headers || {}).find(([k]) => k.toLowerCase() === 'user-agent')?.[1] || '').toLowerCase();
  const isStash = target ? target === 'stash' : /\bstash(?:mac)?(?:[\s/_-]|$)/.test(ua);
  const isMihomo = target
    ? ['meta', 'clashmeta', 'clash.meta', 'mihomo'].includes(target)
    : ua === 'meta' || ua.includes('flclash') || ua.includes('clash-verge') || (ua.includes('clash') && ua.includes('meta'));
  // Sub-Store's legacy VMess JSON URI omits ECH. Reuse its native query
  // serializer, which supports ECH, for our verified AEAD VMess WS entrances.
  if (target === 'uri') {
    const hosts = new Set(CF_HOSTS);
    res.body = res.body.split('\n').map(line => {
      if (!line.startsWith('vmess://')) return line;
      const p = ProxyUtils.parse(line)[0];
      if (!p || !hosts.has(p.server)) return line;
      if (p.network !== 'ws' || !p.tls || Number(p.alterId || 0) !== 0) {
        throw new Error('Unexpected Cloudflare VMess URI');
      }
      const uri = ProxyUtils.produce([{...p, type: 'vless', flow: undefined,
        encryption: p.cipher || 'auto', 'client-fingerprint': 'chrome',
        'ech-opts': {enable: true, 'query-server-name': 'cloudflare-ech.com',
          _dns: 'https://dns.alidns.com/dns-query'}}], 'URI');
      if (!uri.startsWith('vless://') || !uri.includes('ech=')) throw new Error('ECH URI conversion failed');
      return uri.replace(/^vless:\/\//, 'vmess://');
    }).join('\n');
    delete res.headers['content-length'];
  }
  if (!isMihomo && !isStash) return res;

  const source = ProxyUtils.yaml.safeLoad(res.body);
  if (!Array.isArray(source?.proxies) || !source.proxies.length) {
    throw new Error('Client export contains no usable proxies');
  }
  if (isStash) {
    // XHTTP and VLESS Encryption require iOS/tvOS 3.6 or macOS 4.3.
    // A versionless request uses the 3.4-compatible fleet subset. Never turn
    // an encrypted XHTTP node into an invalid plaintext VLESS node.
    const version = ua.match(/\bstash(?:[\s_-]?mac)?[\/\s]+(\d+)\.(\d+)(?:\.(\d+))?/);
    const mac = /stash[\s_-]?mac|macos|mac os x/.test(ua) || (version && Number(version[1]) >= 4 && !/iphone|ipad|ios|tvos/.test(ua));
    const minimum = mac ? [4, 3] : [3, 6];
    const modern = version && (Number(version[1]) > minimum[0] || Number(version[1]) === minimum[0] && Number(version[2]) >= minimum[1]);
    if (!modern) source.proxies = source.proxies.filter(p =>
      p.network !== 'xhttp' && !(p.type === 'vless' && p.encryption && p.encryption !== 'none'));
    if (!source.proxies.length) throw new Error('No proxies compatible with this Stash version');
  }
  const profileName = isStash ? ($arguments.stash_profile || 'stash') : ($arguments.profile || 'clash');
  const profile = ($substore.read('files') || []).find(f => f.name === profileName);
  if (!profile || profile.type !== 'mihomoConfig') throw new Error('Complete client profile is missing');
  // Feed the already converted nodes to the canonical file processors. No HTTP
  // recursion, extra source downloads, or duplicate DNS/rule template.
  const body = await produceArtifact({
    type: 'file',
    file: {...profile, sourceType: 'local', source: 'local', mode: 'text', mergeSources: undefined},
    content: ProxyUtils.yaml.safeDump({proxies: source.proxies}),
    noFlow: true,
  });
  const config = ProxyUtils.yaml.safeLoad(body);
  if (config?.mode !== 'rule' || !config['proxy-groups']?.length || !config.rules?.length) {
    throw new Error('Client complete profile is invalid');
  }
  res.body = body;
  res.headers = {...res.headers,
    'content-type': 'text/yaml; charset=utf-8',
  };
  setTitle(`ArgoSBX-${suffix}-${isStash ? 'Stash' : 'FlClash'}.yaml`);
  if (isStash) {
    // Format/version depends on UA even when target=Stash is explicit.
    const vary = Object.entries(res.headers).filter(([k]) => k.toLowerCase() === 'vary')
      .flatMap(([,v]) => String(v).split(',').map(s => s.trim())).filter(Boolean);
    for (const key of Object.keys(res.headers)) {
      if (['cache-control','vary'].includes(key.toLowerCase())) delete res.headers[key];
    }
    res.headers['cache-control'] = 'private, no-store';
    res.headers.vary = [...new Set([...vary, 'User-Agent'])].join(', ');
  }
  for (const key of Object.keys(res.headers)) if (key.toLowerCase() === 'content-length') delete res.headers[key];
  return res;
}
