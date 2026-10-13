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
  const target = String(req.query?.platform || req.query?.target || req.params?.target || '').toLowerCase();
  const ua = String(req.headers?.['user-agent'] || '').toLowerCase();
  const isMihomo = target
    ? ['meta', 'clashmeta', 'clash.meta', 'mihomo'].includes(target)
    : ua === 'meta' || ua.includes('flclash') || ua.includes('clash-verge') || (ua.includes('clash') && ua.includes('meta'));
  if (!isMihomo) return res;

  const source = ProxyUtils.yaml.safeLoad(res.body);
  if (!Array.isArray(source?.proxies) || !source.proxies.length) {
    throw new Error('FlClash export contains no usable proxies');
  }
  const profile = ($substore.read('files') || []).find(f => f.name === ($arguments.profile || 'clash'));
  if (!profile || profile.type !== 'mihomoConfig') throw new Error('Complete Clash profile is missing');
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
    throw new Error('FlClash complete profile is invalid');
  }
  res.body = body;
  res.headers = {...res.headers,
    'content-type': 'text/yaml; charset=utf-8',
  };
  setTitle(`ArgoSBX-${suffix}-FlClash.yaml`);
  delete res.headers['content-length'];
  return res;
}
