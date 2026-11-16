// Turn two BestCF IPv4 feeds into CF entrances chained to the existing JP VPS.
// This operator runs inside the private Sub-Store backend; it never logs nodes.
async function operator(proxies) {
  const sources = [
    { id: 'Mia', url: 'https://bestcf.pages.dev/xinyitang3/ipv4.txt' },
    { id: 'Qilin', url: 'https://bestcf.pages.dev/uouin/all.txt' },
  ];
  const now = Date.now();
  // Collapse bursts of subscription requests, then check the live upstream.
  const freshFor = 60 * 1000;
  const validFor = 6 * 60 * 60 * 1000;
  const cacheKey = id => 'argosbx-jp-self-cf-v3-' + id;
  const publicIPv4 = (value) => {
    const fields = value.split('.');
    if (fields.length !== 4 || fields.some(x => !/^\d{1,3}$/.test(x) || Number(x) > 255)) return false;
    const [a,b,c] = fields.map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) ||
        (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)))) ||
        (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
        (a === 203 && b === 0 && c === 113)) return false;
    return true;
  };
  function parse(body) {
    const found = new Map();
    if (typeof body !== 'string' || body.length > 200000 || /<(?:!doctype|html)\b/i.test(body)) return [];
    for (const row of body.replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g, '').split(/\r?\n/)) {
      const match = row.trim().match(/^((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})#(.+)$/);
      if (!match || /BestCF\.pages\.dev/i.test(match[3]) || !publicIPv4(match[1])) continue;
      const port = Number(match[2]);
      if (port < 1 || port > 65535) continue;
      const address = match[1];
      found.set(address + ':' + port, {address, port});
      // Reject an abnormal list as a whole instead of silently truncating it.
      if (found.size > 2000) throw new Error('source too large');
    }
    return [...found.values()];
  }
  const entry = proxies.find(p => p.type === 'vless' && p.network === 'ws' && p.tls && p.uuid &&
    (p.servername || p.sni) && p['ws-opts']?.path && p['skip-cert-verify'] !== true);
  if (!entry) return [];
  async function obtain(spec) {
    const key = cacheKey(spec.id);
    const old = scriptResourceCache.get(key);
    const usable = old && Array.isArray(old.addresses) && old.addresses.length && Number.isFinite(old.at) && now >= old.at;
    if (usable && now - old.at < freshFor) return old.addresses;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 8000);
      try {
        const response = await fetch(spec.url, { headers: {'User-Agent': 'Mozilla/5.0'}, signal: controller.signal });
        if (!response.ok) throw new Error('source unavailable');
        const addresses = parse(await response.text());
        if (!addresses.length) throw new Error('source has no valid IPv4 entries');
        scriptResourceCache.set(key, {at: now, addresses}, validFor);
        return addresses;
      } finally { clearTimeout(timer); }
    } catch (_) {
      if (usable && now - old.at <= validFor) return old.addresses;
      return [];
    }
  }
  let japan;
  try {
    const candidates = await produceArtifact({type:'subscription', name:'argo-jp', platform:'ClashMeta', produceType:'internal'});
    japan = candidates.find(p => p.name === 'JP-T-v4-VLESS-REALITY-Vision' && p.type === 'vless' &&
      p.tls && p.uuid && p['reality-opts']?.['public-key'] && p['skip-cert-verify'] !== true);
  } catch (_) { return []; }
  if (!japan) return [];
  const results = await Promise.all(sources.map(obtain));
  if (results.every(addresses => !addresses.length)) return [];
  const output = [];
  for (let i = 0; i < sources.length; i++) {
    for (let j = 0; j < results[i].length; j++) {
      const candidate = results[i][j];
      const identity = `${sources[i].id}-${candidate.address}-${candidate.port}`;
      const entranceName = `CF入口-${identity}`;
      const exitName = `JP-T-v4-CF-自建-${identity}`;
      // Keep the entry's fallback tied to the same Japan host; the former
      // Germany ProxyIP must not remain in the generated nodes.
      const ws = {...entry['ws-opts'], path:`/proxyip=${japan.server}:${japan.port}`};
      const entrance = {...entry, name:entranceName, server:candidate.address, port:candidate.port, udp:false, 'ws-opts':ws};
      const exit = {...japan, name:exitName, 'dialer-proxy':entranceName, udp:false};
      delete entrance['dialer-proxy'];
      delete entrance['underlying-proxy'];
      output.push(entrance, exit);
    }
  }
  return output;
}
