// URI subscriptions do not carry Mihomo's dialer-proxy field by default.
async function addJapanChains(body, source, onlySelf = false) {
  const nodes = await produceArtifact({type:'subscription', name:source || 'external-seven-de',
    platform:'ClashMeta', produceType:'internal'});
  const names = new Set(nodes.map(p => p.name));
  const mapping = new Map(nodes.filter(p => p.name?.startsWith('JP-T-v4-CF-自建-')).map(p => [p.name, p['dialer-proxy']]));
  if (!mapping.size || [...mapping.values()].some(name => !name || !names.has(name))) throw new Error('Japan chain source incomplete');
  const added = new Set();
  const result = body.split('\n').map(line => {
    if (!line.startsWith('vless://') || !line.includes('#')) return onlySelf ? '' : line;
    const index = line.lastIndexOf('#');
    let name;
    try { name = decodeURIComponent(line.slice(index + 1)); } catch (_) { return line; }
    const upstream = mapping.get(name);
    if (onlySelf && !upstream && ![...mapping.values()].includes(name)) return '';
    if (!upstream) return line;
    const prefix = line.slice(0, index);
    if (/[?&]chain=/i.test(prefix)) throw new Error('Unexpected existing proxy chain');
    added.add(name);
    return prefix + (prefix.includes('?') ? '&' : '?') + 'chain=' + encodeURIComponent(upstream) + line.slice(index);
  }).filter(Boolean).join('\n');
  if (added.size !== mapping.size) throw new Error('Japan chain missing from URI output');
  return result;
}
