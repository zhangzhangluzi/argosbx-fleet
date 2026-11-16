// Derive chain names from the same response, avoiding a second volatile source read.
function attachJapanChains(body) {
  const lines=body.split('\n');
  const names=new Set();
  for (const line of lines) {
    if (!line.startsWith('vless://') || !line.includes('#')) continue;
    try { names.add(decodeURIComponent(line.slice(line.lastIndexOf('#')+1))); } catch (_) {}
  }
  return lines.map(line => {
    if (!line.startsWith('vless://') || !line.includes('#')) return line;
    const at=line.lastIndexOf('#');
    let name; try { name=decodeURIComponent(line.slice(at+1)); } catch (_) { return line; }
    const prefix='JP-T-v4-CF-自建-';
    if (!name.startsWith(prefix)) return line;
    const entry='CF入口-'+name.slice(prefix.length);
    if (!names.has(entry)) throw new Error('Japan chain entry missing');
    const uri=line.slice(0,at);
    if (/[?&]chain=/i.test(uri)) throw new Error('Unexpected existing proxy chain');
    return uri+(uri.includes('?')?'&':'?')+'chain='+encodeURIComponent(entry)+line.slice(at);
  }).join('\n');
}
