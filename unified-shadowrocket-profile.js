function operator(input) {
  const nodes=ProxyUtils.yaml.safeLoad(input.$content).proxies;
  if (!Array.isArray(nodes)) throw new Error('Missing subscription nodes');
  const countries=__COUNTRIES__;
  const isSelf=n=>n.startsWith('JP-T-v4-CF-自建-');
  const belongs=(n,c)=>c==='日本自建'?isSelf(n):!isSelf(n)&&countries[c].some(p=>n.startsWith(p+'-T-')||n.startsWith(p+'-U-'));
  const available=Object.keys(countries).filter(c=>nodes.some(p=>belongs(p.name,c)));
  const regions=available.map(c=>'地区-'+c);
  const purposes=__PURPOSE__.filter(n=>regions.includes(n));
  const lines=['[Proxy Group]','日常线路 = select, '+regions.join(', '),
    'AI线路 = select, 日常线路, '+purposes.join(', '),
    'Telegram = select, 日常线路, '+purposes.join(', ')];
  for(const country of available) {
    const names=nodes.filter(p=>belongs(p.name,country)).map(p=>p.name);
    lines.push('地区-'+country+' = url-test, '+names.join(', ')+', url=https://www.gstatic.com/generate_204, interval='+__INTERVAL__+', timeout=5, tolerance=100');
  }
  input.$content=__BASE__+'\n'+lines.join('\n')+'\n';
  input.$options??={};input.$options._res??={};
  input.$options._res.headers={'content-type':'text/plain; charset=utf-8','cache-control':'private, no-store'};
  return input;
}
