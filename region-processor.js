function operator(proxies) {
  const spec = SPEC;
  const result = [];
  const ids={'VLESS-REALITY-Vision':'reality','Hysteria2':'hy2','AnyTLS':'anytls','SS2022-ShadowTLS-v3':'shadowtls','Hysteria2-Salamander':'salamander'};
  function check(p,id) {
    const desired=spec.protocols?.[id];
    if(!desired)return !Object.keys(spec.protocols||{}).length;
    if(!desired.enabled)return false;
    if(!['cf','xhttp'].includes(desired.type||id) && p.port!==desired.port)throw new Error('Server port is not applied: '+id);
    if(desired.sni && (p.sni||p.servername)!==desired.sni)throw new Error('Server SNI is not applied: '+id);
    if((desired.type||id)==='cf' && String(p['ws-opts']?.path||'').replace(/^\//,'')!==String(desired.ws_path||'').replace(/^\//,''))throw new Error('Server WS path is not applied');
    return true;
  }
  for (const p of proxies) {
    if ((p.type === 'vmess' && p.network === 'ws' || p.type === 'vless' && p.network === 'xhttp') && p.tls) {
      const kind=p.network==='xhttp'?'xhttp':'cf';
      const id=p.name?.startsWith('fleet.')?p.name.slice(6):kind;
      if (!check(p,id)) continue;
      const host=spec.protocols?.[id]?.sni||spec.cf;
      if(!host)continue;
      const n = JSON.parse(JSON.stringify(p));
      n.server = host;
      n.servername = host;
      if (n['ws-opts']?.headers?.Host) n['ws-opts'].headers.Host = host;
      if (kind==='xhttp') {
        if(n['xhttp-opts']?.path!==spec.protocols[id].path || n['xhttp-opts']?.mode!==spec.protocols[id].mode)throw new Error('XHTTP configuration mismatch');
        n['xhttp-opts'].host=host;
      }
      result.push({...n, name:spec.name+'-T-'+(kind==='xhttp'?'CF-VLESS-XHTTP-TLS':'CF-VMess-WS-TLS')+(id===kind?'':'@'+id), 'skip-cert-verify':false});
      continue;
    }
    let protocol;
    if (p.type === 'vless' && p['reality-opts']) protocol = 'VLESS-REALITY-Vision';
    else if (p.type === 'hysteria2') protocol = p.obfs === 'salamander' ? 'Hysteria2-Salamander' : 'Hysteria2';
    else if (p.type === 'anytls') protocol = 'AnyTLS';
    else if (p.type === 'ss' && p.cipher === '2022-blake3-aes-128-gcm' && p.plugin === 'shadow-tls' && Number(p['plugin-opts']?.version) === 3) protocol = 'SS2022-ShadowTLS-v3';
    else continue;
    const id=p.name?.startsWith('fleet.')?p.name.slice(6):ids[protocol];
    if(!check(p,id))continue;
    const suffix=id===ids[protocol]?'':'@'+id;
    for (const family of ['IPv4', 'IPv6']) {
      // The two IPv6 UDP 8443 paths fail the user's direct-network acceptance.
      if (protocol === 'Hysteria2-Salamander' && family === 'IPv6' && !spec.salamanderIPv6) continue;
      const binding=spec.protocols?.[id];
      if(binding?.listen) {
        const addr=binding.listen, kind=binding.type||id;
        const both=addr==='::'||(addr==='0.0.0.0'&&['reality','hy2'].includes(kind));
        if(!both && ((addr.includes(':')?'IPv6':'IPv4')!==family))continue;
      }
      const domain = spec[family];
      if (!domain) continue;
      const n = JSON.parse(JSON.stringify(p));
      n.server = domain;
      n.name = spec.name+'-'+(p.type==='hysteria2'?'U':'T')+'-'+family.replace('IP','')+'-'+protocol+suffix;
      n.udp = true;
      n['skip-cert-verify'] = false;
      delete n.fingerprint;
      if (p.type === 'hysteria2') delete n.pinSHA256;
      result.push(n);
    }
  }
  if (!result.length || new Set(result.map(p=>p.name)).size !== result.length) throw new Error('Invalid ArgoSBX node set');
  // Keep stable display order and the initial choice before automatic testing.
  const order = ['VLESS-REALITY-Vision','Hysteria2','CF-VMess-WS-TLS','AnyTLS','SS2022-ShadowTLS-v3','Hysteria2-Salamander','CF-VLESS-XHTTP-TLS'];
  const rank = n => order.findIndex(p => n.split('@')[0].endsWith('-'+p));
  result.sort((a,b) => rank(a.name)-rank(b.name));
  return result;
}
