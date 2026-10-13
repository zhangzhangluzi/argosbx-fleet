// Only the verified Cloudflare TLS entrances terminate ECH at the edge.
// DNS rotation is handled by Mihomo's independent proxy-server-nameserver.
function applyCfEch(proxies) {
  const hosts = new Set(CF_HOSTS);
  return proxies.map(p => {
    if (!hosts.has(p.server)) return p;
    if (p.type !== 'vmess' || p.network !== 'ws' || !p.tls ||
        p.servername !== p.server || p['reality-opts']) {
      throw new Error('Unexpected Cloudflare TLS entrance');
    }
    return {...p, 'skip-cert-verify': false, 'client-fingerprint': 'chrome',
      'ech-opts': {enable: true, 'query-server-name': 'cloudflare-ech.com'}};
  });
}
