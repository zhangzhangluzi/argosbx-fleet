// Called only after the existing EdgeTunnel subscription token has been checked.
async function japanSelfSubscription(request, env, original, ua) {
  try {
    const configured = await env.KV.get('JP_SELF_SUB_URL');
    if (!configured) throw new Error('subscription unconfigured');
    const endpoint = new URL(configured);
    if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.hash) throw new Error('invalid destination');
    endpoint.searchParams.set('only', 'jpself');
    const target = original.searchParams.get('target') || original.searchParams.get('platform');
    if (target && /^(?:clashmeta|meta|mihomo|stash|uri|shadowrocket)$/i.test(target)) endpoint.searchParams.set('target', target);
    const response = await fetch(endpoint.toString(), {
      method:'GET', redirect:'manual', headers:{'User-Agent':ua || 'unknown', 'Accept-Encoding':'identity'},
      signal:AbortSignal.timeout(45000),
    });
    if (!response.ok) throw new Error('subscription unavailable');
    let body = await response.text();
    if (!body || body.length > 8 * 1024 * 1024) throw new Error('invalid response');
    if (/stash/i.test(target || ua)) {
      const refresh = '#SUBSCRIBED ' + original.toString() + '\n';
      body = body.replace(/^#SUBSCRIBED [^\r\n]*(?:\r?\n|$)/, '');
      body = refresh + body;
    }
    const headers = new Headers(response.headers);
    headers.delete('content-length');
    headers.delete('set-cookie');
    headers.set('cache-control', 'private, no-store');
    headers.set('profile-title', 'JP-CF-Self');
    return new Response(body, {status:200, headers});
  } catch (_) {
    return new Response('Japan self-hosted subscription temporarily unavailable\n', {
      status:503, headers:{'content-type':'text/plain; charset=utf-8', 'cache-control':'no-store', 'retry-after':'60'},
    });
  }
}
