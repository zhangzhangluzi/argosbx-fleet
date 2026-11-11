// Produces native rule-provider contents from the current published profile.
// Each part has exactly one policy; ordering and policy assignment belong to
// the importing client. Unknown source structure fails instead of misrouting.
const allowedAdOrigin = 'STANDARD_AD_ORIGIN';
const expected = [
  ['magic-dns','DIRECT','IP-CIDR,100.100.100.100/32,'],
  ['dns-block','REJECT','DST-PORT,53,'],
  ['dns-dot','日常线路','DST-PORT,853,'],
  ['priority-direct','DIRECT','DOMAIN-SUFFIX,'],
  ['priority-proxy','日常线路','DOMAIN-SUFFIX,browserleaks.com,'],
  ['china-console','DIRECT','DOMAIN,e.qq.com,'],
  ['foreign-console','日常线路','DOMAIN,r.applovin.com,'],
  ['dns-direct','DIRECT','IP-CIDR,223.6.6.6/32,'],
  ['dns-proxy-1','日常线路','DOMAIN,dns.alidns.com,'],
  ['google-dns','AI线路','IP-CIDR,8.8.8.8/32,'],
  ['dns-proxy-2','日常线路','IP-CIDR,223.5.5.5/32,'],
  ['telegram','Telegram','DOMAIN-SUFFIX,telegram.org,'],
  ['ads','去广告','RULE-SET,广告域名,'],
  ['lan','DIRECT','IP-CIDR,127.0.0.0/8,'],
  ['ai','AI线路','DOMAIN-SUFFIX,chatgpt.com,'],
  ['china-sites','DIRECT','DOMAIN-SUFFIX,cn,'],
  ['overseas','日常线路','DOMAIN-SUFFIX,google.com,'],
  ['china-providers','DIRECT','RULE-SET,国内域名,'],
  ['udp','日常线路','NETWORK,UDP,']
];

// This exact host has appeared on both sides of the domestic console block.
// The intervening rules must be distinct exact hosts, so moving it to the
// stable provider boundary cannot change first-match routing semantics.
function normalizedRules(rules) {
  const result = rules.slice();
  const exact = 'DOMAIN,r.applovin.com,日常线路';
  const start = result.indexOf(exact);
  const end = result.findIndex(rule => rule === 'DOMAIN,lf3-ad-platform.byteadverts.com,DIRECT');
  if (start < 0 || end < 0 || result.lastIndexOf(exact) !== start || start > end) return result;
  const crossed = result.slice(start + 1, end + 1);
  if (!crossed.every(rule => {
    const fields = rule.split(',');
    return fields.length === 3 && fields[0] === 'DOMAIN' && fields[1] !== 'r.applovin.com' &&
      (fields[2] === 'DIRECT' || fields[2] === '日常线路');
  })) throw new Error('后台规则顺序变化可能影响匹配');
  result.splice(start, 1);
  result.splice(end, 0, exact);
  return result;
}

function buildStandardProvider(input) {
  const query = input.$options?._req?.query || {};
  const part = query.part;
  if (typeof part !== 'string' || !part) throw new Error('缺少规则集类型');
  const source = ProxyUtils.yaml.safeLoad(input.$content);
  const profile = source?.stash || source;
  if (!profile || !Array.isArray(profile.rules) || !profile['rule-providers']) {
    throw new Error('当前订阅缺少规则或规则集');
  }
  const runs = [];
  for (const rule of normalizedRules(profile.rules)) {
    if (typeof rule !== 'string') throw new Error('当前规则格式不正确');
    const fields = rule.split(',');
    const kind = fields[0];
    const target = kind === 'MATCH' ? fields[1] : fields[2];
    if (!target) throw new Error('当前规则缺少策略');
    const klass = kind === 'RULE-SET' ? 'provider' : 'rule';
    const last = runs[runs.length-1];
    if (!last || last.target !== target || last.klass !== klass) {
      runs.push({target,klass,rules:[rule]});
    } else last.rules.push(rule);
  }
  if (runs.length !== expected.length) throw new Error('规则顺序已变化，请更新独立规则集');
  const byName = {};
  expected.forEach(([name, target, start], i) => {
    const run = runs[i];
    if (run.target !== target || !run.rules[0].startsWith(start)) {
      throw new Error('规则顺序已变化，请更新独立规则集');
    }
    byName[name] = run;
  });
  if (byName['china-providers'].rules.length !== 2 ||
      byName['china-providers'].rules[1] !== 'RULE-SET,国内IP,DIRECT' ||
      byName.udp.rules.length !== 2 || byName.udp.rules[1] !== 'MATCH,日常线路') {
    throw new Error('规则集或兜底规则已变化，请更新独立规则集');
  }
  if (part === 'applovin-console') {
    const domains = ['ads.applovin.com', 'max.applovin.com', 'dash.applovin.com',
      'r.applovin.com', 'developers.applovin.com', 'support.applovin.com'];
    const published = new Set(profile.rules);
    if (!domains.every(domain => published.has('DOMAIN,' + domain + ',日常线路'))) {
      throw new Error('AppLovin 后台例外与现行订阅不一致');
    }
    input.$content = domains.map(domain => 'DOMAIN,' + domain).join('\n') + '\n';
    return input;
  }
  const businessConsole = {
    'business-overseas': {target:'日常线路', domains:[
      'ads.applovin.com', 'ads.tiktok.com', 'max.applovin.com', 'dash.applovin.com',
      'r.applovin.com', 'developers.applovin.com', 'support.applovin.com', 'analytics.google.com'
    ]},
    'business-cn': {target:'DIRECT', domains:[
      'e.qq.com', 'ad.qq.com', 'ad.e.kuaishou.com', 'ad-m.e.kuaishou.com',
      'dapi.e.kuaishou.com', 'p4-ad.adkwai.com', 'p5-ad.adkwai.com',
      'lf3-ad-platform.byteadverts.com'
    ]}
  };
  if (part === 'business-all') {
    const groups = Object.values(businessConsole);
    const published = new Set(profile.rules);
    if (!groups.every(({target, domains}) =>
        domains.every(domain => published.has('DOMAIN,' + domain + ',' + target)))) {
      throw new Error('投放后台例外与现行订阅不一致');
    }
    input.$content = groups.flatMap(({domains}) => domains)
      .map(domain => 'DOMAIN,' + domain).join('\n') + '\n';
    return input;
  }
  if (Object.prototype.hasOwnProperty.call(businessConsole, part)) {
    const {target, domains} = businessConsole[part];
    const published = new Set(profile.rules);
    if (!domains.every(domain => published.has('DOMAIN,' + domain + ',' + target))) {
      throw new Error('投放后台例外与现行订阅不一致');
    }
    input.$content = domains.map(domain => 'DOMAIN,' + domain).join('\n') + '\n';
    return input;
  }
  if (part === 'ads' || part === 'china-domains' || part === 'china-ip') {
    const provider = profile['rule-providers'][{
      'ads':'广告域名','china-domains':'国内域名','china-ip':'国内IP'
    }[part]];
    if (!provider || provider.format !== 'mrs' ||
        provider.behavior !== (part === 'china-ip' ? 'ipcidr' : 'domain')) {
      throw new Error('当前规则集格式已变化');
    }
    const url = provider.url;
    const valid = part === 'ads'
      ? typeof url === 'string' && url.startsWith(allowedAdOrigin+'/rules/ad/ads-') &&
        /^ads-[0-9a-f]{64}\.mrs$/.test(url.slice((allowedAdOrigin+'/rules/ad/').length))
      : url === 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/'+
        (part === 'china-ip' ? 'geoip/cn.mrs' : 'geosite/cn.mrs');
    if (!valid) throw new Error('当前规则集地址不符合安全范围');
    input.$options._res = {status:302, headers:{Location:url, 'Cache-Control':'private, no-store'}};
    input.$content = '';
    return input;
  }
  const run = byName[part];
  if (!run || run.klass !== 'rule') throw new Error('未知规则集类型');
  const allowed = new Set(['DOMAIN','DOMAIN-SUFFIX','IP-CIDR','IP-CIDR6','DST-PORT','NETWORK']);
  const output = [];
  for (const rule of run.rules) {
    const fields = rule.split(',');
    if (fields[0] === 'MATCH') continue;
    if (!allowed.has(fields[0]) || fields.length < 3 || fields[2] !== run.target) {
      throw new Error('规则类型已变化，请更新独立规则集');
    }
    output.push([fields[0],fields[1],...fields.slice(3)].join(','));
  }
  if (!output.length) throw new Error('规则集没有内容');
  input.$content = output.join('\n')+'\n';
  return input;
}

function operator(input) {
  try { return buildStandardProvider(input); }
  catch (error) {
    // Sub-Store may otherwise continue after an operator error and expose the
    // input. The input is separately restricted to a sanitized local snapshot.
    input.$content = '';
    input.$options = input.$options || {};
    input.$options._res = {status:503,headers:{'Cache-Control':'private, no-store'}};
    return input;
  }
}
