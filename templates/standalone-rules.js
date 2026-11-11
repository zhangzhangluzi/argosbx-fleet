// Sub-Store file operator. Its input must be a sanitized rules-only profile.
const standaloneFormat = 'STANDALONE_FORMAT';

function applyStandaloneRules(config, bundle) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    throw new Error('配置必须是对象');
  }
  const oldGroups = config['proxy-groups'] || [];
  const oldRules = config.rules || [];
  const oldProviders = config['rule-providers'] || {};
  if (!Array.isArray(oldGroups) || !Array.isArray(oldRules) ||
      !oldProviders || typeof oldProviders !== 'object' || Array.isArray(oldProviders)) {
    throw new Error('原配置的策略组、规则或规则集格式不正确');
  }
  const occupied = new Set(oldGroups.map(group => group.name));
  for (const group of bundle.groups) {
    if (occupied.has(group.name)) throw new Error('独立规则策略组名称冲突：' + group.name);
  }
  for (const name of Object.keys(bundle.providers)) {
    if (Object.prototype.hasOwnProperty.call(oldProviders, name)) {
      throw new Error('独立规则集名称冲突：' + name);
    }
  }
  config['proxy-groups'] = [...bundle.groups, ...oldGroups];
  config['rule-providers'] = {...oldProviders, ...bundle.providers};
  config.rules = [...bundle.rules, ...oldRules];
  return config;
}

function buildStandalone(input) {
  const source = ProxyUtils.yaml.safeLoad(input.$content);
  const profile = source?.[standaloneFormat] || source;
  if (!profile || !Array.isArray(profile.rules) || !profile['rule-providers']) {
    throw new Error('当前订阅缺少规则或规则集');
  }
  const names = {
    '日常线路': '独立规则·日常线路',
    'AI线路': '独立规则·AI线路',
    'Telegram': '独立规则·Telegram',
    '去广告': '独立规则·去广告',
    '国内域名': '独立规则·国内域名',
    '国内IP': '独立规则·国内IP',
    '广告域名': '独立规则·广告域名'
  };
  const providerFiles = {'国内域名':'cn-domain', '国内IP':'cn-ip', '广告域名':'ad-domain'};
  const providers = {};
  for (const [name, file] of Object.entries(providerFiles)) {
    const original = profile['rule-providers'][name];
    if (!original || original.behavior == null || !original.url) {
      throw new Error('当前订阅缺少规则集：' + name);
    }
    const value = {...original};
    if (value.proxy && names[value.proxy]) value.proxy = names[value.proxy];
    if (value.path) value.path = './ruleset/standalone-' + file + '.mrs';
    providers[names[name]] = value;
  }
  // The source profile owns DNS interception and its final MATCH. An additive
  // rule bundle must not impose either on an unrelated existing profile.
  const rules = profile.rules.filter(rule => !/^MATCH,/.test(rule) &&
    rule !== 'DST-PORT,53,REJECT' && rule !== 'DST-PORT,853,日常线路')
    .map(rule => rule.split(',').map(part => names[part] || part).join(','));
  if (!rules.some(rule => rule === 'RULE-SET,独立规则·广告域名,独立规则·去广告')) {
    throw new Error('广告规则不完整');
  }
  const prefix = '独立规则·';
  const common = standaloneFormat === 'stash' ? {interval:-1} : {};
  const groups = [
    {name:prefix+'日常线路',type:'select',proxies:[prefix+'自动节点','REJECT'], 'include-all':true,...common},
    {name:prefix+'AI线路',type:'select',proxies:[prefix+'日常线路'], 'include-all':true,...common},
    {name:prefix+'Telegram',type:'select',proxies:[prefix+'日常线路'], 'include-all':true,...common},
    {name:prefix+'自动节点',type:'url-test',proxies:['REJECT'],'include-all':true,
      url:'https://www.gstatic.com/generate_204',interval:1800,tolerance:100,lazy:true},
    {name:prefix+'去广告',type:'select',proxies:[prefix+'开启去广告',prefix+'关闭去广告'],...common},
    {name:prefix+'开启去广告',type:'select',proxies:['REJECT'],hidden:true,...common},
    {name:prefix+'关闭去广告',type:'select',proxies:[standaloneFormat === 'stash' ? prefix+'日常线路' : 'PASS'],hidden:true,...common}
  ];
  if (standaloneFormat === 'stash') {
    input.$content = ProxyUtils.yaml.safeDump({
      name:'独立分流与去广告',
      desc:'引用已有节点；保留原配置 DNS 与未匹配规则。',
      'proxy-groups':groups,'rule-providers':providers,rules
    });
  } else if (standaloneFormat === 'clash') {
    const bundle = JSON.stringify({groups,providers,rules});
    input.$content = 'const standaloneRuleBundle = '+bundle+';\n'+
      applyStandaloneRules.toString()+'\nfunction main(config) { return applyStandaloneRules(config, standaloneRuleBundle); }\n';
  } else {
    throw new Error('未知客户端类型');
  }
  return input;
}

function operator(input) {
  try { return buildStandalone(input); }
  catch (error) {
    input.$content = '';
    input.$options = input.$options || {};
    input.$options._res = {status:503,headers:{'Cache-Control':'private, no-store'}};
    return input;
  }
}
