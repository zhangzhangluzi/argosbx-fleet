// The iOS Stash core cannot apply process rules; this source is for FlClash.
function buildProcessProvider(input) {
  const source=ProxyUtils.yaml.safeLoad(input.$content);
  const config=source?.clash || source;
  if (!config || !Array.isArray(config.rules)) throw new Error('当前配置缺少规则');
  const rules=config.rules.filter(rule => typeof rule === 'string' &&
    rule.startsWith('PROCESS-NAME-REGEX,'));
  if (rules.length !== 1 || !rules[0].endsWith(',DIRECT')) {
    throw new Error('当前进程规则已变化');
  }
  input.$content=rules[0].slice(0,-',DIRECT'.length)+'\n';
  return input;
}

function operator(input) {
  try { return buildProcessProvider(input); }
  catch (error) {
    input.$content='';
    input.$options=input.$options || {};
    input.$options._res={status:503,headers:{'Cache-Control':'private, no-store'}};
    return input;
  }
}
