// Convert only the domain category used by Clash/Stash; do not broaden its scope.
function operator(input) {
  const domains = input.$content.split(/\r?\n/).map(s => s.trim())
    .filter(s => s && !s.startsWith('#'));
  if (!domains.length || domains.some(s => !/^(\+\.)?[a-z0-9_-]+(\.[a-z0-9_-]+)+$/i.test(s))) {
    throw new Error('Unexpected ad domain-set format');
  }
  input.$content = [...new Set(domains.map(s => s.replace(/^\+\./, '.')))].join('\n') + '\n';
  return input;
}
