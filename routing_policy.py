"""Shared application routing; no broad platform or login-domain bypasses."""
AI_DOMAINS = ('chatgpt.com', 'openai.com', 'oaistatic.com', 'oaiusercontent.com', 'claude.ai', 'anthropic.com', 'gemini.google.com', 'aistudio.google.com', 'generativelanguage.googleapis.com', 'notebooklm.google.com', 'notebooklm.google', 'notebook.google', 'copilot.microsoft.com', 'copilot.com', 'copilot.cloud.microsoft', 'grok.com', 'grok.x.ai', 'accounts.x.ai', 'api.x.ai', 'console.x.ai')

DIAGNOSTIC_DOMAINS = ['browserleaks.com', 'dnsleaktest.com', 'ipleak.net']
# Small explicit fast path, after purpose/ad rules and before resolving IP rules.
# Do not capture shared CDNs or all Microsoft/Apple domains.
OVERSEAS_DOMAINS = ['google.com', 'youtube.com', 'youtu.be', 'ytimg.com',
                    'googlevideo.com', 'github.com', 'githubusercontent.com',
                    'githubassets.com', 'x.com', 'twitter.com', 't.co', 'twimg.com']


def overseas_rules(rules):
    additions = ['DOMAIN-SUFFIX,'+d+',日常线路' for d in OVERSEAS_DOMAINS]
    result = [r for r in rules if r not in additions]
    index = next((i for i,r in enumerate(result) if r == 'RULE-SET,国内域名,DIRECT'
                  or r.startswith('DOMAIN-SET,') or r == 'GEOIP,CN,DIRECT'), len(result)-1)
    return result[:index] + additions + result[index:]


def ai_rules(rules):
    rules=list(rules)
    indexes=[i for i,r in enumerate(rules) if r.endswith(",AI线路")]
    at=indexes[0] if indexes else next((i for i,r in enumerate(rules) if r.startswith(("RULE-SET,国内", "GEOIP,CN", "MATCH,", "FINAL,"))),len(rules))
    before=[r for r in rules[:at] if not r.endswith(",AI线路")]
    after=[r for r in rules[at:] if not r.endswith(",AI线路")]
    return before+["DOMAIN-SUFFIX,"+d+",AI线路" for d in AI_DOMAINS]+after
