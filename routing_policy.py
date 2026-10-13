"""Shared application routing; no broad platform or login-domain bypasses."""
AI_DOMAINS = ('chatgpt.com', 'openai.com', 'oaistatic.com', 'oaiusercontent.com', 'claude.ai', 'anthropic.com', 'gemini.google.com', 'aistudio.google.com', 'generativelanguage.googleapis.com', 'notebooklm.google.com', 'notebooklm.google', 'notebook.google', 'copilot.microsoft.com', 'copilot.com', 'copilot.cloud.microsoft', 'grok.com', 'grok.x.ai', 'accounts.x.ai')

def ai_rules(rules):
    rules=list(rules)
    indexes=[i for i,r in enumerate(rules) if r.endswith(",AI线路")]
    at=indexes[0] if indexes else next((i for i,r in enumerate(rules) if r.startswith(("RULE-SET,国内", "GEOIP,CN", "MATCH,", "FINAL,"))),len(rules))
    before=[r for r in rules[:at] if not r.endswith(",AI线路")]
    after=[r for r in rules[at:] if not r.endswith(",AI线路")]
    return before+["DOMAIN-SUFFIX,"+d+",AI线路" for d in AI_DOMAINS]+after
