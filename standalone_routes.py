"""Caddy scope for read-only, separately tokenized rule downloads."""

MARKER = '# BEGIN STANDALONE RULE SHARES'
END = '# END STANDALONE RULE SHARES'
ROUTES = '''# BEGIN STANDALONE RULE SHARES
@standalone_rule_share path /share/file/standalone-stash /share/file/standalone-flclash
handle @standalone_rule_share {
 encode gzip
 @standalone_rule_method not method GET
 respond @standalone_rule_method 405
 header Cache-Control "private, no-store"
 header Referrer-Policy "no-referrer"
 header X-Content-Type-Options "nosniff"
 reverse_proxy 127.0.0.1:3001
}
# END STANDALONE RULE SHARES
'''


def render(text):
    if text.count(ROUTES) == 1 and text.count(MARKER) == text.count(END) == 1:
        return text
    if (MARKER in text or END in text or '/share/file/standalone-stash' in text or
            '/share/file/standalone-flclash' in text):
        raise ValueError('独立规则路由范围无法确认，保留原配置')
    if text.count('# END EXTERNAL SEVEN SHARES') != 1:
        raise ValueError('原分享路由未确认，保留原配置')
    return text + '\n' + ROUTES
