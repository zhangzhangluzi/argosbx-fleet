"""Give the two authenticated rule shares conventional client extensions."""

MARKER = '# BEGIN STANDALONE RULE ALIASES'
END = '# END STANDALONE RULE ALIASES'
ROUTES = '''# BEGIN STANDALONE RULE ALIASES
@standalone_stash_alias path /rules/independent.stoverride
handle @standalone_stash_alias {
 @standalone_stash_method not method GET
 respond @standalone_stash_method 405
 header Cache-Control "private, no-store"
 header Referrer-Policy "no-referrer"
 header X-Content-Type-Options "nosniff"
 rewrite * /share/file/standalone-stash
 reverse_proxy 127.0.0.1:3001
}
@standalone_flclash_alias path /rules/independent.js
handle @standalone_flclash_alias {
 @standalone_flclash_method not method GET
 respond @standalone_flclash_method 405
 header Cache-Control "private, no-store"
 header Referrer-Policy "no-referrer"
 header X-Content-Type-Options "nosniff"
 rewrite * /share/file/standalone-flclash
 reverse_proxy 127.0.0.1:3001
}
# END STANDALONE RULE ALIASES
'''


def render(text):
    if text.count(ROUTES) == 1 and text.count(MARKER) == text.count(END) == 1:
        return text
    if (MARKER in text or END in text or '/rules/independent.stoverride' in text or
            '/rules/independent.js' in text):
        raise ValueError('独立规则别名范围无法确认，保留原配置')
    if text.count('# END STANDALONE RULE SHARES') != 1:
        raise ValueError('原独立规则分享路由未确认')
    return text + '\n' + ROUTES
