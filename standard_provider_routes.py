"""Expose only two authenticated read-only Sub-Store rule-provider files."""
MARKER='# BEGIN STANDARD RULE PROVIDERS'
END='# END STANDARD RULE PROVIDERS'
ROUTES='''# BEGIN STANDARD RULE PROVIDERS
@standard_provider path /rules/providers/standard.txt /rules/providers/standard.mrs
handle @standard_provider {
 @standard_provider_noget not method GET
 respond @standard_provider_noget 405
 header Cache-Control "private, no-store"
 header Referrer-Policy "no-referrer"
 header X-Content-Type-Options "nosniff"
 rewrite * /share/file/standard-rule-provider
 reverse_proxy 127.0.0.1:3001
}
@standard_process path /rules/providers/process.txt
handle @standard_process {
 @standard_process_noget not method GET
 respond @standard_process_noget 405
 header Cache-Control "private, no-store"
 header Referrer-Policy "no-referrer"
 header X-Content-Type-Options "nosniff"
 rewrite * /share/file/standard-process-provider
 reverse_proxy 127.0.0.1:3001
}
# END STANDARD RULE PROVIDERS
'''

def render(text):
    if text.count(ROUTES)==1 and text.count(MARKER)==text.count(END)==1:return text
    if (MARKER in text or END in text or '/rules/providers/standard.txt' in text or
            '/rules/providers/standard.mrs' in text or '/rules/providers/process.txt' in text):
        raise ValueError('标准规则集路由存在冲突，保留现有配置')
    if text.count('# END EXTERNAL SEVEN SHARES') != 1:
        raise ValueError('现有分享路由未确认')
    return text+'\n'+ROUTES
