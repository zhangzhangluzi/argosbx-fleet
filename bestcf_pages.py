"""Attach the JP-only subscription handler to the existing Germany Worker."""
from pathlib import Path


def patch(source):
    helper = Path(__file__).with_name('bestcf-pages-sub.js').read_text()
    marker = 'export default {'
    if source.count(marker) != 1:
        raise ValueError('Worker entry point changed')
    source = source.replace(marker, helper + '\n' + marker, 1)
    marker = '\t\t\t\t\t\tconfig_JSON = await 读取config_JSON(env, host, userID, UA);'
    if source.count(marker) != 1:
        raise ValueError('Worker subscription hook changed')
    hook = ("\t\t\t\t\t\tif (用户客户端请求订阅) {\n"
            "\t\t\t\t\t\tconst jpResult = await japanSelfSubscription(request, env, url, UA);\n"
            "\t\t\t\t\t\tif (jpResult) return jpResult;\n"
            "\t\t\t\t\t\t}\n")
    return source.replace(marker, hook + marker, 1)
