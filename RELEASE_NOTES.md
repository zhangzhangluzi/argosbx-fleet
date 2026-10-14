v1.2.5 统一 Stash 文件地址与通用下载地址的版本兼容。
- `/api/file/stash` 按原始客户端 User-Agent 选择兼容节点；旧版或版本未知时过滤 XHTTP／VLESS Encryption，新版保留完整参数。
- 共用兼容判断，节点过滤后重建分组；通用下载向文件处理器传递客户端信息，避免新版节点被二次误过滤。
- 文件响应采用 YAML、Vary: User-Agent 与 private, no-store；原统一订阅及各国家链接不变。
- 发布前后增加真实文件接口的新旧 iOS、macOS 与无版本验收，保留已有下载接口验证。
- 仅更新维护代码与 Sub-Store 处理器，不修改监听配置或重启代理服务。
