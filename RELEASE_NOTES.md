# ArgoSBX Fleet v1.2.16
支持通过 inventory 的 cloudflare.management_server 将全部维护命令的 CF API 请求固定到指定服务器。使用独立 OpenSSH 本地转发，入口仅监听控制机回环地址；CF 的 DNS 在出口服务器解析为 IPv4，TLS 在控制机校验 api.cloudflare.com，管理令牌不落盘出口服务器。
发送令牌前通过同一通道核对 Cloudflare 看到的源 IPv4；不匹配或通道失败时停止，不回退本机。审计展示实际管理出口与白名单匹配情况。独立 SSH 进程在命令结束时清理，不修改系统代理、VPN、服务或订阅。
