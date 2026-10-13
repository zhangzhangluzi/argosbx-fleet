v1.1.4 自动覆盖全部可用 ECH 入口。
- CF 固定使用 cloudflare-ech.com 与阿里 DoH 默认值，自动解析公钥。
- AnyTLS、Hysteria2、Salamander 自动生成并保留独立原生 ECH 密钥，订阅只导出公开配置。
- 修复 Mihomo ECH DNS 引导策略及 Sub-Store VMess URI 丢失 ECH，保留原订阅路径、节点身份、分组和路由。
- REALITY、ShadowTLS 维持其原生机制，不输出被内核忽略的普通 ECH 参数。
- 支持应用后保留恢复日志，握手验收通过再提交；新增独立 TLS/QUIC ECHAccepted 验收工具与密钥一致性回归。
首次启用 ECH 会重启受影响的 Xray/sing-box 服务；维护代码安装本身不重启。
