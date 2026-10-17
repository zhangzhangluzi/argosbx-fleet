# v1.2.9
补齐 api.x.ai、console.x.ai 的 AI 分流及 DNS 策略，三种客户端保持一致，不扩大到整个 x.ai 域名。
Stash 文件和下载入口均显式下发节点级 benchmark-url（HTTP 204）与 8 秒 benchmark-timeout；保留半小时按需测速、上层选择组禁用递归定时测试、订阅内去广告开关及版本兼容过滤。
空白机安装清单更新 cloudflared 2026.10.1 的 amd64／arm64 官方校验和。维护代码安装不会自动重启或更新线上连接器；现有机器使用同隧道副本先验证、空闲后交接的独立流程。
统一及各国家订阅 URL、节点名称、协议凭据和 Xray／sing-box 配置均保留。
