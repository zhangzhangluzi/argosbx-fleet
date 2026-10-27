# ArgoSBX Fleet v1.2.15
明确 Cloudflare Token 详情接口 403／9109 的权限边界：资源管理 Token 无需为审计额外获得 Token 管理权限。支持引用控制台核实的 0600 策略快照，校验 Token ID、凭据摘要及 24 小时时效，并标注证据来源。兼容 request_ip／request.ip 两种 IP 过滤字段，明确区分允许所有 IP、受限与未知。
增加显式 --verify-writes：仅对随机独立 TXT 和无连接器、无 DNS 路由的测试隧道执行写入回读及清理。写前保存私有意图日志，未知结果可通过 --recover-writes 按标记恢复；资源被其他操作使用或修改时拒绝清理。默认审计仍只读。
仅更新维护代码，保留现有 Token 权限、代理进程、CF 正式配置和原统一／国家订阅地址。
