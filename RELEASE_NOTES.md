# ArgoSBX Fleet v1.2.22
CF VMess WebSocket 默认由现有 sing-box 承接，兼容 TLS 下自动选择 zero 的现有客户端。Xray 26.10.29 不再接受该模式；保留旧客户端的 auto、UUID、端口、WS 路径、分组和订阅身份即可继续连接，无需先强制客户端刷新或改用新协议。
新增无副作用的 VMess 后端迁移规划，可与 REALITY 迁移组合。旧 Xray 与新 sing-box 入站均支持读取、编辑、启停和导出；特殊路由、旧式用户或无法映射的安全选项会拒绝迁移，保留其他入站及共享 DNS／出站引用。
原生 CI 增加 TLS 终止转发夹具，以真实 HTTPS、UDP 验证 auto、zero、AES-GCM 和 ChaCha20-Poly1305 四种 VMess 客户端模式，避免明文回环掩盖兼容性问题。隔离探针使用节点实际 cipher。
新机 cloudflared 固定到 2026.10.7，包含 HTTP/2 并发回归修复；Xray 26.10.29、sing-box 1.14.4 和 Caddy 2.11.7 保持。维护工具安装本身仍不替换运行内核或重启服务；实际迁移和运行升级需按事务分批验收，原订阅链接不变。
