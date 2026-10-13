v1.1.5 国内 IP 兜底与现有 Tailscale 共存。
- 只移除末尾国内 IP / GEOIP 兜底的 no-resolve，保留应用、广告例外和其他 IP 规则优先级。
- 私有 inventory 可填写实际 MagicDNS 域名；Clash / Stash 同步专用解析、Fake-IP 排除与 Tailnet 直连，Mihomo 同步 TUN 排除。
- 仅本机 MagicDNS 例外先于明文 DNS 拦截，不放行整个 ts.net，不改变公网 DNS 策略。
- 收录已在线使用的 UU 远程 / ToDesk / 向日葵直连规则及回归测试。
- 原统一和国家订阅地址、节点身份、协议参数不变；维护工具升级不重启代理进程。
