# ArgoSBX Fleet v1.2.30

统一订阅和七国合集的 Stash 配置可通过原地址定时更新。生成器只为完整合集写入各自的更新地址。升级脚本先用临时模板校验，再通过原链接回读，验收失败时恢复本次改动。

广告规则可在两份聚合订阅中定时更新。Mihomo／Stash 的 MRS 与 Shadowrocket 域名列表采用同一份校验快照。保留精确的 AppLovin 后台例外，源站短时不可达时可继续使用上次校验的订阅源缓存。

空白机初始化改用官方 Xray 26.10.31，并固定 amd64 和 arm64 的 SHA256。维护包安装只更新维护脚本。[Xray 发布说明](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31)
