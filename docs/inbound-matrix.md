# 入站协议矩阵与界面设计

本项目将「客户端连接入口」与「中转落地入口」分开呈现。配置界面只展示当前 Xray 配置编译器、订阅生成器和测试覆盖的组合，不把尚未实现的传输或协议列成可选项。

| 用途 | 面板选项 | 传输 | 安全层 | 证书 | 出现在个人订阅 |
| --- | --- | --- | --- | --- | --- |
| 客户端入口 | VLESS · REALITY | TCP/RAW | REALITY + Vision | 无需本机证书 | 是 |
| 客户端入口 | VLESS · TLS | TCP/RAW | TLS | 节点域名证书 | 是 |
| 客户端入口 | Trojan · TLS | TCP/RAW | TLS | 节点域名证书 | 是 |
| 客户端入口 | VMess · WS | WebSocket | TLS | 节点域名证书 | 是 |
| 客户端入口 | Shadowsocks | TCP + UDP | AES-256-GCM | 不需要 | 是 |
| 私网落地 | SOCKS5 | TCP | 独立账号密码，依赖既有私网/隧道 | 不需要 | 否 |
| 私网落地 | HTTP | TCP | 独立账号密码，依赖既有私网/隧道 | 不需要 | 否 |

## 操作逻辑

- 先选「客户端入口」或「私网落地」，再选上表中的协议卡片；每张卡片说明传输和安全层。
- 选节点后建议可用端口；名称可留空自动生成。TLS 类使用节点域名作默认证书域名，VMess WS 默认路径 `/ws`。
- REALITY 的伪装站点 SNI 与目标单独命名，不与 VPS 自己的域名混淆；初始示例为 `www.microsoft.com:443`，应按节点网络环境选择真实可访问的目标。密钥与 Short ID 由后端生成。
- SOCKS5/HTTP 强制使用节点私网 IP，不进入订阅；服务账号密码默认自动生成。加密隧道与节点间连通由已有网络提供。
- 高级设置只放监听地址、私网账号密码、Shadowsocks 服务密码和启用开关。编辑已有入站时保持协议不变，以免破坏已有用户凭据。

## 参考项目中的取舍

- [3x-ui 入站文档](https://docs.sanaei.dev/zh/docs/config/inbounds/)将协议、传输、安全层与客户端分开，并提供更大的协议/传输矩阵。本项目首版采用经过端到端验证的固定组合，避免展示不能生成正确订阅的选项。
- [3x-ui REALITY 文档](https://docs.sanaei.dev/zh/docs/config/reality/)与 [Xray REALITY 文档](https://xtls.github.io/en/config/transports/reality.html)明确区分目标地址、SNI、密钥和 Short ID，因此界面不再用笼统的「域名/SNI」字段。
- [RelayPanel](https://github.com/MoeShinX/relay-panel)的核心是 TCP/UDP 转发规则与节点状态，并非 Xray 客户端协议矩阵；本项目借鉴其「节点/规则分开管理」的思路，不把端口转发误写成代理入站。
- [ForwardX](https://github.com/poouo/Forwardx)将入口、中转、出口链路资源与业务转发规则分开；本项目对应地将私网落地 SOCKS5/HTTP 与公网订阅入口分组，出口链路则继续在「出口与落地」管理。

后续若增加 Hysteria2、TUIC、gRPC、XHTTP、WireGuard 或通用端口转发，须同时完成节点配置编译、客户端订阅格式、流量计量、真实核心配置测试后，才能加入此矩阵。
