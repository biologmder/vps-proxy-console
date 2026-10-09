# 入站协议矩阵与界面设计

本项目将「客户端连接入口」与「中转落地入口」分开呈现。配置界面只展示当前 Xray 配置编译器、订阅生成器和测试覆盖的组合，不把尚未实现的传输或协议列成可选项。

入站与 3x-ui 一样拆成**协议 / 传输 / 安全层**三个独立字段，任意受支持的组合都可选择。旧版的组合名（`vless-reality`、`vless-tls`、`trojan-tls`、`vmess-ws-tls`、`ss`）在读取时自动转换，无需迁移。允许的组合以 `internal/model/inbound.go` 的 `CheckCombination` 为准，前端 `InboundEditor.tsx` 与之保持一致。

| 协议 | 传输 | 安全层 | 备注 | Mihomo 订阅 |
| --- | --- | --- | --- | --- |
| VLESS | TCP、WebSocket、gRPC、HTTPUpgrade、XHTTP | 无、TLS、REALITY（REALITY 仅 TCP/gRPC/XHTTP） | `xtls-rprx-vision` 仅 TCP + TLS/REALITY | XHTTP 跳过，其余包含 |
| VMess | TCP、WebSocket、gRPC、HTTPUpgrade | 无、TLS | | 包含 |
| Trojan | TCP、WebSocket、gRPC、HTTPUpgrade | TLS、REALITY | | REALITY 跳过，其余包含 |
| Shadowsocks | TCP + UDP | — | 2022-blake3-aes-128/256-gcm、2022-blake3-chacha20-poly1305、aes-256/128-gcm、chacha20-ietf-poly1305 | 包含 |
| SOCKS5 / HTTP 落地 | TCP | 独立账号密码，依赖既有私网/隧道 | 只监听节点私网 IP | 不进入订阅 |

TLS 证书由 Agent 通过节点 80 端口申请；REALITY 不需要本机证书。XHTTP 与 Trojan+REALITY 的分享链接仍出现在通用（Base64）订阅中。

## 操作逻辑

- 表单分为「基本设置 / 协议设置 / 传输 / 安全」四段；切换协议或传输时，不支持的安全层与 Flow 会自动回落到可用值。
- 选节点后建议端口，冲突时随机高位端口；名称可留空自动生成。WS/HTTPUpgrade 路径默认随机，XHTTP 默认 `/xhttp`，gRPC 默认 `grpc`。
- REALITY 的目标（dest）与 SNI 分开填写，不与 VPS 自己的域名混淆；密钥与 Short ID 由后端生成，编辑时可一键重新生成（所有人需更新订阅）。
- Shadowsocks 2022 的服务密钥与每人密钥按方法要求的长度自动生成；2022 与传统加密之间不可互相切换。
- 编辑已有入站时协议和节点不可修改，以免破坏已有用户凭据；传输与安全层可以修改。

## 默认安全策略

每个节点的路由第一条固定为 `geoip:private → block`，并使用 `IPOnDemand` 域名策略，使解析到私网地址的域名同样被拦截。代理用户因此无法访问节点本机（含 `127.0.0.1:10085` 的 Xray 统计 API）及隧道内的其他主机。落地出口由 Xray 自身发起连接，不受该规则影响。

## 参考项目中的取舍

- [3x-ui 入站文档](https://docs.sanaei.dev/zh/docs/config/inbounds/)将协议、传输、安全层与客户端分开，并提供更大的协议/传输矩阵。本项目首版采用经过端到端验证的固定组合，避免展示不能生成正确订阅的选项。
- [3x-ui REALITY 文档](https://docs.sanaei.dev/zh/docs/config/reality/)与 [Xray REALITY 文档](https://xtls.github.io/en/config/transports/reality.html)明确区分目标地址、SNI、密钥和 Short ID，因此界面不再用笼统的「域名/SNI」字段。
- [RelayPanel](https://github.com/MoeShinX/relay-panel)的核心是 TCP/UDP 转发规则与节点状态，并非 Xray 客户端协议矩阵；本项目借鉴其「节点/规则分开管理」的思路，不把端口转发误写成代理入站。
- [ForwardX](https://github.com/poouo/Forwardx)将入口、中转、出口链路资源与业务转发规则分开；本项目对应地将私网落地 SOCKS5/HTTP 与公网订阅入口分组，出口链路则继续在「出口与落地」管理。

后续若增加 Hysteria2、TUIC、WireGuard 或通用端口转发，须同时完成节点配置编译、客户端订阅格式、流量计量、真实核心配置测试后，才能加入此矩阵。
