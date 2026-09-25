# VPS Proxy Console

一个自托管的多 VPS 代理与订阅管理 MVP。中心面板管理人员、节点、入站、出口与分流规则；每台 VPS 运行主动连接面板的 Agent，并由 Agent 管理 Xray-core。

> 当前为 MVP。请先在隔离的测试 VPS 上验证，再迁移现有线路。尚未在真实两台 VPS 上完成端到端验收。

## 已实现范围

- 入站：VLESS/TLS、VLESS/REALITY、Trojan/TLS、Shadowsocks、VMess/WebSocket/TLS；SOCKS5/HTTP 落地入口仅可监听节点私网 IP。
- 新建入站采用按用途分组的协议卡片，只显示所选协议必需字段；完整支持范围见[入站协议矩阵](docs/inbound-matrix.md)。
- 出口：本机直连、阻断、手动 SOCKS5/HTTP 上游、面板管理的落地入口。
- 分流：按用户、入站、域名或 IP/CIDR 匹配；按 `position` 从小到大生效。域名与 IP 列表分开编译为同优先级规则；两者是“或”，用户与入站条件是“且”。未匹配时直连。
- 人员：独立凭据、跨入口节点总额度、到期时间、禁用、可轮换订阅令牌。额度按入口用户的上行加下行统计；Agent 20 秒周期上报，允许短时超额。
- 订阅：通用分享链接集合（Base64）与 Mihomo YAML。`/sub/<token>?format=mihomo` 获取 Mihomo 配置；未指定格式时返回 Base64 链接。
- Agent：主动经 HTTPS 拉取配置，Xray `run -test` 校验，应用失败恢复旧配置；统计与最近有效配置保存在持久卷中。代理节点通过 ACME HTTP-01 自动领取 TLS 证书。
- Telegram：节点离线、配置应用失败、证书临期、用量达到 80% 的提醒。

## 部署要求

- Linux VPS，Docker Compose v2；面板一台，入口/落地节点可分别部署在多台 VPS。
- 面板域名由 Cloudflare 管理并解析到面板 VPS。面板默认只开放 TCP `8443`，**不占用主机的 80/443**；可在 `.env` 中通过 `PANEL_PORT` 改为其他端口。DNS-01 签发面板证书，不要求面板对外开放 80/443。
- 每个 TLS 入站域名解析到对应节点。节点 Agent 仍需占用 TCP 80 完成其入站证书的 HTTP-01 验证，并开放所配置的代理端口；Shadowsocks 如需 UDP，还需开放同端口 UDP。面板和 Agent 可以同机运行，只要面板高位端口不与入站端口冲突。
- 如果面板域名在 Cloudflare 开启代理（橙云），`PANEL_PORT` 应选 Cloudflare 支持的 HTTPS 端口，例如 `8443`、`2053`、`2083`、`2087` 或 `2096`；使用其他高位端口时，将该记录设为 DNS-only。
- 若入口要连接落地 SOCKS5/HTTP，先由你现有的 WireGuard/Tailscale 等网络提供私网连通；面板不会创建隧道。SOCKS5/HTTP **不能**填 `0.0.0.0` 或公网 IP。
- 面板与 Agent 的系统时间应准确，否则证书、到期和流量统计会受影响。
- 下方使用 HTTPS 克隆地址，无需在 VPS 上配置 GitHub SSH 公钥。`git@github.com:...` 地址仍需先配置 SSH 公钥，即使仓库已公开。

## 面板部署

```bash
git clone https://github.com/biologmder/vps-proxy-console.git
cd vps-proxy-console
cp .env.example .env
# 编辑 PANEL_DOMAIN、PANEL_PORT、CF_API_TOKEN、ADMIN_PASSWORD；如需提醒则填写 Telegram 参数
docker compose up -d --build
```

Cloudflare API Token 限定到面板域名所在 Zone，并赋予 `Zone.Zone:Read` 与 `Zone.DNS:Edit`。浏览 `https://<PANEL_DOMAIN>:<PANEL_PORT>` 登录；默认示例为 `https://panel.example.com:8443`。管理员密码至少 12 个字符；面板数据保存在 Docker 卷 `panel-data`。Caddy 经 Cloudflare DNS-01 自动申请和续期可信 HTTPS 证书。面板的 `PUBLIC_URL` 及订阅链接会包含该端口。

已有旧版面板占用 80/443 时，拉取新版并补齐 `.env` 的 `PANEL_PORT`、`CF_API_TOKEN`，再运行 `docker compose up -d --build`；新版 Compose 不再映射主机的 80/443。

## 节点部署

1. 在面板的「VPS 节点」中添加节点，填写名称、公网域名、已有私网/隧道 IP（如需落地）。
2. 创建后点击「复制完整命令」，在对应 Linux VPS 的终端粘贴执行。面板会自动把面板地址（含端口）、节点 ID 和令牌填好；命令会通过 HTTPS 拉取代码、写入 `agent.env`、拉取预构建镜像并启动 Agent，**不会在 VPS 上编译 Go**。目标 VPS 需要已安装 Git 与 Docker Compose，执行者需要有 `/opt` 写入与 Docker 权限。
3. 回到面板查看节点是否在线。若令牌遗失或需要重装，在节点列表「轮换令牌」生成新的部署命令，旧令牌会立即失效。

部署命令仅在创建或轮换令牌时提供，不会长期保存在面板。网页预览会隐藏令牌，复制按钮仍包含真实令牌。它仅应在对应 VPS 上执行；不要发到公开聊天或工单。Agent 镜像由 GitHub Actions 为 amd64/arm64 构建并发布到公开的 GHCR；首拉速度取决于 VPS 到 GHCR 的网络，后续更新只下载变更层。若要自行构建，可运行 `docker build -f Dockerfile.agent -t local-agent .`。

Agent 使用 Linux host 网络，端口与 VPS 网络命名空间一致。它会连接面板并在有入站配置时应用 Xray。节点数据保存在 Docker 卷 `agent-data`，包含证书、令牌之外的配置和流量计数；切勿无备份删除该卷。

## 配置顺序

1. 添加节点；确认 Agent 心跳出现。
2. 添加入站。TLS 类型需填写已解析到此节点的域名；REALITY 需填写目标地址，私钥与 Short ID 可以创建时自动生成。SOCKS5/HTTP 落地入口填写该节点私网 IP，系统可自动生成服务账号密码。
3. 添加人员与订阅分配（人员 → 入站）。创建人员时保存订阅链接；之后只可通过“轮换令牌”生成新链接，旧链接随即失效。
4. 如需链式出口，先在落地节点建立 SOCKS5/HTTP 入站，再在入口节点创建对应出口并选择该落地入口。
5. 添加分流规则。`domain:example.com` 匹配域名及子域，`full:example.com` 仅匹配完全相同域名，`geosite:cn` / `geoip:cn` 使用 Xray 内置资源。`position` 越小优先级越高。全局默认出口为直连。

## 验证与开发

```bash
go test ./...
cd web && npm ci && npm run build
```

若已安装 Xray，可运行真实配置校验集成测试：

```bash
XRAY_BIN=/usr/local/bin/xray go test ./internal/xray -run TestRealXrayConfig -v
```

本地开发：`ADMIN_PASSWORD=... DATABASE_PATH=./data/dev.db WEB_DIR=./web/dist go run ./cmd/panel`。生产环境建议仅通过 Caddy 暴露面板，勿直接对公网开放 8080。

## 已知边界

- 尚无公开注册、支付、自助门户、自动多跳/故障切换、端口转发或自动建立 VPS 间私网。
- 每次入站或分流配置变化需要重启对应 Xray 进程，现有连接会中断；校验失败会恢复上一版。未来可改用 Xray 动态 API 缩小中断范围。
- 若 Agent 本地持久卷丢失，其已上报的中心累计用量不会回退，但未上报的少量流量可能丢失。
- 面板数据库与 Agent 数据卷应由部署者定期备份。当前不提供自动备份恢复。

## 安全与许可证

项目代码为独立实现，不复制参考项目代码。Xray-core 使用 MPL-2.0；React、Go 依赖保留各自许可证。仓库公开可见；项目本身尚未选择开源许可证。
