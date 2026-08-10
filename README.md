# VulnFlanker 侧卫-漏洞监测平台

English version: [README_EN.md](README_EN.md)

VulnFlanker 是一个面向内部安全运营的漏洞影响评估与受控验证平台。它将漏洞情报、主机资产快照、资产与漏洞匹配、风险优先级排序、只读验证任务和审计日志连接为一套完整工作流。

项目旨在实现"自动采集威胁情报 —— 自动完成资产更新 —— 自动完成漏洞比对 —— 自动完成风险评估"。自建**权重可调**的风险匹配流水线，以满足企业实际管理需求。

本项目另一优化点在于加入了两组AI补全机制，在获取的威胁情报质量不佳时，允许通过**AI大模型提取漏洞信息**（支持OpenAI格式API对接）、允许**AI大模型联网搜索补充漏洞信息**（目前仅完成KIMI API的对接优化），尽可能减少人工维护漏洞库的步骤，提高漏洞评估效率。当然，如果有**标准化的漏洞数据源**再好不过，项目默认使用CISA漏洞库作为威胁信息采集源，后续将逐步新增采集器。

**【如有需求或意见可提issue，作者将尽快响应，谢谢。】**

本项目适用于本地演示、内部使用和小型受控环境，因平台会收集资产敏感信息，**不建议对互联网开放**。生产环境部署时建议开启TLS加密。

## 文档导航

| 文档 | 中文版 | 英文版 |
| --- | --- | --- |
| 项目说明 | [README.md](README.md) / [中文副本](Documents/README_ZH.md) | [README_EN.md](README_EN.md) |
| 变更日志 | [CHANGELOG_ZH.md](Documents/CHANGELOG_ZH.md) | [CHANGELOG_EN.md](Documents/CHANGELOG_EN.md) |
| 贡献指南 | [CONTRIBUTING_ZH.md](Documents/CONTRIBUTING_ZH.md) | [CONTRIBUTING_EN.md](Documents/CONTRIBUTING_EN.md) |
| 安全策略 | [SECURITY_ZH.md](Documents/SECURITY_ZH.md) | [SECURITY_EN.md](Documents/SECURITY_EN.md) |
| 第三方声明 | [THIRD_PARTY_NOTICES_ZH.md](Documents/THIRD_PARTY_NOTICES_ZH.md) | [THIRD_PARTY_NOTICES_EN.md](Documents/THIRD_PARTY_NOTICES_EN.md) |

## 功能

- 从 CISA KEV、阿里云 AVD 和内置 WatchVuln 采集器收集并标准化漏洞情报。
    - WatchVuln 高价值漏洞采集与推送 https://github.com/zema1/watchvuln
    - WatchVuln 项目功能非常好用，初期有考虑以此作为采集器，但本项目中使用标准化格式数据源较佳，还是感谢原作者。
- 通过 Agent 接入 API 接收 Linux 主机快照。
- 跟踪资产、组件、网络暴露情况、Agent 状态和快照新鲜度。
- 依据产品、版本、操作系统、功能和暴露规则，评估漏洞是否影响资产。
- 生成包含优先级、风险因素、说明和稳定风险代码的风险队列条目。
- 创建只读验证任务，并记录 Agent 返回的证据。
- **快速完成新增漏洞信息监控，内部资产受影响范围评估。**
- 提供 React 控制台，用于管理资产、漏洞、匹配结果、风险处置、验证任务、AI 设置、平台设置和审计日志。
- 支持通过可配置的AI服务提供商，使用 AI 辅助补充漏洞信息。

<img width="2492" height="1262" alt="image" src="https://github.com/user-attachments/assets/c07e145c-0998-4069-8dee-603d91d813dd" />
<img width="2492" height="1262" alt="image" src="https://github.com/user-attachments/assets/f009d375-92cd-4e3b-9163-ab559c636be1" />
<img width="2492" height="1262" alt="image" src="https://github.com/user-attachments/assets/9ebde7c4-0524-4179-aba4-5790547268f1" />
<img width="2492" height="1262" alt="image" src="https://github.com/user-attachments/assets/5ec9a29c-bfb5-4268-adf0-dd460a2f863f" />

## 架构

```text
漏洞情报源
    |
    v
情报采集 -> 标准化 -> 漏洞目录
    |                    |
    |                    v
Linux Agent -> Agent 接入 -> 资产 -> 匹配引擎 -> 风险队列
    ^                            |
    |                            v
    +----------- 验证任务 <- 匹配详情
```

主要运行时服务：

- 控制台 API：位于 `/api/v1` 下、需要身份认证的控制平面 API。
- Agent 接入服务：位于 `/agent/v1` 下、面向 Agent 的 API。
- Worker 和 Beat：负责情报采集、信息补充和监控的后台任务。
- PostgreSQL 和 Redis：提供持久化存储和任务队列基础设施。
- 前端：由 Vite 构建的 React 控制台，在演示用 Compose 技术栈中通过 Nginx 提供服务。

## 快速开始

环境要求：

- Docker 和 Docker Compose
- PowerShell、Bash，或其他能够复制 `.env.example` 的 Shell
- 如需采集实时漏洞情报，需要连接互联网

创建本地环境配置文件：

```powershell
Copy-Item .env.example .env
```

启动前编辑 `.env`：

- 将 `VULNFLANKER_REDIS_PASSWORD` 设置为非默认值。
- 将 `VULNFLANKER_INTEL_WEBHOOK_TOKEN` 设置为非默认值。
- `VULNFLANKER_API_BIND` 为后端接口设置，建议保持默认仅本地可访问。
- `VULNFLANKER_AGENT_INGRESS_BIND` 为Agent资产数据快照上报接口设置，如需使用资产Agent功能，则建议设置为资产可访问的地址掩码（如0.0.0.0）。
- `VULNFLANKER_FRONTEND_BIND` 为前端访问接口设置，建议保持默认。
- 为保证密钥安全，在保存 AI 服务提供商 API 密钥前，需设置 `VULNFLANKER_AI_KEY_ENCRYPTION_KEY`。
- 可于 `VULNFLANKER_BOOTSTRAP_ADMIN_PASSWORD` 直接设定管理员账号密码，留空则会在初次启动时开启首次启动的密码设定页面。

启动演示环境：

```powershell
docker compose --env-file .env -f .\deploy\docker-compose.yml up --build -d
```

打开控制台：

```text
http://127.0.0.1:8100/
```

常用本地服务地址：

- 控制台 API 健康检查：`http://127.0.0.1:8000/api/v1/health/live`
- Agent 接入服务健康检查：`http://127.0.0.1:8001/agent/v1/health/live`

`deploy/docker-compose.yml` 中的 Compose 文件专门针对演示和开发用途进行了优化。它使用源代码绑定挂载，并为后端进程启用了重新加载。

## Agent

Linux 主机 Agent 位于 `agent/`，使用 Go 编写。它负责收集本地资产信息、上报心跳、拉取只读验证任务并返回验证证据。

**使用 Agent 前必须先编译 Linux 二进制。**公开仓库不默认附带预编译的 Agent
可执行文件；控制台生成的安装命令也依赖这些二进制产物已经准备好。

在 Windows/PowerShell 环境中构建 Linux amd64 和 arm64 Agent：

```powershell
.\scripts\build-agent-artifacts.ps1
```

在 Linux、macOS 或 Bash 环境中构建 Linux amd64 和 arm64 Agent：

```bash
./scripts/build-agent-artifacts.sh
```

构建完成后，二进制文件会写入：

```text
agent/bin/vulnflanker-agent-linux-amd64
agent/bin/vulnflanker-agent-linux-arm64
```

如果只想在当前平台做本地开发调试，也可以直接构建当前系统架构的 Agent：

```powershell
cd agent
go build ./cmd/vulnflanker-agent
```

控制台可以生成注册令牌和安装命令。将 Agent 部署到 Linux 主机时，请选择匹配
CPU 架构的二进制文件，并确保命令中的 Agent 接入地址是该主机可以访问的平台
地址；不要在远程主机上继续使用默认的 `127.0.0.1:8001`。

Linux 主机上的一次性连通性验证示例：

```bash
chmod +x ./vulnflanker-agent-linux-amd64
./vulnflanker-agent-linux-amd64 \
  -agent-ingress-url http://<平台IP或域名>:8001 \
  -enrollment-token <控制台生成的注册令牌> \
  -once=true
```

新部署应使用 `/agent/v1`；旧版 Agent API 默认关闭，仅在迁移旧 Agent 时临时启用。

## AI 信息补充

AI 信息补充是可选功能。系统内置了用于确定性本地测试的模拟配置，也可以在控制台中配置真实服务提供商。

保存真实服务提供商的 API 密钥时，请设置：

```env
VULNFLANKER_AI_KEY_ENCRYPTION_KEY=<long-random-secret>
```

新的 AI 密钥使用加密的 `fernet:` 存储。为兼容迁移，旧版以 `b64:` 和 `plain:` 存储的值仍可读取。请备份加密密钥：一旦丢失，已存储的 AI 密钥将无法恢复。

## 本地开发

后端检查：

```powershell
python -m pip install -e ".[dev]"
$env:PYTHONPATH = "backend;backend/tests"
python -m compileall backend\app
python -m pytest -q
```

前端检查：

```powershell
cd frontend
npm install
npm run build
npm audit
```

Go 检查：

```powershell
cd agent
go test ./...
cd ..\tools\watchvuln-collector
go test ./...
```

## 仓库结构

```text
backend/                    控制台 API、Agent 接入服务、业务服务和测试
frontend/                   React 控制台
agent/                      Linux 主机 Agent
tools/watchvuln-collector/  内置 WatchVuln 采集器
deploy/                     演示/开发用 Docker 文件
Documents/                  中英文项目说明文档
.github/                    CI 和依赖更新配置
```

私有规划笔记、内部文档和真实第三方漏洞语料快照有意不包含在公开发布分支中。

## 安全边界

- 不建议将控制台 API、Agent 接入服务、PostgreSQL 或 Redis 直接暴露在公网。
- 任何共享部署的前端都应配置 HTTPS、身份认证边界、网络访问控制和监控。
- 轮换所有示例密码、Webhook 令牌、Redis 密码、引导密码、Agent 密钥和 AI 加密密钥。
- **在 HTTPS 环境下启用 `VULNFLANKER_SESSION_COOKIE_SECURE=true`，以设置安全 Cookie。**
- 登录页使用服务端一次性图片验证码；同一 IP 在 10 分钟内累计 5 次密码错误后，按 5 分钟、15 分钟、1 小时、8 小时、24 小时、永久封禁逐级递增。
- 共享或生产部署必须设置随机的 `VULNFLANKER_LOGIN_SECURITY_SECRET`，并用 `VULNFLANKER_LOGIN_TRUSTED_PROXY_CIDRS` 精确声明可信反向代理网段；不要无条件信任公网传入的 `X-Forwarded-For`。
- 管理员无法从 Web 页面登录时，可在 Console API 容器内运行 `python backend/scripts/manage_auth_bans.py list` 查看封禁，并用 `python backend/scripts/manage_auth_bans.py release --ip <IP> --reason <原因>` 解封。
- 系统已支持 Agent Bearer Secret 身份认证，但 HMAC 重放保护和密钥轮换仍是后续安全加固事项。
- 当前验证任务均为只读。自动修复和侵入式概念验证执行有意不纳入范围。

漏洞报告指引请参阅 [`Documents/SECURITY_ZH.md`](Documents/SECURITY_ZH.md)。

## 许可证

VulnFlanker 采用 Apache License 2.0 许可证。详情请参阅 `LICENSE` 和 `NOTICE`。
