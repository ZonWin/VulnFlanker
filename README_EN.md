# VulnFlanker Vulnerability Monitoring Platform

Chinese version: [README.md](README.md)

VulnFlanker is a vulnerability impact assessment and controlled verification
platform for internal security operations. It connects vulnerability
intelligence, host asset snapshots, asset-vulnerability matching, risk
prioritization, read-only verification tasks, and audit logs into one workflow.

The project is designed to support "automatic threat intelligence collection ->
automatic asset updates -> automatic vulnerability comparison -> automatic risk
assessment." It includes a self-built, weight-adjustable risk matching pipeline
to better fit real enterprise management needs.

Another optimization is the addition of two AI completion mechanisms. When the
collected threat intelligence is incomplete or low quality, VulnFlanker can use
an **AI large model to extract vulnerability information** with
OpenAI-compatible API support, and an **AI large model with web search to
supplement vulnerability information**. At present, only the KIMI API
integration has been optimized for web enrichment. The goal is to reduce manual
vulnerability database maintenance and improve vulnerability assessment
efficiency. **Standardized vulnerability data sources** are still preferred
where available. The project uses the CISA vulnerability catalog as the default
threat intelligence source, and more collectors will be added gradually.

**If you have needs or feedback, please open an issue; the author will respond
as soon as possible. Thank you.**

This project is suitable for local demos, internal use, and small controlled
environments. Because the platform collects sensitive asset information, **it is
not recommended to expose it to the public internet**. TLS is recommended for
production deployments.

## Documentation

| Document | Chinese | English |
| --- | --- | --- |
| Project overview | [README.md](README.md) / [Chinese copy](Documents/README_ZH.md) | [README_EN.md](README_EN.md) |
| Changelog | [CHANGELOG_ZH.md](Documents/CHANGELOG_ZH.md) | [CHANGELOG_EN.md](Documents/CHANGELOG_EN.md) |
| Contributing guide | [CONTRIBUTING_ZH.md](Documents/CONTRIBUTING_ZH.md) | [CONTRIBUTING_EN.md](Documents/CONTRIBUTING_EN.md) |
| Security policy | [SECURITY_ZH.md](Documents/SECURITY_ZH.md) | [SECURITY_EN.md](Documents/SECURITY_EN.md) |
| Third-party notices | [THIRD_PARTY_NOTICES_ZH.md](Documents/THIRD_PARTY_NOTICES_ZH.md) | [THIRD_PARTY_NOTICES_EN.md](Documents/THIRD_PARTY_NOTICES_EN.md) |

## What It Does

- Collects and normalizes vulnerability intelligence from CISA KEV, Aliyun AVD,
  and the built-in WatchVuln collector.
  - WatchVuln high-value vulnerability collection and push:
    `https://github.com/zema1/watchvuln`
  - WatchVuln is very useful. It was initially considered as a collector, but
    standardized-format data sources work better for this project. Thanks to
    the original author.
- Receives Linux host snapshots from the Agent ingress API.
- Tracks assets, components, network exposure, Agent status, and snapshot
  freshness.
- Evaluates whether a vulnerability affects an asset through product, version,
  operating-system, feature, and exposure rules.
- Produces risk queue entries with priority, risk factors, explanations, and
  stable risk codes.
- Creates read-only verification tasks and records Agent-returned evidence.
- Quickly monitor newly added vulnerability intelligence and assess the impact
  scope across internal assets.
- Provides a React console for assets, vulnerabilities, matching results, risk
  operations, verification tasks, AI settings, platform settings, and audit logs.
- Supports AI-assisted vulnerability information enrichment through configurable
  AI service providers.

<img width="2492" height="1262" alt="image" src="https://github.com/user-attachments/assets/10c012f7-7e66-49a0-bdea-b9e156b5144a" />
<img width="2492" height="1262" alt="image" src="https://github.com/user-attachments/assets/6351d794-cbe9-40e6-b1da-aa4ce60d1963" />
<img width="2492" height="1262" alt="image" src="https://github.com/user-attachments/assets/31bb0a27-cabc-4d64-b23f-cbdfddead652" />
<img width="2492" height="1262" alt="image" src="https://github.com/user-attachments/assets/2728627d-0414-4899-9257-ecc7ebf23fee" />

## Architecture

```text
Vulnerability feeds
        |
        v
Intel collection -> normalization -> vulnerability catalog
        |                                  |
        |                                  v
Linux Agent -> Agent ingress -> assets -> matching engine -> risk queue
        ^                                  |
        |                                  v
        +--------- verification tasks <- match detail
```

Main runtime services:

- Console API: authenticated control-plane API under `/api/v1`.
- Agent Ingress: Agent-facing API under `/agent/v1`.
- Worker and Beat: background jobs for collection, enrichment, and monitoring.
- PostgreSQL and Redis: persistence and task queue infrastructure.
- Frontend: Vite-built React console served behind Nginx in the demo compose
  stack.

## Quick Start

Requirements:

- Docker and Docker Compose
- PowerShell, Bash, or another shell capable of copying `.env.example`
- Internet access if you want to collect live vulnerability intelligence

Create a local environment file:

```powershell
Copy-Item .env.example .env
```

Edit `.env` before starting:

- Set `VULNFLANKER_REDIS_PASSWORD` to a non-default value.
- Set `VULNFLANKER_INTEL_WEBHOOK_TOKEN` to a non-default value.
- `VULNFLANKER_API_BIND` controls the backend API bind address; the default
  localhost-only value is recommended.
- `VULNFLANKER_AGENT_INGRESS_BIND` controls the Agent asset snapshot ingress
  bind address. If you use the asset Agent feature, set it to an address mask
  reachable by Agent hosts, such as `0.0.0.0`.
- `VULNFLANKER_FRONTEND_BIND` controls the frontend bind address; the default
  value is recommended.
- For key security, set `VULNFLANKER_AI_KEY_ENCRYPTION_KEY` before saving AI
  provider API keys.
- You can set the administrator password directly with
  `VULNFLANKER_BOOTSTRAP_ADMIN_PASSWORD`. Leave it empty to enable the
  first-run password setup page on initial startup.

Start the demo stack:

```powershell
docker compose --env-file .env -f .\deploy\docker-compose.yml up --build -d
```

Open the console:

```text
http://127.0.0.1:8100/
```

Useful local service URLs:

- Console API health: `http://127.0.0.1:8000/api/v1/health/live`
- Agent Ingress health: `http://127.0.0.1:8001/agent/v1/health/live`

The compose file in `deploy/docker-compose.yml` is intentionally optimized for
demo and development use. It uses source bind mounts and reload-enabled backend
processes.

## Agent

The Linux host Agent lives in `agent/` and is written in Go. It collects local
asset information, reports heartbeats, pulls read-only verification tasks, and
returns verification evidence.

**Before using the Agent, build the Linux binaries first.** The public
repository does not ship prebuilt Agent executables by default, and the
installation commands generated by the console expect these binary artifacts to
be available.

Build Linux amd64 and arm64 Agent binaries from Windows/PowerShell:

```powershell
.\scripts\build-agent-artifacts.ps1
```

Build Linux amd64 and arm64 Agent binaries from Linux, macOS, or Bash:

```bash
./scripts/build-agent-artifacts.sh
```

The generated binaries are written to:

```text
agent/bin/vulnflanker-agent-linux-amd64
agent/bin/vulnflanker-agent-linux-arm64
```

For local development only, you can also build an Agent binary for the current
system and architecture:

```powershell
cd agent
go build ./cmd/vulnflanker-agent
```

The console can generate enrollment tokens and installation commands. When
deploying the Agent to a Linux host, choose the binary that matches the host CPU
architecture, and make sure the Agent ingress URL is reachable from that host.
Do not keep the default `127.0.0.1:8001` when running the Agent on a remote
machine.

One-time connectivity check on a Linux host:

```bash
chmod +x ./vulnflanker-agent-linux-amd64
./vulnflanker-agent-linux-amd64 \
  -agent-ingress-url http://<platform-ip-or-domain>:8001 \
  -enrollment-token <enrollment-token-from-console> \
  -once=true
```

New deployments should use `/agent/v1`; the legacy Agent API compatibility
switch is disabled by default and should only be enabled temporarily while
migrating old Agents.

## AI Enrichment

AI enrichment is optional. Built-in fake profiles are available for deterministic
local tests. Real providers can be configured in the console.

When saving a real provider API key, set:

```env
VULNFLANKER_AI_KEY_ENCRYPTION_KEY=<long-random-secret>
```

New AI keys are stored with encrypted `fernet:` storage. Legacy `b64:` and
`plain:` stored values remain readable for migration compatibility. Back up the
encryption key: losing it makes stored AI keys unrecoverable.

## Local Development

Backend checks:

```powershell
python -m pip install -e ".[dev]"
$env:PYTHONPATH = "backend;backend/tests"
python -m compileall backend\app
python -m pytest -q
```

Frontend checks:

```powershell
cd frontend
npm install
npm run build
npm audit
```

Go checks:

```powershell
cd agent
go test ./...
cd ..\tools\watchvuln-collector
go test ./...
```

## Repository Layout

```text
backend/                    Console API, Agent Ingress, services, tests
frontend/                   React console
agent/                      Linux host Agent
tools/watchvuln-collector/  Built-in WatchVuln collector
deploy/                     Demo/development Docker files
Documents/                  Chinese and English project documentation
.github/                    CI and dependency update configuration
```

Private planning notes, internal docs, and real third-party vulnerability corpus
captures are intentionally not part of the public release branch.

## Security Boundary

- It is not recommended to expose the console API, Agent Ingress, PostgreSQL, or
  Redis directly to the public internet.
- Put HTTPS, authentication boundaries, network access control, and monitoring in
  front of any shared deployment.
- Rotate all example passwords, webhook tokens, Redis passwords, bootstrap
  passwords, Agent secrets, and AI encryption keys.
- **Set secure cookies behind HTTPS by enabling
  `VULNFLANKER_SESSION_COOKIE_SECURE=true`.**
- The login page uses a server-validated, single-use image CAPTCHA. Five password
  failures from one IP in ten minutes advance bans through 5 minutes, 15
  minutes, 1 hour, 8 hours, 24 hours, and permanent.
- Shared and production deployments must set a random
  `VULNFLANKER_LOGIN_SECURITY_SECRET` and precisely define trusted reverse proxy
  networks with `VULNFLANKER_LOGIN_TRUSTED_PROXY_CIDRS`; never trust public
  `X-Forwarded-For` values unconditionally.
- If an administrator cannot sign in through the web console, run
  `python backend/scripts/manage_auth_bans.py list` inside the Console API
  container, then release an address with
  `python backend/scripts/manage_auth_bans.py release --ip <IP> --reason <reason>`.
- Agent Bearer Secret authentication exists, but HMAC replay protection and
  secret rotation are future hardening items.
- Current verification tasks are read-only. Automatic remediation and intrusive
  proof-of-concept execution are intentionally out of scope.

See [`Documents/SECURITY_EN.md`](Documents/SECURITY_EN.md) for vulnerability
reporting guidance.

## License

VulnFlanker is licensed under the Apache License, Version 2.0. See `LICENSE` and
`NOTICE` for details.
