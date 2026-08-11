# 第三方声明

VulnFlanker 依赖第三方开源软件。本文档汇总公开 `v0.9.0-prep` 版本的直接运行时依赖。传递依赖由仓库中的包管理器锁定文件和模块文件解析。

## Python 运行时依赖

| 软件包 | 检测到的版本 | 许可证 |
| --- | --- | --- |
| fastapi | 0.136.3 | MIT |
| uvicorn | 0.48.0 | BSD-3-Clause |
| SQLAlchemy | 2.0.50 | MIT |
| psycopg | 3.3.4 | LGPL-3.0-only |
| Alembic | 1.18.4 | MIT |
| pydantic-settings | 2.14.1 | MIT |
| cryptography | 48.0.0 | Apache-2.0 OR BSD-3-Clause |
| celery | 5.6.3 | BSD-3-Clause |
| redis-py | 5.3.1 | MIT |
| zstandard | 0.25.0 | BSD-3-Clause |

开发和测试依赖包括 `httpx` 和 `pytest`。

## 外部安全数据归属

Red Hat CSAF/VEX 安全数据由 Red Hat, Inc. 提供，并按 [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/) 许可使用。原始数据入口为 <https://access.redhat.com/security/data>。

## 前端运行时依赖

| 软件包 | 锁定版本 | 许可证 |
| --- | --- | --- |
| @tanstack/react-query | 5.100.9 | MIT |
| antd | 6.3.7 | MIT |
| lucide-react | 1.14.0 | ISC |
| react | 19.2.8 | MIT |
| react-dom | 19.2.8 | MIT |
| react-router | 8.3.0 | MIT |

前端传递依赖记录在 `frontend/package-lock.json` 中。

## Go 依赖

Agent 模块当前仅使用 Go 标准库。

内置 WatchVuln 采集器依赖 `tools/watchvuln-collector/go.mod` 中声明的模块，包括：

- `github.com/PuerkitoBio/goquery`
- `github.com/dop251/goja`
- `github.com/dop251/goja_nodejs`
- `github.com/imroc/req/v3`
- `golang.org/x/net`

该采集器改编了 WatchVuln 公开抓取逻辑的部分内容。相关归属声明请参阅 `tools/watchvuln-collector/THIRD_PARTY_NOTICES.md`。

## 更新本文档

发布前，请依据当前锁定文件和已安装软件包的元数据更新依赖声明：

```powershell
python -m pip install -e ".[dev]"
python -m pip install pip-audit
cd frontend
npm install
npm audit
cd ..\agent
go test ./...
cd ..\tools\watchvuln-collector
go test ./...
```

如需进行更严格的依赖审查，还应对 Python 依赖运行 `pip-audit`，并对每个 Go 模块运行 `govulncheck ./...`。
