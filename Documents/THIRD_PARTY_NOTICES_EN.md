# Third Party Notices

VulnFlanker depends on third-party open source software. This file summarizes
the direct runtime dependencies for the public `v0.9.0-prep` release. Transitive
dependencies are resolved by the package manager lockfiles and module files in
the repository.

## Python Runtime Dependencies

| Package | Observed version | License |
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

Development and test dependencies include `httpx` and `pytest`.

## External Security Data Attribution

Red Hat CSAF/VEX security data is provided by Red Hat, Inc. and used under the
[Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/)
license. The original data entry point is <https://access.redhat.com/security/data>.

## Frontend Runtime Dependencies

| Package | Locked version | License |
| --- | --- | --- |
| @tanstack/react-query | 5.100.9 | MIT |
| antd | 6.3.7 | MIT |
| lucide-react | 1.14.0 | ISC |
| react | 19.2.8 | MIT |
| react-dom | 19.2.8 | MIT |
| react-router | 8.3.0 | MIT |

Frontend transitive dependencies are recorded in `frontend/package-lock.json`.

## Go Dependencies

The Agent module currently uses only the Go standard library.

The built-in WatchVuln collector depends on modules declared in
`tools/watchvuln-collector/go.mod`, including:

- `github.com/PuerkitoBio/goquery`
- `github.com/dop251/goja`
- `github.com/dop251/goja_nodejs`
- `github.com/imroc/req/v3`
- `golang.org/x/net`

The collector adapts portions of WatchVuln's public grabbing logic. See
`tools/watchvuln-collector/THIRD_PARTY_NOTICES.md` for that attribution.

## Refreshing This File

Before a release, refresh dependency notices from the current lockfiles and
installed package metadata:

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

For a stricter dependency review, also run `pip-audit` for Python dependencies
and `govulncheck ./...` for each Go module.
