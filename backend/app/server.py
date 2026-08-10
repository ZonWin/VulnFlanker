from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn

from app.core.config import get_settings
from app.core.deployment import deployment_profile


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a VulnFlanker API service.")
    parser.add_argument("role", choices=("console", "agent"))
    args = parser.parse_args()

    settings = get_settings()
    profile = deployment_profile(settings)
    is_console = args.role == "console"
    app_path = "app.main_console:app" if is_console else "app.main_agent:app"
    # Compose exposes configurable host ports, while service ports stay fixed.
    port = 8000 if is_console else 8001
    workers = (
        profile.console_api_workers if is_console else profile.agent_api_workers
    )
    reload_enabled = settings.app_env.lower() == "development" and not (
        settings.large_scale_mode
    )
    reload_dir = Path("/workspace/backend")

    uvicorn.run(
        app_path,
        host="0.0.0.0",
        port=port,
        log_level=settings.log_level.lower(),
        reload=reload_enabled,
        reload_dirs=[str(reload_dir)] if reload_enabled and reload_dir.exists() else None,
        workers=workers,
        proxy_headers=not is_console,
    )


if __name__ == "__main__":
    main()
