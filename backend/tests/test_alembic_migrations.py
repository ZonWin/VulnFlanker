from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


def test_alembic_migrations_have_single_head() -> None:
    project_root = Path(__file__).resolve().parents[2]
    config = Config(str(project_root / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(project_root / "backend" / "alembic"),
    )

    script = ScriptDirectory.from_config(config)
    heads = script.get_heads()

    assert len(heads) == 1, f"Expected one Alembic head, found: {heads}"
    assert heads == ["e0f1a2b3c4d5"]
