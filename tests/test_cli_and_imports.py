from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from pw_locker_sql import cli


def test_cli_help_has_no_external_requirements(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--help"]) == cli.EXIT_OK
    output = capsys.readouterr()
    assert "SQL Server Password Locker foundation" in output.out
    assert output.err == ""


@pytest.mark.parametrize("command", ["initialize", "unlock", "list", "get", "set", "delete"])
def test_operational_commands_fail_safely(
    command: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main([command]) == cli.EXIT_UNAVAILABLE
    output = capsys.readouterr()
    assert output.out == ""
    assert "providers are configured" in output.err


def test_imports_create_no_files_or_external_connections(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[1] / "src"
    audit_guard = """def guard(event, args):
    if event == "open" and isinstance(args[1], str) and any(flag in args[1] for flag in "wax+"):
        raise RuntimeError("filesystem write blocked")
    if event in {"os.mkdir", "os.remove", "os.rename", "os.replace", "subprocess.Popen"}:
        raise RuntimeError("external side effect blocked")
    if event.startswith("socket."):
        raise RuntimeError("network side effect blocked")
"""
    script = (
        "import sys;"
        f"sys.path.insert(0, {str(source)!r});"
        f"exec({audit_guard!r});"
        "sys.addaudithook(guard);"
        "import pw_locker_sql;"
        "import pw_locker_sql.cli;"
        "import pw_locker_sql.config;"
        "import pw_locker_sql.domain;"
        "import pw_locker_sql.gui.controller;"
        "import pw_locker_sql.repositories.memory;"
        "import pw_locker_sql.services"
    )
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
        "STAGE2_SENTINEL": "ENVIRONMENT_VALUE_MUST_NOT_APPEAR",
    }
    completed = subprocess.run(
        [sys.executable, "-B", "-c", script],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0
    assert completed.stdout == ""
    assert completed.stderr == ""
    application_artifacts = [path for path in tmp_path.iterdir() if path.name != "_norton_"]
    assert application_artifacts == []


def test_runtime_package_has_no_sql_gui_or_environment_imports() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "pw_locker_sql"
    source = "\n".join(path.read_text(encoding="utf-8") for path in root.rglob("*.py"))
    for forbidden in ("pyodbc", "tkinter", "load_dotenv", "os.environ", "sqlite3"):
        assert forbidden not in source
