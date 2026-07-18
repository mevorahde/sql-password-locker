from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

from pw_locker_sql import cli


def test_cli_help_has_no_external_requirements(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--help"]) == cli.EXIT_OK
    output = capsys.readouterr()
    assert "Client-side encrypted SQL Server password vault" in output.out
    assert output.err == ""


def test_no_command_prints_help_without_loading_configuration(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main([]) == cli.EXIT_OK
    output = capsys.readouterr()
    assert "check-config" in output.out
    assert output.err == ""


def test_help_does_not_import_production_integrations(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[1] / "src"
    script = (
        "import sys;"
        f"sys.path.insert(0, {str(source)!r});"
        "from pw_locker_sql import cli;"
        "assert cli.main(['--help']) == 0;"
        "forbidden = {'argon2', 'cryptography', 'dotenv', 'pyodbc', 'pyperclip'};"
        "assert forbidden.isdisjoint(sys.modules)"
    )
    completed = subprocess.run(
        [sys.executable, "-B", "-c", script],
        cwd=tmp_path,
        env={
            "PATH": os.environ.get("PATH", ""),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0
    assert "check-config" in completed.stdout
    assert completed.stderr == ""


def test_imports_create_no_files_or_external_connections(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[1] / "src"
    audit_guard = """def guard(event, args):
    if event == "open" and isinstance(args[1], str) and any(flag in args[1] for flag in "wax+"):
        raise RuntimeError("filesystem write blocked")
    if event == "open" and str(args[0]).lower().endswith((".env", ".db", ".log")):
        raise RuntimeError("protected read blocked")
    if event in {"os.mkdir", "os.remove", "os.rename", "os.replace", "subprocess.Popen"}:
        raise RuntimeError("external side effect blocked")
    if event in {
        "socket.bind",
        "socket.connect",
        "socket.connect_ex",
        "socket.getaddrinfo",
        "socket.gethostbyaddr",
        "socket.gethostbyname",
    }:
        raise RuntimeError("network side effect blocked")
"""
    script = (
        "import sys;"
        f"sys.path.insert(0, {str(source)!r});"
        f"exec({audit_guard!r});"
        "sys.addaudithook(guard);"
        "import pw_locker_sql;"
        "import pw_locker_sql.cli;"
        "import pw_locker_sql.clipboard;"
        "import pw_locker_sql.config;"
        "import pw_locker_sql.crypto.argon2_aesgcm;"
        "import pw_locker_sql.crypto.protocol;"
        "import pw_locker_sql.domain;"
        "import pw_locker_sql.gui.controller;"
        "import pw_locker_sql.repositories.memory;"
        "import pw_locker_sql.repositories.sql_server;"
        "import pw_locker_sql.prompting;"
        "import pw_locker_sql.runtime;"
        "import pw_locker_sql.schema.manager;"
        "import pw_locker_sql.services"
        ";assert 'pyodbc' not in sys.modules"
        ";assert 'pyperclip' not in sys.modules"
        ";assert 'dotenv' not in sys.modules"
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


def test_runtime_package_has_no_gui_or_implicit_environment_loading() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "pw_locker_sql"
    source = "\n".join(path.read_text(encoding="utf-8") for path in root.rglob("*.py"))
    for forbidden in (
        "load_dotenv",
        "logging.basicConfig",
        "sqlite3",
        "tkinter",
    ):
        assert forbidden not in source


def test_pyodbc_is_only_loaded_lazily() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "pw_locker_sql"
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(alias.name != "pyodbc" for alias in node.names)
            if isinstance(node, ast.ImportFrom):
                assert node.module != "pyodbc"
