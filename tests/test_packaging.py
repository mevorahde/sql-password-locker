from __future__ import annotations

import re
from pathlib import Path

import yaml

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised by the Python 3.10 CI job
    import tomli as tomllib

from pw_locker_sql.runtime import ENVIRONMENT_KEY_MAP

ROOT = Path(__file__).resolve().parents[1]


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_release_documentation_and_license_are_present_and_portable() -> None:
    readme = _text("README.md")
    security = _text("SECURITY.md")
    license_text = _text("LICENSE")
    for heading in (
        "## Architecture",
        "## Encryption model",
        "## SQL persistence and transport",
        "## Command-line interface",
        "## Desktop GUI",
        "### GUI preview",
        "## Testing and development",
        "## Current limitations",
    ):
        assert heading in readme
    assert "professional security audit" in readme
    assert "professional security audit" in security
    assert "Copyright (c) 2026 David Mevorah" in license_text
    combined = readme + security
    assert not re.search(r"[A-Za-z]:\\Users\\", combined)
    assert "SERVER_PLACEHOLDER" not in combined
    assert "DATABASE_PLACEHOLDER" not in combined


def test_env_example_contains_exactly_the_runtime_configuration_names() -> None:
    template = _text(".env.example")
    names = re.findall(r"^\s*#?\s*(PW_LOCKER_SQL_[A-Z_]+)\s*=", template, re.MULTILINE)
    assert len(names) == len(set(names))
    assert set(names) == set(ENVIRONMENT_KEY_MAP)
    assert "integrated" in template
    assert "YOUR_" in template
    assert not re.search(r"(?i)password\s*=\s*[^Y#]", template)


def test_gitignore_protects_local_configuration_but_tracks_template() -> None:
    entries = {
        line.strip()
        for line in _text(".gitignore").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert {".env", ".env.*", "!.env.example"} <= entries


def test_superseded_root_artifacts_are_absent() -> None:
    legacy_paths = {
        "favicon.ico",
        "pw.bat",
        "pw.py",
        "pw_locker.pyw",
        "requirements.txt",
    }
    assert not {path for path in legacy_paths if (ROOT / path).exists()}


def test_project_uses_spdx_license_and_declares_distribution_resources() -> None:
    project = tomllib.loads(_text("pyproject.toml"))
    assert project["project"]["license"] == "MIT"
    assert project["project"]["license-files"] == ["LICENSE"]
    assert project["project"]["scripts"] == {
        "pw-locker-sql": "pw_locker_sql.cli:main",
        "pw-locker-sql-gui": "pw_locker_sql.gui.app:main",
    }
    package_data = project["tool"]["setuptools"]["package-data"]
    assert package_data["pw_locker_sql.assets"] == ["*.png", "*.ico"]
    assert package_data["pw_locker_sql.schema.migrations"] == ["*.sql"]
    for requirement in project["project"]["dependencies"] + project["project"][
        "optional-dependencies"
    ]["dev"]:
        assert ">=" in requirement and "<" in requirement


def test_ci_is_least_privilege_windows_matrix_and_never_opts_into_live_sql() -> None:
    workflow = yaml.safe_load(_text(".github/workflows/ci.yml"))
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["isolated-tests"]
    assert job["runs-on"] == "windows-latest"
    assert job["strategy"]["matrix"]["python-version"] == ["3.10", "3.13"]
    rendered = _text(".github/workflows/ci.yml")
    assert "actions/checkout@v7" in rendered
    assert "actions/setup-python@v7" in rendered
    assert "not sqlserver_integration" in rendered
    assert "--run-sqlserver-integration" not in rendered
    for command in ("pip check", "compileall", "ruff check", "mypy", "pytest"):
        assert command in rendered


def test_dependabot_has_conservative_weekly_limits() -> None:
    configuration = yaml.safe_load(_text(".github/dependabot.yml"))
    assert configuration["version"] == 2
    updates = configuration["updates"]
    assert [item["package-ecosystem"] for item in updates] == ["pip", "github-actions"]
    assert all(item["directory"] == "/" for item in updates)
    assert all(item["schedule"]["interval"] == "weekly" for item in updates)
    assert [item["open-pull-requests-limit"] for item in updates] == [3, 2]
