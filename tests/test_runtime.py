from __future__ import annotations

import os
from pathlib import Path

import pytest

from pw_locker_sql.config import AuthenticationMode
from pw_locker_sql.errors import ConfigurationError
from pw_locker_sql.runtime import (
    ConfigurationSelection,
    RuntimeComposition,
    load_sql_server_config,
)

INTEGRATED_ENVIRONMENT = {
    "PW_LOCKER_SQL_SERVER": "SERVER_PLACEHOLDER",
    "PW_LOCKER_SQL_DATABASE": "DATABASE_PLACEHOLDER",
    "PW_LOCKER_SQL_AUTH_MODE": "integrated",
}


def test_temporary_dotenv_uses_recognized_keys_without_interpolation(tmp_path: Path) -> None:
    path = tmp_path / "placeholder.env"
    path.write_text(
        "PW_LOCKER_SQL_SERVER=${UNRELATED_PLACEHOLDER}\n"
        "PW_LOCKER_SQL_DATABASE=DATABASE_PLACEHOLDER\n"
        "PW_LOCKER_SQL_AUTH_MODE=integrated\n"
        "UNRELATED_PLACEHOLDER=IGNORED_PLACEHOLDER\n",
        encoding="utf-8",
    )
    before = dict(os.environ)
    config = load_sql_server_config(
        ConfigurationSelection(path),
        {},
        tmp_path,
    )
    assert config.server == "${UNRELATED_PLACEHOLDER}"
    assert config.database == "DATABASE_PLACEHOLDER"
    assert dict(os.environ) == before


def test_process_environment_overrides_dotenv_values(tmp_path: Path) -> None:
    path = tmp_path / "placeholder.env"
    path.write_text(
        "PW_LOCKER_SQL_SERVER=FILE_SERVER_PLACEHOLDER\n"
        "PW_LOCKER_SQL_DATABASE=FILE_DATABASE_PLACEHOLDER\n"
        "PW_LOCKER_SQL_AUTH_MODE=integrated\n",
        encoding="utf-8",
    )
    config = load_sql_server_config(
        ConfigurationSelection(path),
        {
            "PW_LOCKER_SQL_SERVER": "PROCESS_SERVER_PLACEHOLDER",
            "PW_LOCKER_SQL_DATABASE": "PROCESS_DATABASE_PLACEHOLDER",
        },
        tmp_path,
    )
    assert config.server == "PROCESS_SERVER_PLACEHOLDER"
    assert config.database == "PROCESS_DATABASE_PLACEHOLDER"


def test_default_dotenv_is_selected_only_at_explicit_runtime_load(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "PW_LOCKER_SQL_SERVER=SERVER_PLACEHOLDER\n"
        "PW_LOCKER_SQL_DATABASE=DATABASE_PLACEHOLDER\n"
        "PW_LOCKER_SQL_AUTH_MODE=integrated\n",
        encoding="utf-8",
    )
    composition = RuntimeComposition(environment={}, working_directory=tmp_path)
    config = composition.load_config(ConfigurationSelection())
    assert config.authentication_mode is AuthenticationMode.WINDOWS_INTEGRATED


def test_only_recognized_environment_keys_are_selected(tmp_path: Path) -> None:
    environment = {
        **INTEGRATED_ENVIRONMENT,
        "UNRELATED_SETTING": "UNRELATED_VALUE_PLACEHOLDER",
        "LEGACY_SERVER": "LEGACY_VALUE_PLACEHOLDER",
        "PW_LOCKER_SQL_MASTER_PASSWORD": "SYNTHETIC_MASTER_PASSWORD",
    }
    config = load_sql_server_config(
        ConfigurationSelection(use_env_file=False),
        environment,
        tmp_path,
    )
    rendered = repr(config.redacted_diagnostics())
    assert "UNRELATED_VALUE_PLACEHOLDER" not in rendered
    assert "LEGACY_VALUE_PLACEHOLDER" not in rendered
    assert "SYNTHETIC_MASTER_PASSWORD" not in rendered


def test_no_env_file_ignores_default_file(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("INVALID_PLACEHOLDER", encoding="utf-8")
    config = load_sql_server_config(
        ConfigurationSelection(use_env_file=False),
        INTEGRATED_ENVIRONMENT,
        tmp_path,
    )
    assert config.authentication_mode is AuthenticationMode.WINDOWS_INTEGRATED


def test_missing_explicit_file_error_does_not_expose_path(tmp_path: Path) -> None:
    missing = tmp_path / "SENSITIVE_PATH_PLACEHOLDER.env"
    with pytest.raises(ConfigurationError) as captured:
        load_sql_server_config(ConfigurationSelection(missing), {}, tmp_path)
    assert str(missing) not in str(captured.value)
    assert "SENSITIVE_PATH_PLACEHOLDER" not in repr(captured.value)


def test_configuration_failures_do_not_log_paths_or_values(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    missing = tmp_path / "SENSITIVE_PATH_PLACEHOLDER.env"
    with pytest.raises(ConfigurationError):
        load_sql_server_config(ConfigurationSelection(missing), {}, tmp_path)
    assert caplog.records == []


def test_integrated_and_sql_authentication_are_composed_without_connections(
    tmp_path: Path,
) -> None:
    class Connector:
        def __init__(self) -> None:
            self.calls = 0

        def connect(self, *args: object, **kwargs: object) -> object:
            self.calls += 1
            raise AssertionError("connection must remain lazy")

    connector = Connector()
    integrated = RuntimeComposition(
        connector=connector,  # type: ignore[arg-type]
        environment=INTEGRATED_ENVIRONMENT,
        working_directory=tmp_path,
    )
    integrated_config = integrated.load_config(ConfigurationSelection(use_env_file=False))
    integrated_runtime = integrated.compose(integrated_config)
    integrated_runtime.close()

    sql_environment = {
        **INTEGRATED_ENVIRONMENT,
        "PW_LOCKER_SQL_AUTH_MODE": "sql",
        "PW_LOCKER_SQL_USERNAME": "USERNAME_PLACEHOLDER",
        "PW_LOCKER_SQL_PASSWORD": "PASSWORD_PLACEHOLDER",
    }
    sql = RuntimeComposition(
        connector=connector,  # type: ignore[arg-type]
        environment=sql_environment,
        working_directory=tmp_path,
    )
    sql_config = sql.load_config(ConfigurationSelection(use_env_file=False))
    sql_runtime = sql.compose(sql_config)
    sql_runtime.close()

    assert integrated_config.authentication_mode is AuthenticationMode.WINDOWS_INTEGRATED
    assert sql_config.authentication_mode is AuthenticationMode.SQL
    assert connector.calls == 0


def test_runtime_configuration_is_redacted_and_tls_is_enforced(tmp_path: Path) -> None:
    composition = RuntimeComposition(
        environment=INTEGRATED_ENVIRONMENT,
        working_directory=tmp_path,
    )
    config = composition.load_config(ConfigurationSelection(use_env_file=False))
    rendered = repr(composition) + repr(config) + str(config.redacted_diagnostics())
    assert "SERVER_PLACEHOLDER" not in rendered
    assert "DATABASE_PLACEHOLDER" not in rendered
    assert config.encrypt is True
    assert config.trust_server_certificate is False
