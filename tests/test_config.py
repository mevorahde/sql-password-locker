from __future__ import annotations

import pytest

from pw_locker_sql.config import AuthenticationMode, SQLServerConfig
from pw_locker_sql.errors import ConfigurationError

INTEGRATED_PLACEHOLDERS = {
    "ODBC_DRIVER": "ODBC_DRIVER_PLACEHOLDER",
    "SERVER": "SERVER_PLACEHOLDER",
    "DATABASE": "DATABASE_PLACEHOLDER",
    "AUTH_MODE": "integrated",
}

SQL_AUTH_PLACEHOLDERS = {
    **INTEGRATED_PLACEHOLDERS,
    "AUTH_MODE": "sql",
    "USERNAME": "USERNAME_PLACEHOLDER",
    "PASSWORD": "PASSWORD_PLACEHOLDER",
}


def test_integrated_authentication_configuration() -> None:
    config = SQLServerConfig.from_mapping(INTEGRATED_PLACEHOLDERS)
    assert config.authentication_mode is AuthenticationMode.WINDOWS_INTEGRATED
    assert config.username is None
    assert config.password is None


def test_sql_authentication_configuration() -> None:
    config = SQLServerConfig.from_mapping(SQL_AUTH_PLACEHOLDERS)
    assert config.authentication_mode is AuthenticationMode.SQL
    assert config.username == "USERNAME_PLACEHOLDER"
    assert config.password is not None
    assert config.password.get_secret_value() == "PASSWORD_PLACEHOLDER"


@pytest.mark.parametrize("missing", ["ODBC_DRIVER", "SERVER", "DATABASE", "AUTH_MODE"])
def test_missing_required_setting_is_rejected(missing: str) -> None:
    values = dict(INTEGRATED_PLACEHOLDERS)
    del values[missing]
    with pytest.raises(ConfigurationError):
        SQLServerConfig.from_mapping(values)


def test_sql_authentication_requires_both_username_and_password() -> None:
    for missing in ("USERNAME", "PASSWORD"):
        values = dict(SQL_AUTH_PLACEHOLDERS)
        del values[missing]
        with pytest.raises(ConfigurationError):
            SQLServerConfig.from_mapping(values)


def test_integrated_authentication_rejects_sql_credentials() -> None:
    values = {**INTEGRATED_PLACEHOLDERS, "USERNAME": "USERNAME_PLACEHOLDER"}
    with pytest.raises(ConfigurationError):
        SQLServerConfig.from_mapping(values)


def test_encrypted_transport_defaults_on_and_certificate_trust_defaults_off() -> None:
    config = SQLServerConfig.from_mapping(INTEGRATED_PLACEHOLDERS)
    assert config.encrypt is True
    assert config.trust_server_certificate is False


def test_invalid_boolean_and_timeout_are_rejected() -> None:
    with pytest.raises(ConfigurationError):
        SQLServerConfig.from_mapping({**INTEGRATED_PLACEHOLDERS, "ENCRYPT": "MAYBE"})
    with pytest.raises(ConfigurationError):
        SQLServerConfig.from_mapping(
            {**INTEGRATED_PLACEHOLDERS, "CONNECTION_TIMEOUT": "999"}
        )


def test_repr_and_diagnostics_are_redacted() -> None:
    config = SQLServerConfig.from_mapping(SQL_AUTH_PLACEHOLDERS)
    rendered = repr(config)
    diagnostics = repr(dict(config.redacted_diagnostics()))
    for value in (
        "ODBC_DRIVER_PLACEHOLDER",
        "SERVER_PLACEHOLDER",
        "DATABASE_PLACEHOLDER",
        "USERNAME_PLACEHOLDER",
        "PASSWORD_PLACEHOLDER",
    ):
        assert value not in rendered
        assert value not in diagnostics
    assert str(config.password) == "<redacted>"
