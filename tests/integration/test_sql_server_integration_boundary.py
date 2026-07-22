from __future__ import annotations

import pytest

pytestmark = pytest.mark.sqlserver_integration


def test_sql_server_integration_requires_an_explicit_test_database(
    pytestconfig: pytest.Config,
) -> None:
    database = pytestconfig.getoption("--sqlserver-test-database")
    if not isinstance(database, str) or not database.strip():
        pytest.fail("an explicit test-only database designation is required")
    normalized = database.strip().casefold()
    if "test" not in normalized:
        pytest.fail("the designated database must be clearly test-only")
    pytest.skip("live SQL Server execution is intentionally deferred beyond Stage 4")
