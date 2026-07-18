from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

import pytest

from pw_locker_sql.domain import CredentialId, CredentialMetadata, EncryptedEnvelope
from pw_locker_sql.errors import UnsupportedFormatError, ValidationError


def test_account_identifier_is_trimmed_nfkc_normalized_and_casefolded() -> None:
    assert CredentialId.from_account("  KELVIN-Straße  ").value == "kelvin-strasse"


@pytest.mark.parametrize("account", ["", " ", "\t\r\n"])
def test_empty_account_is_rejected(account: str) -> None:
    with pytest.raises(ValidationError):
        CredentialId.from_account(account)


def test_metadata_is_immutable(fixed_time: datetime) -> None:
    metadata = CredentialMetadata(CredentialId("ACCOUNT_PLACEHOLDER"), fixed_time, fixed_time)
    with pytest.raises(FrozenInstanceError):
        metadata.revision = 2  # type: ignore[misc]


def test_metadata_rejects_naive_or_reversed_timestamps() -> None:
    aware = datetime(2026, 1, 2, tzinfo=timezone.utc)
    naive = datetime(2026, 1, 2)
    with pytest.raises(ValidationError):
        CredentialMetadata(CredentialId("ACCOUNT_PLACEHOLDER"), naive, aware)
    with pytest.raises(ValidationError):
        CredentialMetadata(
            CredentialId("ACCOUNT_PLACEHOLDER"),
            aware,
            datetime(2026, 1, 1, tzinfo=timezone.utc),
        )


@pytest.mark.parametrize(
    "field",
    ["ciphertext", "nonce", "authentication_tag", "associated_data"],
)
def test_envelope_rejects_empty_binary_fields(field: str) -> None:
    values = {
        "ciphertext": b"SYNTHETIC_CIPHERTEXT",
        "nonce": b"SYNTHETIC_NONCE",
        "authentication_tag": b"SYNTHETIC_AUTH_TAG",
        "associated_data": b"SYNTHETIC_ASSOCIATED_DATA",
    }
    values[field] = b""
    with pytest.raises(ValidationError):
        EncryptedEnvelope(**values)


def test_envelope_rejects_unsupported_version_and_algorithm() -> None:
    values = {
        "ciphertext": b"SYNTHETIC_CIPHERTEXT",
        "nonce": b"SYNTHETIC_NONCE",
        "authentication_tag": b"SYNTHETIC_AUTH_TAG",
        "associated_data": b"SYNTHETIC_ASSOCIATED_DATA",
    }
    with pytest.raises(UnsupportedFormatError):
        EncryptedEnvelope(**values, format_version=999)
    with pytest.raises(UnsupportedFormatError):
        EncryptedEnvelope(**values, algorithm="SYNTHETIC_UNSUPPORTED_ALGORITHM")


def test_envelope_copies_mutable_binary_inputs_and_redacts_repr() -> None:
    caller_owned = bytearray(b"SYNTHETIC_CIPHERTEXT")
    envelope = EncryptedEnvelope(
        ciphertext=caller_owned,  # type: ignore[arg-type]
        nonce=b"SYNTHETIC_NONCE",
        authentication_tag=b"SYNTHETIC_AUTH_TAG",
        associated_data=b"SYNTHETIC_ASSOCIATED_DATA",
    )
    caller_owned[:] = b"CHANGED_BY_CALLER_DATA"
    assert envelope.ciphertext == b"SYNTHETIC_CIPHERTEXT"
    rendered = repr(envelope)
    assert "SYNTHETIC_CIPHERTEXT" not in rendered
    assert "SYNTHETIC_NONCE" not in rendered
